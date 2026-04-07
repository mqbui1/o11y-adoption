#!/usr/bin/env python3
"""
o11y-adoption: Splunk Observability Cloud adoption & user activity audit tool.

Data sources:
  - GET /v2/organization/member        — user roster
  - GET /v2/event/find?sf_eventType=SessionLog   — logins/logouts
  - GET /v2/event/find?sf_eventType=HttpRequest  — API/UI activity per user
  - GET /v2/detector, /v2/dashboard, /v2/chart   — asset inventory + staleness
  - GET /v2/token                               — token health
  - GET /v2/metrictimeseries (dims)             — OTel adoption signals
  - POST /v2/apm/topology                       — APM service coverage
"""

import argparse
import json
import os
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

REALM = os.environ.get("SPLUNK_REALM", "us1")
TOKEN = os.environ.get("SPLUNK_ACCESS_TOKEN", "")
API_BASE = f"https://api.{REALM}.signalfx.com"
APP_BASE = f"https://app.{REALM}.signalfx.com"

HDR = {"X-SF-TOKEN": TOKEN, "Content-Type": "application/json"}

REPORTS_DIR = Path("reports")

# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

def api_get(path, params=None):
    r = requests.get(f"{API_BASE}{path}", headers=HDR, params=params, timeout=30)
    r.raise_for_status()
    return r.json()


def event_find(query, start_time_ms, limit=10000):
    url = f"{API_BASE}/v2/event/find"
    params = {"query": query, "start_time": start_time_ms, "limit": limit}
    r = requests.get(url, headers=HDR, params=params, timeout=30)
    r.raise_for_status()
    data = r.json()
    return data if isinstance(data, list) else data.get("results", [])


def ts_to_str(ms):
    if not ms:
        return "never"
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def days_ago(ms):
    if not ms:
        return None
    delta = datetime.now(timezone.utc) - datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    return delta.days


# ---------------------------------------------------------------------------
# Data fetchers
# ---------------------------------------------------------------------------

def fetch_members():
    data = api_get("/v2/organization/member", params={"limit": 9999})
    return data.get("results", [])


def fetch_session_events(days=90, since_ms=None, until_ms=None):
    start_ms = since_ms or int((datetime.now() - timedelta(days=days)).timestamp() * 1000)
    events = event_find("sf_eventType:SessionLog", start_ms)
    if until_ms:
        events = [e for e in events if e.get("timestamp", 0) <= until_ms]
    return events


def fetch_http_events(days=90, since_ms=None, until_ms=None):
    start_ms = since_ms or int((datetime.now() - timedelta(days=days)).timestamp() * 1000)
    events = event_find("sf_eventType:HttpRequest", start_ms)
    if until_ms:
        events = [e for e in events if e.get("timestamp", 0) <= until_ms]
    return events


def fetch_teams():
    data = api_get("/v2/team", params={"limit": 1000})
    return data.get("results", [])


def fetch_assets():
    detectors  = api_get("/v2/detector",  {"limit": 1000}).get("results", [])
    dashboards = api_get("/v2/dashboard", {"limit": 1000}).get("results", [])
    charts     = api_get("/v2/chart",     {"limit": 1000}).get("results", [])
    tokens     = api_get("/v2/token",     {"limit": 1000}).get("results", [])
    return detectors, dashboards, charts, tokens


def fetch_otel_signals():
    """
    Detect OTel adoption via the Dimension API (GET /v2/dimension).
    telemetry.sdk.* and service.name are dimension-level metadata, not MTS dimensions.
    Returns dict: {languages: [str], sdk_names: [str], service_names: [str], collector: bool}
    """
    def dim_values(key):
        try:
            r = api_get("/v2/dimension", {"query": f"key:{key}", "limit": 200})
            return [d["value"] for d in r.get("results", [])]
        except Exception:
            return []

    languages    = dim_values("telemetry.sdk.language")
    sdk_names    = dim_values("telemetry.sdk.name")
    service_names = dim_values("service.name")

    # Collector present if otelcol dimension keys exist
    try:
        r = api_get("/v2/dimension", {"query": "key:otelcol*", "limit": 1})
        collector = len(r.get("results", [])) > 0
    except Exception:
        collector = False

    return {
        "languages":     sorted(set(languages)),
        "sdk_names":     sorted(set(sdk_names)),
        "service_names": sorted(set(service_names)),
        "collector":     collector,
    }


def fetch_apm_topology():
    """Fetch full APM topology: nodes (services + inferred deps) and edges."""
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    week_ago = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 604800))
    try:
        r = requests.post(f"{API_BASE}/v2/apm/topology",
                          headers=HDR, json={"timeRange": f"{week_ago}/{now}"}, timeout=30)
        data = r.json().get("data") or {}
        return data.get("nodes", []), data.get("edges", [])
    except Exception:
        return [], []


def fetch_apm_services():
    nodes, _ = fetch_apm_topology()
    return [n for n in nodes if not n.get("inferred")]


def fetch_deployment_environments():
    """Return list of deployment environment values from dimension API."""
    try:
        r = api_get("/v2/dimension", {"query": "key:deployment.environment", "limit": 200})
        return sorted({d["value"] for d in r.get("results", [])})
    except Exception:
        return []


def fetch_service_languages():
    """
    Build a dict of service_name -> language by querying service.name dimensions
    and checking their customProperties for telemetry.sdk.language.
    Returns dict: {service: language_str}
    """
    try:
        rs = api_get("/v2/dimension", {"query": "key:service.name", "limit": 500})
        svc_lang_map = {}
        for svc_dim in rs.get("results", []):
            svc_name = svc_dim.get("value", "")
            props = svc_dim.get("customProperties", {})
            lang = props.get("telemetry.sdk.language")
            if lang and svc_name:
                svc_lang_map[svc_name] = lang
        return svc_lang_map
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Analysis functions
# ---------------------------------------------------------------------------

def analyze_users(members, session_events, http_events, days=90):
    """
    Build per-user activity profile from session + HTTP events.
    Returns list of user dicts with login/activity stats.
    """
    email_to_member = {m["email"]: m for m in members}

    # Session analysis
    logins_by_email   = defaultdict(list)   # email -> [timestamp ms, ...]
    logouts_by_email  = defaultdict(list)
    auth_methods      = defaultdict(set)

    for e in session_events:
        props  = e.get("properties", {})
        action = props.get("action", "")
        ts     = e.get("timestamp", 0)
        email  = props.get("email", "")
        if not email:
            continue
        if action == "session created":
            logins_by_email[email].append(ts)
            method = props.get("authMethod", "")
            if method:
                auth_methods[email].add(method)
        elif action == "session deleted":
            logouts_by_email[email].append(ts)

    # HTTP activity analysis
    http_by_email     = defaultdict(list)   # email -> [timestamp ms, ...]
    resource_by_email = defaultdict(set)
    write_count_email = defaultdict(int)
    write_ops_detail  = defaultdict(list)   # email -> [{method, uri, resource, ts}, ...]

    for e in http_events:
        props  = e.get("properties", {})
        email  = props.get("sf_email", "")
        ts     = e.get("timestamp", 0)
        if not email:
            continue
        http_by_email[email].append(ts)
        rtype  = props.get("sf_resourceType", "")
        method = props.get("sf_requestMethod", "")
        uri    = props.get("sf_requestUri", "")
        if rtype:
            resource_by_email[email].add(rtype)
        if method and method != "GET":
            write_count_email[email] += 1
            write_ops_detail[email].append({
                "method":   method,
                "uri":      uri,
                "resource": rtype,
                "ts":       ts,
            })

    # Login frequency: logins per week bucket
    def logins_per_week(login_ts_list, days):
        buckets = defaultdict(int)
        for ts in login_ts_list:
            dt = datetime.fromtimestamp(ts / 1000, tz=timezone.utc)
            week = dt.strftime("%Y-W%W")
            buckets[week] += 1
        return dict(sorted(buckets.items()))

    # Login heatmap: day-of-week x hour-of-day
    def login_heatmap(login_ts_list):
        # Returns dict {(weekday, hour): count}
        heatmap = defaultdict(int)
        for ts in login_ts_list:
            dt = datetime.fromtimestamp(ts / 1000, tz=timezone.utc)
            heatmap[(dt.weekday(), dt.hour)] += 1
        return dict(heatmap)

    # Build user profiles
    users = []
    all_emails = set(m["email"] for m in members)

    for email in all_emails:
        member   = email_to_member.get(email, {})
        logins   = sorted(logins_by_email[email], reverse=True)
        http_ts  = sorted(http_by_email[email], reverse=True)
        all_ts   = sorted(logins + http_ts, reverse=True)

        last_login    = logins[0] if logins  else None
        last_activity = all_ts[0] if all_ts  else None

        users.append({
            "email":          email,
            "full_name":      member.get("fullName", ""),
            "admin":          member.get("admin", False),
            "roles":          [r.get("title", "") for r in member.get("roles", [])],
            "member_since":   member.get("created"),
            "last_login":     last_login,
            "last_activity":  last_activity,
            "login_count":    len(logins),
            "http_count":     len(http_ts),
            "write_ops":      write_count_email[email],
            "resources_used": sorted(resource_by_email[email]),
            "auth_methods":   sorted(auth_methods[email]),
            "active":         last_activity is not None,
            "logins_per_week": logins_per_week(logins_by_email[email], days),
            "login_heatmap":  login_heatmap(logins_by_email[email]),
            "write_ops_detail": sorted(write_ops_detail[email], key=lambda x: x["ts"], reverse=True),
        })

    users.sort(key=lambda u: (-(u["last_activity"] or 0)))
    return users





def analyze_asset_ownership(detectors, dashboards, charts, members):
    """
    Build a map of user -> assets they own/last-modified.
    Resolves userId -> email where possible.
    Returns dict: label -> {detectors: [...], dashboards: [...], charts: [...]}
    """
    # Build userId -> email lookup
    id_to_email = {m["userId"]: m["email"] for m in members}

    def resolve(uid):
        return id_to_email.get(uid, uid)  # fall back to raw ID if not found

    ownership = defaultdict(lambda: {"detectors": [], "dashboards": [], "charts": []})

    for d in detectors:
        owner = resolve(d.get("lastUpdatedBy") or d.get("creator") or "")
        if owner:
            ownership[owner]["detectors"].append({
                "id": d.get("id"), "name": d.get("name"),
                "lastUpdated": d.get("lastUpdated"),
            })

    for d in dashboards:
        owner = resolve(d.get("lastUpdatedBy") or d.get("creator") or "")
        if owner:
            ownership[owner]["dashboards"].append({
                "id": d.get("id"), "name": d.get("name"),
                "lastUpdated": d.get("lastUpdated"),
            })

    for c in charts:
        owner = resolve(c.get("lastUpdatedBy") or c.get("creator") or "")
        if owner:
            ownership[owner]["charts"].append({
                "id": c.get("id"), "name": c.get("name"),
                "lastUpdated": c.get("lastUpdated"),
            })

    return dict(ownership)


def analyze_assets(detectors, dashboards, charts, tokens, stale_days=90):
    now_ms = int(time.time() * 1000)
    stale_ms = stale_days * 86400 * 1000

    def staleness(items):
        stale   = [i for i in items if (now_ms - (i.get("lastUpdated") or 0)) > stale_ms]
        active  = [i for i in items if (now_ms - (i.get("lastUpdated") or 0)) <= stale_ms]
        return active, stale

    det_active,  det_stale  = staleness(detectors)
    dash_active, dash_stale = staleness(dashboards)

    # Token health
    expiring_30d = []
    expiring_7d  = []
    expired      = []
    now_s        = time.time()
    for t in tokens:
        exp = t.get("expiry")
        if exp and exp > 0:
            days_left = (exp / 1000 - now_s) / 86400
            if days_left < 0:
                expired.append(t)
            elif days_left <= 7:
                expiring_7d.append(t)
            elif days_left <= 30:
                expiring_30d.append(t)

    # Creator distribution for dashboards
    creators = defaultdict(int)
    for d in dashboards:
        c = d.get("lastUpdatedBy") or d.get("creator", "unknown")
        creators[c] += 1

    return {
        "detectors":  {"total": len(detectors),  "active": len(det_active),  "stale": len(det_stale)},
        "dashboards": {"total": len(dashboards), "active": len(dash_active), "stale": len(dash_stale),
                       "creators": dict(creators)},
        "charts":     {"total": len(charts)},
        "tokens":     {"total": len(tokens), "expired": len(expired),
                       "expiring_7d": len(expiring_7d), "expiring_30d": len(expiring_30d),
                       "expired_list": expired,
                       "expiring_7d_list": expiring_7d, "expiring_30d_list": expiring_30d},
    }


def score_user_engagement(user, ownership, days):
    """
    Compute a 0–100 engagement score for a single user.

    Components (each capped, then weighted):
      - Recency        (30pts): days since last activity, linear decay
      - Login cadence  (25pts): logins over the window vs expected weekly cadence
      - Write activity (25pts): write ops (log scale, caps at 50 ops = full score)
      - Asset footprint(20pts): detectors + dashboards + charts owned (log scale)
    """
    import math

    score = 0

    # Recency (30pts): full score if active today, 0 if no activity or >days ago
    if user["last_activity"]:
        now_ms     = time.time() * 1000
        days_since = (now_ms - user["last_activity"]) / (86400 * 1000)
        recency    = max(0.0, 1.0 - days_since / days)
        score     += recency * 30

    # Login cadence (25pts): target = at least 1 login/week over the window
    weeks        = max(days / 7, 1)
    target_logins = weeks  # one per week = full cadence
    cadence       = min(user["login_count"] / target_logins, 1.0)
    score        += cadence * 25

    # Write activity (25pts): log scale, 50 ops = full score
    if user["write_ops"] > 0:
        write_score = min(math.log10(user["write_ops"] + 1) / math.log10(51), 1.0)
        score      += write_score * 25

    # Asset footprint (20pts): log scale, 20 assets = full score
    email = user["email"]
    owned = ownership.get(email, {})
    n_assets = (len(owned.get("detectors", [])) +
                len(owned.get("dashboards", [])) +
                len(owned.get("charts", [])))
    if n_assets > 0:
        asset_score = min(math.log10(n_assets + 1) / math.log10(21), 1.0)
        score      += asset_score * 20

    return round(score)


def score_bar(score, width=20):
    """Return a text progress bar for a 0–100 score."""
    filled = round(score / 100 * width)
    bar    = "█" * filled + "░" * (width - filled)
    return bar


def compute_org_health(users, assets, otel, days):
    """
    Compute a 0–100 org health score with sub-scores across four dimensions.

    Dimensions:
      - User adoption    (25pts): active users / total users
      - OTel coverage    (25pts): SDK-instrumented / total APM services
      - Asset hygiene    (25pts): non-stale assets / total assets (detectors + dashboards)
      - Token health     (25pts): non-expired/expiring tokens / total tokens
    """
    scores = {}

    # User adoption
    total_users  = len(users)
    active_users = sum(1 for u in users if u["active"])
    scores["user_adoption"] = round((active_users / total_users * 25) if total_users else 0, 1)

    # OTel coverage
    apm_total = otel["apm_count"]
    sdk_count = otel["sdk_count"]
    scores["otel_coverage"] = round((sdk_count / apm_total * 25) if apm_total else 0, 1)

    # Asset hygiene: (active det + active dash) / (total det + total dash)
    total_assets  = assets["detectors"]["total"] + assets["dashboards"]["total"]
    stale_assets  = assets["detectors"]["stale"] + assets["dashboards"]["stale"]
    active_assets = total_assets - stale_assets
    scores["asset_hygiene"] = round((active_assets / total_assets * 25) if total_assets else 25, 1)

    # Token health: penalise expired + expiring <7d
    total_tokens   = assets["tokens"]["total"]
    unhealthy_toks = assets["tokens"]["expired"] + assets["tokens"]["expiring_7d"]
    healthy_toks   = max(total_tokens - unhealthy_toks, 0)
    scores["token_health"] = round((healthy_toks / total_tokens * 25) if total_tokens else 25, 1)

    scores["total"] = round(sum(scores[k] for k in
                                ["user_adoption", "otel_coverage", "asset_hygiene", "token_health"]))
    scores["details"] = {
        "active_users": active_users, "total_users": total_users,
        "sdk_services": sdk_count,    "apm_services": apm_total,
        "active_assets": active_assets, "total_assets": total_assets,
        "healthy_tokens": healthy_toks, "total_tokens": total_tokens,
    }
    return scores


def analyze_otel(otel_signals, apm_services):
    apm_names = sorted({s["serviceName"] for s in apm_services})
    # APM services present in topology = instrumented (sending traces via agent/OTel)
    sdk_count = len(apm_names)

    return {
        "apm_services":    apm_names,
        "apm_count":       len(apm_names),
        "sdk_count":       sdk_count,          # APM topology = instrumented services
        "collector":       otel_signals.get("collector", False),
        "collector_count": 1 if otel_signals.get("collector") else 0,
        "languages":       otel_signals.get("languages", []),
        "sdk_names":       otel_signals.get("sdk_names", []),
        "service_names":   otel_signals.get("service_names", []),
    }


def analyze_app_insights(apm_nodes, apm_edges, otel_signals, svc_lang_map, environments):
    """
    Derive application onboarding insights from APM topology and dimension data.

    Returns dict with:
      - services: list of real (non-inferred) services with language and type
      - inferred_deps: databases, external HTTP, and other inferred nodes
      - dependency_graph: list of {from, to} service-to-service calls
      - language_breakdown: {lang: count}
      - environments: list of deployment environments
      - stack_types: inferred stack classifications (e.g. "Java microservices")
      - service_graph_summary: hub services (most depended-upon)
    """
    real_services = [n for n in apm_nodes if not n.get("inferred")]
    inferred_deps = [n for n in apm_nodes if n.get("inferred")]

    # Per-service language from dimension API
    enriched_services = []
    for n in real_services:
        svc = n.get("serviceName", "")
        lang = svc_lang_map.get(svc, "")
        enriched_services.append({
            "name":     svc,
            "language": lang,
            "type":     n.get("type", "service"),
        })

    # Inferred dependency types
    dep_types = defaultdict(int)
    for n in inferred_deps:
        ntype = n.get("type", "unknown")
        dep_types[ntype] += 1

    # Service-to-service dependency graph
    svc_names = {n.get("serviceName") for n in real_services}
    dep_graph = []
    in_degree = defaultdict(int)   # how many services call this one
    out_degree = defaultdict(int)  # how many services this one calls

    for edge in apm_edges:
        src = edge.get("from", "")
        dst = edge.get("to", "")
        if src and dst:
            dep_graph.append({"from": src, "to": dst})
            out_degree[src] += 1
            in_degree[dst] += 1

    # Hub services = highest in-degree (most depended-upon)
    hub_services = sorted(svc_names, key=lambda s: -in_degree.get(s, 0))[:5]

    # Language breakdown across all services
    lang_counts = defaultdict(int)
    for s in enriched_services:
        if s["language"]:
            lang_counts[s["language"]] += 1
    # Fall back to org-wide language signals if per-service map is sparse
    if not lang_counts and otel_signals.get("languages"):
        for lang in otel_signals["languages"]:
            lang_counts[lang] = 0  # count unknown but present

    # Stack type fingerprinting
    stack_types = []
    langs = set(lang_counts.keys()) or set(otel_signals.get("languages", []))
    if "java" in langs and len(real_services) >= 3:
        stack_types.append("Java microservices")
    if "python" in langs:
        stack_types.append("Python services")
    if "nodejs" in langs or "node" in langs:
        stack_types.append("Node.js services")
    if "go" in langs:
        stack_types.append("Go services")
    if "dotnet" in langs or "generic" in langs:
        stack_types.append(".NET/generic services")
    if dep_types.get("database", 0) > 0:
        stack_types.append(f"{dep_types['database']} database(s) detected")
    if not stack_types and real_services:
        stack_types.append("Mixed/unknown languages")

    return {
        "services":           enriched_services,
        "service_count":      len(real_services),
        "inferred_deps":      inferred_deps,
        "inferred_dep_types": dict(dep_types),
        "dependency_graph":   dep_graph,
        "in_degree":          dict(in_degree),
        "out_degree":         dict(out_degree),
        "hub_services":       hub_services,
        "language_breakdown": dict(lang_counts),
        "environments":       environments,
        "stack_types":        stack_types,
    }


def analyze_teams(teams, members, users, ownership):
    """Group user activity and asset ownership by team."""
    id_to_email = {m["userId"]: m["email"] for m in members}
    email_to_user = {u["email"]: u for u in users}

    results = []
    for team in teams:
        member_ids = team.get("members", [])
        emails = [id_to_email[mid] for mid in member_ids if mid in id_to_email]
        team_users = [email_to_user[e] for e in emails if e in email_to_user]

        active = sum(1 for u in team_users if u["active"])
        logins = sum(u["login_count"] for u in team_users)
        writes = sum(u["write_ops"] for u in team_users)
        avg_score = round(sum(u.get("engagement_score", 0) for u in team_users) / len(team_users)) if team_users else 0

        det  = sum(len(ownership.get(e, {}).get("detectors",  [])) for e in emails)
        dash = sum(len(ownership.get(e, {}).get("dashboards", [])) for e in emails)
        ch   = sum(len(ownership.get(e, {}).get("charts",     [])) for e in emails)

        results.append({
            "name":        team.get("name", "—"),
            "id":          team.get("id"),
            "member_count": len(emails),
            "active":      active,
            "logins":      logins,
            "writes":      writes,
            "avg_score":   avg_score,
            "detectors":   det,
            "dashboards":  dash,
            "charts":      ch,
            "emails":      emails,
        })

    results.sort(key=lambda t: -t["avg_score"])
    return results


def analyze_detector_health(detectors, tokens):
    """Flag detectors that are muted, have no notifications, or are disabled."""
    token_map = {t["id"]: t for t in tokens}
    issues = []
    for d in detectors:
        flags = []
        if not d.get("teams") and not d.get("notifications"):
            flags.append("no-notifications")
        if d.get("disabled"):
            flags.append("disabled")
        # muted: check if any active muting rules reference this detector
        # (muting rules fetched separately — flag here if present in detector obj)
        if d.get("muted"):
            flags.append("muted")
        if flags:
            issues.append({
                "id":          d.get("id"),
                "name":        d.get("name", "—"),
                "lastUpdated": d.get("lastUpdated"),
                "owner":       d.get("lastUpdatedBy", "—"),
                "flags":       flags,
            })
    return issues


def analyze_token_attribution(session_events, members, tokens):
    """
    Cross-reference tokenId in SessionLog events with token objects
    to identify which tokens are shared across users vs personal.
    """
    id_to_email  = {m["userId"]: m["email"] for m in members}
    token_map    = {t["id"]: t for t in tokens}
    token_users  = defaultdict(set)   # tokenId -> set of emails

    for e in session_events:
        props   = e.get("properties", {})
        email   = props.get("email", "")
        tok_id  = props.get("tokenId", "")
        if email and tok_id:
            token_users[tok_id].add(email)

    results = []
    for tok_id, emails in token_users.items():
        tok = token_map.get(tok_id, {})
        results.append({
            "token_id":   tok_id,
            "token_name": tok.get("name", tok_id),
            "scopes":     ", ".join(tok.get("authScopes", [])),
            "user_count": len(emails),
            "emails":     sorted(emails),
            "shared":     len(emails) > 1,
        })
    results.sort(key=lambda x: -x["user_count"])
    return results


def _html_app_insights(ai):
    """Render the Application Insights card HTML."""
    if not ai:
        return ""

    # Service rows
    svc_rows = ""
    for s in sorted(ai["services"], key=lambda x: x["name"]):
        lang_badge = (f'<span style="background:#8b5cf6;color:#fff;padding:1px 7px;'
                      f'border-radius:9px;font-size:11px">{s["language"]}</span>'
                      if s["language"] else "—")
        hub = "★" if s["name"] in ai["hub_services"][:3] else ""
        callers = ai["in_degree"].get(s["name"], 0)
        callees = ai["out_degree"].get(s["name"], 0)
        svc_rows += (f'<tr><td>{hub} {s["name"]}</td><td>{lang_badge}</td>'
                     f'<td style="text-align:center">{callers}</td>'
                     f'<td style="text-align:center">{callees}</td></tr>')

    # Inferred dep rows
    dep_rows = ""
    for n in sorted(ai["inferred_deps"], key=lambda x: x.get("serviceName", "")):
        dep_rows += (f'<tr><td>{n.get("serviceName","?")}</td>'
                     f'<td><span style="background:#64748b;color:#fff;padding:1px 7px;'
                     f'border-radius:9px;font-size:11px">{n.get("type","unknown")}</span></td></tr>')

    # Language breakdown badges
    lang_badges = ""
    for lang, cnt in sorted(ai["language_breakdown"].items(), key=lambda x: -x[1]):
        lang_badges += (f'<span style="background:#3b82f6;color:#fff;padding:3px 10px;'
                        f'border-radius:12px;font-size:12px;margin:2px;display:inline-block">'
                        f'{lang} ({cnt})</span> ')

    # Stack type badges
    stack_badges = ""
    for st in ai["stack_types"]:
        stack_badges += (f'<span style="background:#10b981;color:#fff;padding:3px 10px;'
                         f'border-radius:12px;font-size:12px;margin:2px;display:inline-block">'
                         f'{st}</span> ')

    # Environment badges
    env_badges = ""
    for env in ai["environments"]:
        env_badges += (f'<span style="background:#f59e0b;color:#fff;padding:3px 10px;'
                       f'border-radius:12px;font-size:12px;margin:2px;display:inline-block">'
                       f'{env}</span> ')

    return f"""
  <div class="card">
    <h2>Application Insights</h2>
    <div class="stat-grid" style="margin-bottom:20px">
      <div class="stat"><div class="val">{ai['service_count']}</div><div class="lbl">Services</div></div>
      <div class="stat"><div class="val">{len(ai['inferred_deps'])}</div><div class="lbl">Inferred Deps</div></div>
      <div class="stat"><div class="val">{len(ai['dependency_graph'])}</div><div class="lbl">Service Calls</div></div>
      <div class="stat"><div class="val">{len(ai['environments'])}</div><div class="lbl">Environments</div></div>
    </div>
    {'<div style="margin-bottom:10px"><b style="font-size:12px;color:#64748b">STACK TYPES</b><br>' + stack_badges + '</div>' if stack_badges else ''}
    {'<div style="margin-bottom:10px"><b style="font-size:12px;color:#64748b">LANGUAGES</b><br>' + lang_badges + '</div>' if lang_badges else ''}
    {'<div style="margin-bottom:16px"><b style="font-size:12px;color:#64748b">ENVIRONMENTS</b><br>' + env_badges + '</div>' if env_badges else ''}
    <div style="display:flex;gap:20px;flex-wrap:wrap">
      {'<div style="flex:2;min-width:300px"><b style="font-size:12px;color:#64748b">SERVICES</b><table style="margin-top:8px"><thead><tr><th>Service</th><th>Language</th><th style="text-align:center">Called By</th><th style="text-align:center">Calls</th></tr></thead><tbody>' + svc_rows + '</tbody></table></div>' if svc_rows else ''}
      {'<div style="flex:1;min-width:200px"><b style="font-size:12px;color:#64748b">INFERRED DEPENDENCIES</b><table style="margin-top:8px"><thead><tr><th>Name</th><th>Type</th></tr></thead><tbody>' + dep_rows + '</tbody></table></div>' if dep_rows else ''}
    </div>
  </div>"""


def save_html(users, assets, otel, ownership, org_health, team_data,
              det_issues, tok_attr, detectors, dashboards, tokens,
              days, stale_days, realm, path=None, app_insights=None):
    REPORTS_DIR.mkdir(exist_ok=True)
    ts_str   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path     = path or REPORTS_DIR / f"adoption_report_{ts_str}.html"
    now_str  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    d        = org_health["details"]
    total    = org_health["total"]
    grade    = "A" if total >= 80 else "B" if total >= 65 else "C" if total >= 50 else "D" if total >= 35 else "F"
    grade_color = {"A": "#22c55e", "B": "#84cc16", "C": "#eab308", "D": "#f97316", "F": "#ef4444"}[grade]

    def pct(n, d_): return round(n / d_ * 100) if d_ else 0
    def score_color(s):
        if s >= 70: return "#22c55e"
        if s >= 40: return "#eab308"
        return "#ef4444"
    def flag_badge(f):
        colors = {"no-notifications": "#f97316", "disabled": "#ef4444", "muted": "#6366f1"}
        c = colors.get(f, "#94a3b8")
        return f'<span style="background:{c};color:#fff;padding:2px 7px;border-radius:9px;font-size:11px;margin-right:3px">{f}</span>'
    def bar(val, maxv=100, color="#3b82f6", height=6):
        w = min(round(val / maxv * 100), 100)
        return (f'<div style="background:#e2e8f0;border-radius:3px;height:{height}px;width:120px;display:inline-block;vertical-align:middle">'
                f'<div style="background:{color};width:{w}%;height:100%;border-radius:3px"></div></div>')

    # ── User rows ─────────────────────────────────────────────────────────
    user_rows = ""
    for u in users:
        sc   = u.get("engagement_score", 0)
        sc_c = score_color(sc)
        ll   = ts_to_str(u["last_login"])    if u["last_login"]    else "never"
        la   = ts_to_str(u["last_activity"]) if u["last_activity"] else "never"
        tag  = " <small style='color:#94a3b8'>[admin]</small>" if u["admin"] else ""
        own  = ownership.get(u["email"], {})
        n_det  = len(own.get("detectors",  []))
        n_dash = len(own.get("dashboards", []))
        n_ch   = len(own.get("charts",     []))
        user_rows += f"""
        <tr>
          <td>{u['email']}{tag}</td>
          <td style="text-align:center">
            <span style="font-weight:700;color:{sc_c}">{sc}</span><small>/100</small><br>
            {bar(sc, color=sc_c, height=4)}
          </td>
          <td>{ll}</td>
          <td>{la}</td>
          <td style="text-align:center">{u['login_count']}</td>
          <td style="text-align:center">{u['write_ops']}</td>
          <td style="text-align:center">{n_det}</td>
          <td style="text-align:center">{n_dash}</td>
          <td style="text-align:center">{n_ch}</td>
        </tr>"""

    # ── Team rows ─────────────────────────────────────────────────────────
    team_rows = ""
    for t in team_data:
        sc_c = score_color(t["avg_score"])
        team_rows += f"""
        <tr>
          <td>{t['name']}</td>
          <td style="text-align:center">{t['member_count']}</td>
          <td style="text-align:center">{t['active']}</td>
          <td style="text-align:center">
            <span style="font-weight:700;color:{sc_c}">{t['avg_score']}</span>/100
          </td>
          <td style="text-align:center">{t['logins']}</td>
          <td style="text-align:center">{t['writes']}</td>
          <td style="text-align:center">{t['detectors']}</td>
          <td style="text-align:center">{t['dashboards']}</td>
          <td style="text-align:center">{t['charts']}</td>
        </tr>"""

    # ── Detector issue rows ───────────────────────────────────────────────
    det_rows = ""
    for dd in sorted(det_issues, key=lambda x: x.get("lastUpdated") or 0, reverse=True)[:30]:
        badges = "".join(flag_badge(f) for f in dd["flags"])
        det_rows += f"""
        <tr>
          <td>{dd['name']}</td>
          <td>{ts_to_str(dd['lastUpdated'])}</td>
          <td>{badges}</td>
        </tr>"""

    # ── Token attribution rows ────────────────────────────────────────────
    tok_rows = ""
    for t in tok_attr:
        shared = '<span style="background:#ef4444;color:#fff;padding:2px 7px;border-radius:9px;font-size:11px">SHARED</span>' if t["shared"] else ""
        tok_rows += f"""
        <tr>
          <td>{t['token_name']}</td>
          <td>{t['scopes']}</td>
          <td style="text-align:center">{t['user_count']}</td>
          <td>{', '.join(t['emails'])}{' ' + shared if shared else ''}</td>
        </tr>"""

    # ── Stale asset rows ──────────────────────────────────────────────────
    now_ms   = int(time.time() * 1000)
    stale_ms = stale_days * 86400 * 1000
    stale_det_rows  = ""
    for dd in sorted([d for d in detectors  if (now_ms - (d.get("lastUpdated") or 0)) > stale_ms],
                     key=lambda x: x.get("lastUpdated", 0))[:20]:
        stale_det_rows += f"<tr><td>{dd['name']}</td><td>{ts_to_str(dd.get('lastUpdated'))}</td><td>{dd.get('lastUpdatedBy','—')}</td></tr>"
    stale_dash_rows = ""
    for dd in sorted([d for d in dashboards if (now_ms - (d.get("lastUpdated") or 0)) > stale_ms],
                     key=lambda x: x.get("lastUpdated", 0))[:20]:
        stale_dash_rows += f"<tr><td>{dd['name']}</td><td>{ts_to_str(dd.get('lastUpdated'))}</td><td>{dd.get('lastUpdatedBy','—')}</td></tr>"

    # ── Token alert rows ──────────────────────────────────────────────────
    tok_alert_rows = ""
    now_s = time.time()
    for t in assets["tokens"]["expired_list"]:
        tok_alert_rows += f'<tr><td>{t["name"]}</td><td><span style="color:#ef4444;font-weight:700">EXPIRED</span></td><td>{ts_to_str(t.get("expiry"))}</td></tr>'
    for t in assets["tokens"]["expiring_7d_list"]:
        dl = int((t.get("expiry", 0) / 1000 - now_s) / 86400)
        tok_alert_rows += f'<tr><td>{t["name"]}</td><td><span style="color:#f97316;font-weight:700">EXPIRING {dl}d</span></td><td>{ts_to_str(t.get("expiry"))}</td></tr>'
    for t in assets["tokens"]["expiring_30d_list"]:
        dl = int((t.get("expiry", 0) / 1000 - now_s) / 86400)
        tok_alert_rows += f'<tr><td>{t["name"]}</td><td><span style="color:#eab308;font-weight:700">expiring {dl}d</span></td><td>{ts_to_str(t.get("expiry"))}</td></tr>'

    # ── OTel rows ─────────────────────────────────────────────────────────
    otel_lang_rows = ""
    for lang in otel.get("languages", []):
        otel_lang_rows += f"<tr><td>{lang}</td></tr>"

    def dim_card(label, val, maxv, color, detail=""):
        p = pct(val, maxv)
        return f"""
        <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:16px;flex:1;min-width:180px">
          <div style="font-size:12px;color:#64748b;margin-bottom:4px">{label}</div>
          <div style="font-size:22px;font-weight:700;color:{color}">{val}<span style="font-size:13px;color:#94a3b8">/{maxv}</span></div>
          <div style="background:#e2e8f0;border-radius:4px;height:8px;margin:8px 0">
            <div style="background:{color};width:{p}%;height:100%;border-radius:4px"></div>
          </div>
          <div style="font-size:11px;color:#64748b">{detail}</div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Splunk O11y Adoption Report — {realm}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #f1f5f9; color: #1e293b; font-size: 14px; }}
    .page {{ max-width: 1200px; margin: 0 auto; padding: 24px; }}
    header {{ background: linear-gradient(135deg,#0f172a,#1e3a5f);
              color: #fff; border-radius: 12px; padding: 28px 32px; margin-bottom: 24px; }}
    header h1 {{ font-size: 22px; font-weight: 700; margin-bottom: 6px; }}
    header p  {{ font-size: 13px; color: #94a3b8; }}
    .card {{ background: #fff; border-radius: 12px; border: 1px solid #e2e8f0;
             padding: 24px; margin-bottom: 20px; }}
    .card h2 {{ font-size: 14px; font-weight: 700; text-transform: uppercase;
                letter-spacing: .05em; color: #64748b; margin-bottom: 16px;
                padding-bottom: 10px; border-bottom: 1px solid #f1f5f9; }}
    .stat-grid {{ display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 4px; }}
    .stat {{ background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px;
             padding:14px 20px; text-align:center; min-width:120px; }}
    .stat .val {{ font-size:28px; font-weight:800; color:#1e293b; }}
    .stat .lbl {{ font-size:11px; color:#94a3b8; margin-top:2px; }}
    table {{ width:100%; border-collapse:collapse; font-size:13px; }}
    th {{ background:#f8fafc; color:#64748b; font-size:11px; font-weight:600;
          text-transform:uppercase; letter-spacing:.05em;
          padding:8px 12px; text-align:left; border-bottom:2px solid #e2e8f0; }}
    td {{ padding:9px 12px; border-bottom:1px solid #f1f5f9; vertical-align:middle; }}
    tr:last-child td {{ border-bottom:none; }}
    tr:hover td {{ background:#f8fafc; }}
    .big-score {{ font-size:52px; font-weight:900; color:{grade_color}; line-height:1; }}
    .grade {{ display:inline-block; background:{grade_color}; color:#fff;
              font-size:24px; font-weight:900; width:48px; height:48px;
              border-radius:50%; text-align:center; line-height:48px; margin-left:12px; }}
    .dim-row {{ display:flex; gap:12px; flex-wrap:wrap; }}
    .section-note {{ font-size:12px; color:#94a3b8; margin-top:12px; font-style:italic; }}
  </style>
</head>
<body>
<div class="page">

  <header>
    <h1>Splunk Observability Cloud — Adoption Report</h1>
    <p>realm={realm} &nbsp;|&nbsp; generated {now_str} &nbsp;|&nbsp; activity window: last {days} days</p>
  </header>

  <!-- ORG HEALTH SCORE -->
  <div class="card">
    <h2>Org Health Score</h2>
    <div style="display:flex;align-items:center;gap:24px;margin-bottom:24px">
      <div>
        <span class="big-score">{total}</span><span style="font-size:20px;color:#94a3b8">/100</span>
        <span class="grade">{grade}</span>
      </div>
      <div style="flex:1;background:#e2e8f0;border-radius:6px;height:14px">
        <div style="background:{grade_color};width:{total}%;height:100%;border-radius:6px;transition:width .3s"></div>
      </div>
    </div>
    <div class="dim-row">
      {dim_card("User Adoption",  round(org_health['user_adoption']),  25, "#3b82f6",
                f"{d['active_users']} of {d['total_users']} users active")}
      {dim_card("OTel Coverage",  round(org_health['otel_coverage']),  25, "#8b5cf6",
                f"{d['sdk_services']} of {d['apm_services']} APM services instrumented")}
      {dim_card("Asset Hygiene",  round(org_health['asset_hygiene']),  25, "#10b981",
                f"{d['active_assets']} of {d['total_assets']} assets not stale")}
      {dim_card("Token Health",   round(org_health['token_health']),   25, "#f59e0b",
                f"{d['healthy_tokens']} of {d['total_tokens']} tokens healthy")}
    </div>
  </div>

  <!-- PLATFORM OVERVIEW -->
  <div class="card">
    <h2>Platform Overview</h2>
    <div class="stat-grid">
      <div class="stat"><div class="val">{len([u for u in users if u['active']])}</div><div class="lbl">Active Users</div></div>
      <div class="stat"><div class="val">{len(users)}</div><div class="lbl">Total Users</div></div>
      <div class="stat"><div class="val">{assets['detectors']['total']}</div><div class="lbl">Detectors</div></div>
      <div class="stat"><div class="val">{assets['dashboards']['total']}</div><div class="lbl">Dashboards</div></div>
      <div class="stat"><div class="val">{assets['charts']['total']}</div><div class="lbl">Charts</div></div>
      <div class="stat"><div class="val">{assets['tokens']['total']}</div><div class="lbl">Tokens</div></div>
      <div class="stat"><div class="val" style="color:#ef4444">{assets['detectors']['stale']}</div><div class="lbl">Stale Detectors</div></div>
      <div class="stat"><div class="val" style="color:#ef4444">{assets['dashboards']['stale']}</div><div class="lbl">Stale Dashboards</div></div>
    </div>
  </div>

  <!-- OTEL ADOPTION -->
  <div class="card">
    <h2>OTel &amp; Signal Adoption</h2>
    <div class="stat-grid" style="margin-bottom:20px">
      <div class="stat"><div class="val">{otel['apm_count']}</div><div class="lbl">APM Services</div></div>
      <div class="stat"><div class="val">{otel['sdk_count']}</div><div class="lbl">Instrumented Services</div></div>
      <div class="stat"><div class="val">{'1' if otel['collector'] else '0'}</div><div class="lbl">OTel Collector</div></div>
    </div>
    <div style="margin-top:12px;font-size:13px;color:#475569">
      <b>Languages:</b> {', '.join(otel['languages']) if otel['languages'] else 'none detected'}
      &nbsp;&nbsp; <b>SDK names:</b> {', '.join(otel['sdk_names']) if otel['sdk_names'] else 'none detected'}
    </div>
  </div>

  <!-- APPLICATION INSIGHTS -->
  {_html_app_insights(app_insights) if app_insights and app_insights.get('service_count', 0) > 0 else ''}

  <!-- USER ACTIVITY -->
  <div class="card">
    <h2>User Activity</h2>
    <table>
      <thead><tr>
        <th>User</th><th>Score</th><th>Last Login</th><th>Last Activity</th>
        <th style="text-align:center">Logins</th><th style="text-align:center">Writes</th>
        <th style="text-align:center">Det</th><th style="text-align:center">Dash</th><th style="text-align:center">Charts</th>
      </tr></thead>
      <tbody>{user_rows}</tbody>
    </table>
  </div>

  {'<!-- TEAM ROLLUP --><div class="card"><h2>Team Rollup</h2><table><thead><tr><th>Team</th><th style="text-align:center">Members</th><th style="text-align:center">Active</th><th style="text-align:center">Avg Score</th><th style="text-align:center">Logins</th><th style="text-align:center">Writes</th><th style="text-align:center">Det</th><th style="text-align:center">Dash</th><th style="text-align:center">Charts</th></tr></thead><tbody>' + team_rows + '</tbody></table></div>' if team_rows else ''}

  <!-- DETECTOR HEALTH -->
  {'<div class="card"><h2>Detector Health Issues</h2><table><thead><tr><th>Detector</th><th>Last Updated</th><th>Flags</th></tr></thead><tbody>' + det_rows + '</tbody></table></div>' if det_rows else ''}

  <!-- TOKEN ATTRIBUTION -->
  {'<div class="card"><h2>Token Attribution</h2><table><thead><tr><th>Token</th><th>Scopes</th><th style="text-align:center">Users</th><th>Attributed To</th></tr></thead><tbody>' + tok_rows + '</tbody></table></div>' if tok_rows else ''}

  <!-- TOKEN ALERTS -->
  {'<div class="card"><h2>Token Alerts</h2><table><thead><tr><th>Token</th><th>Status</th><th>Expiry</th></tr></thead><tbody>' + tok_alert_rows + '</tbody></table></div>' if tok_alert_rows else ''}

  <!-- STALE DETECTORS -->
  {'<div class="card"><h2>Stale Detectors (not updated in >' + str(stale_days) + 'd)</h2><table><thead><tr><th>Name</th><th>Last Updated</th><th>Last Modified By</th></tr></thead><tbody>' + stale_det_rows + '</tbody></table></div>' if stale_det_rows else ''}

  <!-- STALE DASHBOARDS -->
  {'<div class="card"><h2>Stale Dashboards (not updated in >' + str(stale_days) + 'd)</h2><table><thead><tr><th>Name</th><th>Last Updated</th><th>Last Modified By</th></tr></thead><tbody>' + stale_dash_rows + '</tbody></table></div>' if stale_dash_rows else ''}

  <p class="section-note">Generated by o11y-adoption &nbsp;|&nbsp; Audit API logs write operations only — dashboard views and reads are not recorded.</p>
</div>
</body>
</html>"""

    with open(path, "w") as f:
        f.write(html)
    return path


def save_csv(users, ownership, path=None):
    import csv
    REPORTS_DIR.mkdir(exist_ok=True)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = path or REPORTS_DIR / f"adoption_users_{ts}.csv"
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "email", "admin", "engagement_score",
            "last_login", "last_activity", "member_since",
            "login_count", "write_ops",
            "detectors_owned", "dashboards_owned", "charts_owned",
            "resources_used", "auth_methods",
        ])
        for u in users:
            owned = ownership.get(u["email"], {})
            w.writerow([
                u["email"],
                u["admin"],
                u.get("engagement_score", ""),
                ts_to_str(u["last_login"]),
                ts_to_str(u["last_activity"]),
                ts_to_str(u["member_since"]),
                u["login_count"],
                u["write_ops"],
                len(owned.get("detectors",  [])),
                len(owned.get("dashboards", [])),
                len(owned.get("charts",     [])),
                "|".join(u["resources_used"]),
                "|".join(u["auth_methods"]),
            ])
    return path


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def print_report(members, session_events, http_events,
                 detectors, dashboards, charts, tokens,
                 otel_services, apm_services, teams=None,
                 days=90, stale_days=90, csv_path=None, html_path=None,
                 apm_nodes=None, apm_edges=None, environments=None, svc_lang_map=None):

    users        = analyze_users(members, session_events, http_events, days)
    assets       = analyze_assets(detectors, dashboards, charts, tokens, stale_days)
    otel         = analyze_otel(otel_services, apm_services)
    ownership    = analyze_asset_ownership(detectors, dashboards, charts, members)
    org_health   = compute_org_health(users, assets, otel, days)
    det_issues   = analyze_detector_health(detectors, tokens)
    tok_attr     = analyze_token_attribution(session_events, members, tokens)
    app_insights = analyze_app_insights(
        apm_nodes or apm_services, apm_edges or [], otel_services,
        svc_lang_map or {}, environments or []
    )
    now_str      = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    width        = 110

    # Add engagement score to each user
    for u in users:
        u["engagement_score"] = score_user_engagement(u, ownership, days)

    team_data = analyze_teams(teams or [], members, users, ownership) if teams else []

    print()
    print("=" * width)
    print(f"  Splunk Observability Adoption Report  |  realm={REALM}  |  {now_str}")
    print(f"  Activity window: last {days} days  |  Stale threshold: >{stale_days} days since last update")
    print("=" * width)

    # ── Org health score ──────────────────────────────────────────────────
    total        = org_health["total"]
    d            = org_health["details"]
    grade        = "A" if total >= 80 else "B" if total >= 65 else "C" if total >= 50 else "D" if total >= 35 else "F"
    print(f"""
  ORG HEALTH SCORE
  {"─" * 50}
  Overall:  {score_bar(total)}  {total}/100  ({grade})

  User adoption    {score_bar(org_health['user_adoption'] * 4, 10)}  {org_health['user_adoption']:>4.0f}/25   {d['active_users']} of {d['total_users']} users active in last {days}d
  OTel coverage    {score_bar(org_health['otel_coverage']  * 4, 10)}  {org_health['otel_coverage']:>4.0f}/25   {d['sdk_services']} of {d['apm_services']} APM services OTel-instrumented
  Asset hygiene    {score_bar(org_health['asset_hygiene']  * 4, 10)}  {org_health['asset_hygiene']:>4.0f}/25   {d['active_assets']} of {d['total_assets']} detectors+dashboards not stale
  Token health     {score_bar(org_health['token_health']   * 4, 10)}  {org_health['token_health']:>4.0f}/25   {d['healthy_tokens']} of {d['total_tokens']} tokens healthy""")

    # ── Platform summary ──────────────────────────────────────────────────
    active_users  = [u for u in users if u["active"]]
    inactive_users = [u for u in users if not u["active"]]
    print(f"""
  PLATFORM OVERVIEW
  {"─" * 50}
  Users (total):       {len(members):>4}
  Users (active {days}d): {len(active_users):>4}
  Users (inactive):    {len(inactive_users):>4}

  Detectors:   {assets['detectors']['total']:>4}  ({assets['detectors']['active']} active, {assets['detectors']['stale']} stale >{stale_days}d)
  Dashboards:  {assets['dashboards']['total']:>4}  ({assets['dashboards']['active']} active, {assets['dashboards']['stale']} stale >{stale_days}d)
  Charts:      {assets['charts']['total']:>4}

  Tokens:      {assets['tokens']['total']:>4}  ({assets['tokens']['expiring_7d']} expiring <7d, {assets['tokens']['expiring_30d']} expiring <30d, {assets['tokens']['expired']} expired)""")

    # ── OTel / signal adoption ────────────────────────────────────────────
    svc_list   = ', '.join(otel['apm_services'][:6]) + ('...' if otel['apm_count'] > 6 else '')
    coll_str   = "yes" if otel['collector'] else "not detected"
    lang_list  = ', '.join(otel['languages']) if otel['languages'] else "none detected"
    sdk_list   = ', '.join(otel['sdk_names'])  if otel['sdk_names']  else "none detected"
    print(f"""
  OTEL & SIGNAL ADOPTION
  {"─" * 50}
  APM services (traces):        {otel['apm_count']:>4}  {svc_list}
  OTel SDK instrumented:        {otel['sdk_count']:>4}  (= APM topology count)
  OTel Collector:                     {coll_str}
  SDK languages detected:             {lang_list}
  SDK names detected:                 {sdk_list}""")

    # ── Application onboarding insights ──────────────────────────────────
    ai = app_insights
    if ai["service_count"] > 0 or ai["environments"]:
        print(f"""
  APPLICATION INSIGHTS
  {"─" * width}""")
        # Environments
        if ai["environments"]:
            print(f"  Environments:    {', '.join(ai['environments'])}")
        # Stack types
        if ai["stack_types"]:
            print(f"  Stack types:     {', '.join(ai['stack_types'])}")
        # Language breakdown
        if ai["language_breakdown"]:
            lang_parts = [f"{lang} ({cnt})" for lang, cnt in
                          sorted(ai["language_breakdown"].items(), key=lambda x: -x[1])]
            print(f"  Languages:       {', '.join(lang_parts)}")
        # Service inventory
        if ai["services"]:
            print(f"\n  Services ({ai['service_count']}):")
            for s in sorted(ai["services"], key=lambda x: x["name"]):
                lang_tag = f"  [{s['language']}]" if s["language"] else ""
                hub_tag  = "  ★ hub" if s["name"] in ai["hub_services"][:3] else ""
                print(f"    {s['name']:<35}{lang_tag}{hub_tag}")
        # Inferred dependencies
        if ai["inferred_deps"]:
            dep_parts = []
            for dtype, cnt in sorted(ai["inferred_dep_types"].items()):
                dep_parts.append(f"{cnt} {dtype}(s)")
            print(f"\n  Inferred dependencies:  {', '.join(dep_parts)}")
            for n in sorted(ai["inferred_deps"], key=lambda x: x.get("serviceName", "")):
                print(f"    {n.get('serviceName', '?'):<35}  [{n.get('type','unknown')}]")
        # Hub services (most called)
        real_hubs = [s for s in ai["hub_services"] if ai["in_degree"].get(s, 0) > 0]
        if real_hubs:
            print(f"\n  Most-depended-upon services:")
            for svc in real_hubs[:5]:
                callers = ai["in_degree"].get(svc, 0)
                callees = ai["out_degree"].get(svc, 0)
                print(f"    {svc:<35}  called by {callers} service(s), calls {callees}")

    # ── User activity table ───────────────────────────────────────────────
    print(f"""
  USER ACTIVITY  (last {days} days)
  {"─" * width}
  {"User":<35} {"Score":>6}  {"Last Login":<22} {"Last Activity":<22} {"Logins":>7} {"Writes":>7}  {"Resources Used"}""")
    print("  " + "-" * (width - 2))

    for u in users:
        last_login    = ts_to_str(u["last_login"])    if u["last_login"]    else "never"
        last_activity = ts_to_str(u["last_activity"]) if u["last_activity"] else "never"
        resources     = ", ".join(u["resources_used"][:4]) + ("..." if len(u["resources_used"]) > 4 else "")
        admin_tag     = " [admin]" if u["admin"] else ""
        name          = f"{u['email']}{admin_tag}"
        sc            = u["engagement_score"]
        score_str     = f"{sc:>3}/100"
        print(f"  {name:<35} {score_str}  {last_login:<22} {last_activity:<22} "
              f"{u['login_count']:>7} {u['write_ops']:>7}  {resources or '—'}")

    # ── Login frequency timeline ──────────────────────────────────────────
    active_with_logins = [u for u in users if u["logins_per_week"]]
    if active_with_logins:
        # Collect all week buckets across all users
        all_weeks = sorted({w for u in active_with_logins for w in u["logins_per_week"]})
        print(f"""
  LOGIN FREQUENCY  (logins per calendar week)
  {"─" * width}
  {"User":<35}""", end="")
        for w in all_weeks[-12:]:  # last 12 weeks max
            print(f"  {w[5:]}", end="")  # show "W##" only
        print()
        print("  " + "-" * (width - 2))
        for u in active_with_logins:
            tag = " [admin]" if u["admin"] else ""
            print(f"  {u['email']+tag:<35}", end="")
            for w in all_weeks[-12:]:
                count = u["logins_per_week"].get(w, 0)
                cell = f"  {count:>3}" if count else "    ."
                print(cell, end="")
            print()

    # ── Login heatmap ────────────────────────────────────────────────────
    # Aggregate across all users to show org-wide pattern
    DAYS_ABBR = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    combined_heatmap = defaultdict(int)
    for u in users:
        for (dow, hr), cnt in u["login_heatmap"].items():
            combined_heatmap[(dow, hr)] += cnt
    if combined_heatmap:
        print(f"""
  LOGIN HEATMAP  (org-wide logins by day/hour UTC)
  {"─" * 70}
  {"Day":<5}""", end="")
        for hr in range(0, 24):
            print(f" {hr:02d}", end="")
        print()
        print("  " + "-" * 75)
        for dow in range(7):
            print(f"  {DAYS_ABBR[dow]:<5}", end="")
            for hr in range(24):
                cnt = combined_heatmap.get((dow, hr), 0)
                if cnt == 0:
                    print("  .", end="")
                elif cnt <= 2:
                    print(f"  {cnt}", end="")
                else:
                    print(f" {cnt:>2}", end="")
            print()

    # ── Write activity detail per user ───────────────────────────────────
    users_with_writes = [u for u in users if u["write_ops_detail"]]
    if users_with_writes:
        print(f"""
  WRITE ACTIVITY DETAIL  (API mutations per user, last {days} days)
  {"─" * width}""")
        for u in users_with_writes:
            tag = " [admin]" if u["admin"] else ""
            print(f"\n  {u['email']}{tag}  —  {u['write_ops']} write op(s)")
            # Group by method+resource
            by_type = defaultdict(int)
            for op in u["write_ops_detail"]:
                key = f"{op['method']} {op['resource'] or op['uri'].split('/')[2] if len(op['uri'].split('/')) > 2 else op['uri']}"
                by_type[key] += 1
            for key, cnt in sorted(by_type.items(), key=lambda x: -x[1]):
                print(f"    {cnt:>4}x  {key}")
            # Show 5 most recent individual ops
            print(f"    Recent:")
            for op in u["write_ops_detail"][:5]:
                print(f"      {ts_to_str(op['ts'])}  {op['method']:<7} {op['uri']}")

    # ── Asset ownership map ───────────────────────────────────────────────
    if ownership:
        print(f"""
  ASSET OWNERSHIP  (detectors / dashboards / charts by last modifier)
  {"─" * width}
  {"User":<40} {"Detectors":>10} {"Dashboards":>11} {"Charts":>7}  Most Recently Modified""")
        print("  " + "-" * (width - 2))
        for owner, owned in sorted(ownership.items(),
                                   key=lambda x: -(len(x[1]["detectors"]) +
                                                   len(x[1]["dashboards"]) +
                                                   len(x[1]["charts"]))):
            n_det  = len(owned["detectors"])
            n_dash = len(owned["dashboards"])
            n_ch   = len(owned["charts"])
            # Most recently modified asset
            all_owned = (
                [(a["lastUpdated"] or 0, "detector",  a["name"]) for a in owned["detectors"]] +
                [(a["lastUpdated"] or 0, "dashboard", a["name"]) for a in owned["dashboards"]] +
                [(a["lastUpdated"] or 0, "chart",     a["name"]) for a in owned["charts"]]
            )
            recent = sorted(all_owned, key=lambda x: -x[0])
            recent_str = f"{recent[0][1]}: {recent[0][2][:35]}" if recent else "—"
            print(f"  {owner:<40} {n_det:>10} {n_dash:>11} {n_ch:>7}  {recent_str}")

    # ── Team rollup ───────────────────────────────────────────────────────
    if team_data:
        print(f"""
  TEAM ROLLUP
  {"─" * width}
  {"Team":<30} {"Members":>8} {"Active":>7} {"Avg Score":>10} {"Logins":>7} {"Writes":>7} {"Det":>5} {"Dash":>6} {"Charts":>7}""")
        print("  " + "-" * (width - 2))
        for t in team_data:
            print(f"  {t['name']:<30} {t['member_count']:>8} {t['active']:>7} "
                  f"{t['avg_score']:>10} {t['logins']:>7} {t['writes']:>7} "
                  f"{t['detectors']:>5} {t['dashboards']:>6} {t['charts']:>7}")

    # ── Detector health issues ────────────────────────────────────────────
    if det_issues:
        print(f"""
  DETECTOR HEALTH ISSUES  — {len(det_issues)} detector(s) flagged
  {"─" * width}
  {"Name":<50} {"Last Updated":<22} {"Flags"}""")
        print("  " + "-" * (width - 2))
        for d in sorted(det_issues, key=lambda x: x.get("lastUpdated") or 0, reverse=True)[:20]:
            flags = ", ".join(d["flags"])
            print(f"  {d['name']:<50} {ts_to_str(d['lastUpdated']):<22} {flags}")
        if len(det_issues) > 20:
            print(f"  ... and {len(det_issues) - 20} more")

    # ── Token attribution ─────────────────────────────────────────────────
    if tok_attr:
        print(f"""
  TOKEN ATTRIBUTION  (tokens seen in login events)
  {"─" * 70}
  {"Token":<35} {"Scopes":<12} {"Users":>6}  Users""")
        print("  " + "-" * 70)
        for t in tok_attr:
            shared_tag = " [SHARED]" if t["shared"] else ""
            users_str  = ", ".join(t["emails"][:3]) + ("..." if len(t["emails"]) > 3 else "")
            print(f"  {t['token_name']:<35} {t['scopes']:<12} {t['user_count']:>6}  {users_str}{shared_tag}")

    # ── Inactive users ────────────────────────────────────────────────────
    if inactive_users:
        print(f"""
  INACTIVE USERS  (no activity in last {days} days)
  {"─" * 60}""")
        for u in inactive_users:
            since = ts_to_str(u["member_since"])
            print(f"  {u['email']:<40}  member since {since}  roles={', '.join(u['roles']) or 'none'}")

    # ── Token warnings ────────────────────────────────────────────────────
    if assets["tokens"]["expiring_7d"] or assets["tokens"]["expiring_30d"] or assets["tokens"]["expired"]:
        print(f"""
  TOKEN ALERTS
  {"─" * 60}""")
        for t in assets["tokens"]["expired_list"]:
            print(f"  [EXPIRED]       {t['name']:<35}  expired {ts_to_str(t.get('expiry'))}")
        for t in assets["tokens"]["expiring_7d_list"]:
            exp_days = int((t.get("expiry", 0) / 1000 - time.time()) / 86400)
            print(f"  [EXPIRING <7d]  {t['name']:<35}  expires in {exp_days}d")
        for t in assets["tokens"]["expiring_30d_list"]:
            exp_days = int((t.get("expiry", 0) / 1000 - time.time()) / 86400)
            print(f"  [EXPIRING <30d] {t['name']:<35}  expires in {exp_days}d")

    # ── Stale asset details ───────────────────────────────────────────────
    now_ms    = int(time.time() * 1000)
    stale_ms  = stale_days * 86400 * 1000
    stale_det = [d for d in detectors  if (now_ms - (d.get("lastUpdated") or 0)) > stale_ms]
    stale_dash = [d for d in dashboards if (now_ms - (d.get("lastUpdated") or 0)) > stale_ms]

    if stale_det:
        print(f"""
  STALE DETECTORS  (not updated in >{stale_days}d)  — {len(stale_det)} detector(s)
  {"─" * 70}
  {"Name":<50} {"Last Updated":<22} {"Creator"}""")
        for d in sorted(stale_det, key=lambda x: x.get("lastUpdated", 0))[:15]:
            print(f"  {d['name']:<50} {ts_to_str(d.get('lastUpdated')):<22} {d.get('lastUpdatedBy', '—')}")
        if len(stale_det) > 15:
            print(f"  ... and {len(stale_det) - 15} more")

    if stale_dash:
        print(f"""
  STALE DASHBOARDS  (not updated in >{stale_days}d)  — {len(stale_dash)} dashboard(s)
  {"─" * 70}
  {"Name":<50} {"Last Updated":<22} {"Creator"}""")
        for d in sorted(stale_dash, key=lambda x: x.get("lastUpdated", 0))[:15]:
            print(f"  {d['name']:<50} {ts_to_str(d.get('lastUpdated')):<22} {d.get('lastUpdatedBy', '—')}")
        if len(stale_dash) > 15:
            print(f"  ... and {len(stale_dash) - 15} more")

    # ── CSV export ────────────────────────────────────────────────────────
    if csv_path is not None:
        out = save_csv(users, ownership, path=csv_path if csv_path != True else None)
        print(f"\n  CSV saved: {out}")

    # ── HTML export ───────────────────────────────────────────────────────
    if html_path is not None:
        out = save_html(
            users, assets, otel, ownership, org_health, team_data,
            det_issues, tok_attr, detectors, dashboards, tokens,
            days, stale_days, REALM,
            path=html_path if html_path != True else None,
            app_insights=app_insights,
        )
        print(f"\n  HTML saved: {out}")

    print()


def save_json(data, prefix="adoption_report"):
    REPORTS_DIR.mkdir(exist_ok=True)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = REPORTS_DIR / f"{prefix}_{ts}.json"
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    return path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Splunk Observability adoption & user activity audit"
    )
    sub = parser.add_subparsers(dest="command")

    p_report = sub.add_parser("report", help="Full adoption report — users, assets, OTel coverage")
    p_report.add_argument("--days",       type=int, default=90,
                          help="Activity window in days (default: 90)")
    p_report.add_argument("--since",      help="Start date YYYY-MM-DD (overrides --days)")
    p_report.add_argument("--until",      help="End date YYYY-MM-DD (default: now)")
    p_report.add_argument("--stale-days", type=int, default=90,
                          help="Mark assets stale if not updated in N days (default: 90)")
    p_report.add_argument("--json",       action="store_true",
                          help="Also save full data as JSON to reports/")
    p_report.add_argument("--csv",        action="store_true",
                          help="Save user activity table as CSV to reports/")
    p_report.add_argument("--html",       action="store_true",
                          help="Save full report as HTML to reports/")
    p_report.add_argument("--no-otel",    action="store_true",
                          help="Skip OTel MTS dimension scan (faster)")
    p_report.add_argument("--no-teams",   action="store_true",
                          help="Skip team rollup section")

    p_users = sub.add_parser("users", help="User activity summary only")
    p_users.add_argument("--days",          type=int, default=90)
    p_users.add_argument("--since",         help="Start date YYYY-MM-DD (overrides --days)")
    p_users.add_argument("--until",         help="End date YYYY-MM-DD (default: now)")
    p_users.add_argument("--inactive-only", action="store_true",
                         help="Show only users with no activity in the window")
    p_users.add_argument("--csv",           action="store_true",
                         help="Save results as CSV to reports/")

    p_tokens = sub.add_parser("tokens", help="Token health — expiring and expired tokens")

    p_timeline = sub.add_parser("activity-timeline",
                                help="Chronological write-event timeline for a specific user")
    p_timeline.add_argument("--user",  required=True, help="User email address")
    p_timeline.add_argument("--days",  type=int, default=90)
    p_timeline.add_argument("--since", help="Start date YYYY-MM-DD")
    p_timeline.add_argument("--until", help="End date YYYY-MM-DD")

    args = parser.parse_args()

    if not TOKEN:
        print("Error: SPLUNK_ACCESS_TOKEN not set")
        sys.exit(1)

    def parse_date_ms(date_str, end_of_day=False):
        """Parse YYYY-MM-DD to milliseconds."""
        dt = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        if end_of_day:
            dt = dt.replace(hour=23, minute=59, second=59)
        return int(dt.timestamp() * 1000)

    def resolve_window(args):
        """Return (since_ms, until_ms, effective_days) from --since/--until/--days."""
        until_ms = parse_date_ms(args.until, end_of_day=True) if getattr(args, "until", None) else None
        if getattr(args, "since", None):
            since_ms = parse_date_ms(args.since)
            end_ms   = until_ms or int(time.time() * 1000)
            eff_days = max(1, int((end_ms - since_ms) / (86400 * 1000)))
        else:
            since_ms = None
            eff_days = args.days
        return since_ms, until_ms, eff_days

    if args.command == "report":
        since_ms, until_ms, eff_days = resolve_window(args)
        window_desc = (f"{args.since} → {args.until or 'now'}"
                       if getattr(args, "since", None) else f"last {eff_days}d")
        print(f"Fetching data from realm={REALM} ({window_desc})...")
        print("  members...")
        members = fetch_members()
        print("  session events...")
        session_events = fetch_session_events(eff_days, since_ms, until_ms)
        print("  HTTP audit events...")
        http_events = fetch_http_events(eff_days, since_ms, until_ms)
        print("  assets (detectors, dashboards, charts, tokens)...")
        detectors, dashboards, charts, tokens = fetch_assets()

        otel_services = {}
        apm_services  = []
        apm_nodes     = []
        apm_edges     = []
        environments  = []
        svc_lang_map  = {}
        if not args.no_otel:
            print("  OTel dimensions...")
            otel_services = fetch_otel_signals()
            print("  APM topology...")
            apm_nodes, apm_edges = fetch_apm_topology()
            apm_services = [n for n in apm_nodes if not n.get("inferred")]
            print("  Deployment environments...")
            environments = fetch_deployment_environments()
            print("  Per-service languages...")
            svc_lang_map = fetch_service_languages()

        teams = []
        if not args.no_teams:
            print("  teams...")
            teams = fetch_teams()

        print_report(members, session_events, http_events,
                     detectors, dashboards, charts, tokens,
                     otel_services, apm_services, teams=teams,
                     days=eff_days, stale_days=args.stale_days,
                     csv_path=True if args.csv else None,
                     html_path=True if args.html else None,
                     apm_nodes=apm_nodes, apm_edges=apm_edges,
                     environments=environments, svc_lang_map=svc_lang_map)

        if args.json:
            path = save_json({
                "members": members,
                "session_events": session_events,
                "http_events": http_events,
                "detectors": detectors,
                "dashboards": dashboards,
                "tokens": tokens,
                "otel_signals": otel_services,
                "apm_nodes": apm_nodes,
                "apm_edges": apm_edges,
                "environments": environments,
                "svc_lang_map": svc_lang_map,
            })
            print(f"  JSON saved: {path}")

    elif args.command == "users":
        since_ms, until_ms, eff_days = resolve_window(args)
        print(f"Fetching user activity...")
        members        = fetch_members()
        session_events = fetch_session_events(eff_days, since_ms, until_ms)
        http_events    = fetch_http_events(eff_days, since_ms, until_ms)
        users          = analyze_users(members, session_events, http_events, eff_days)
        ownership      = analyze_asset_ownership([], [], [], members)

        if args.inactive_only:
            users = [u for u in users if not u["active"]]
            print(f"\nInactive users: {len(users)}\n")
        else:
            print(f"\nUser activity:\n")

        for u in users:
            u["engagement_score"] = score_user_engagement(u, ownership, eff_days)

        print(f"  {'User':<35} {'Score':>6}  {'Last Login':<22} {'Logins':>7} {'Writes':>7}")
        print("  " + "-" * 85)
        for u in users:
            ll  = ts_to_str(u["last_login"]) if u["last_login"] else "never"
            tag = " [admin]" if u["admin"] else ""
            print(f"  {u['email']+tag:<35} {u['engagement_score']:>3}/100  {ll:<22} {u['login_count']:>7} {u['write_ops']:>7}")

        if args.csv:
            path = save_csv(users, ownership)
            print(f"\n  CSV saved: {path}")

    elif args.command == "tokens":
        print("Fetching tokens...")
        tokens = api_get("/v2/token", {"limit": 1000}).get("results", [])
        assets = analyze_assets([], [], [], tokens)
        now_s  = time.time()

        print(f"\nToken health (realm={REALM})  —  {len(tokens)} total\n")
        print(f"  {'Name':<40} {'Type':<10} {'Expires':<22} {'Status'}")
        print("  " + "-" * 90)
        for t in sorted(tokens, key=lambda x: x.get("expiry") or 0):
            exp = t.get("expiry")
            if exp and exp > 0:
                days_left = (exp / 1000 - now_s) / 86400
                if days_left < 0:
                    status = "EXPIRED"
                elif days_left <= 7:
                    status = f"EXPIRING {int(days_left)}d"
                elif days_left <= 30:
                    status = f"expiring {int(days_left)}d"
                else:
                    status = f"ok ({int(days_left)}d)"
                exp_str = ts_to_str(exp)
            else:
                status  = "no expiry"
                exp_str = "—"
            scopes = ", ".join(t.get("authScopes", []))
            print(f"  {t['name']:<40} {scopes:<10} {exp_str:<22} {status}")

    elif args.command == "activity-timeline":
        since_ms, until_ms, eff_days = resolve_window(args)
        print(f"Fetching activity timeline for {args.user}...")
        http_events = fetch_http_events(eff_days, since_ms, until_ms)
        session_events = fetch_session_events(eff_days, since_ms, until_ms)

        # Filter to this user
        user_http = [e for e in http_events
                     if e.get("properties", {}).get("sf_email") == args.user]
        user_logins = [e for e in session_events
                       if e.get("properties", {}).get("email") == args.user
                       and e.get("properties", {}).get("action") == "session created"]

        all_events = (
            [(e["timestamp"], "LOGIN",
              e.get("properties", {}).get("authMethod", ""),
              "") for e in user_logins] +
            [(e["timestamp"],
              e.get("properties", {}).get("sf_requestMethod", ""),
              e.get("properties", {}).get("sf_resourceType", ""),
              e.get("properties", {}).get("sf_requestUri", "")) for e in user_http]
        )
        all_events.sort(key=lambda x: x[0])

        if not all_events:
            print(f"  No activity found for {args.user} in this window.")
        else:
            print(f"\n  Activity timeline for {args.user}  ({len(all_events)} events)\n")
            print(f"  {'Timestamp':<22} {'Action':<8} {'Resource/Detail'}")
            print("  " + "-" * 70)
            for ts, action, resource, uri in all_events:
                detail = uri or resource or "—"
                print(f"  {ts_to_str(ts):<22} {action:<8} {detail}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
