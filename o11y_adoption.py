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
  - GET /v2/incident                            — alert history per detector
  - GET /v2/integration                         — cloud/infra integration coverage
  - GET /v2/organization                        — org limits & capacity
  - POST /v2/signalflow/execute                 — data ingestion trend (MTS count)
"""

import argparse
import json
import math
import os
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

REALM = os.environ.get("SPLUNK_REALM", "us1")
TOKEN = os.environ.get("SPLUNK_ACCESS_TOKEN", "")
API_BASE = f"https://api.{REALM}.signalfx.com"
APP_BASE = f"https://app.{REALM}.signalfx.com"

HDR = {"X-SF-TOKEN": TOKEN, "Content-Type": "application/json"}

REPORTS_DIR = Path("reports")
CACHE_DIR   = Path(".cache")

# ---------------------------------------------------------------------------
# Disk cache helpers
# ---------------------------------------------------------------------------

def _cache_path(key):
    CACHE_DIR.mkdir(exist_ok=True)
    return CACHE_DIR / f"{key}.json"


def cache_load(key, max_age_s=300):
    """Return cached data if fresher than max_age_s, else None."""
    p = _cache_path(key)
    if not p.exists():
        return None
    if time.time() - p.stat().st_mtime > max_age_s:
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        return None


def cache_save(key, data):
    try:
        _cache_path(key).write_text(json.dumps(data, default=str))
    except Exception:
        pass


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
    try:
        tokens = api_get("/v2/token", {"limit": 1000}).get("results", [])
    except Exception:
        tokens = []
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


def fetch_services_per_environment(environments):
    """
    Query APM topology per environment to build a service -> [envs] map.
    Skips workshop envs to keep it fast (they all share the same service set).
    Returns dict: {service_name: [env, ...]}
    """
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    week_ago = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 604800))

    svc_envs = defaultdict(set)
    # Only query non-workshop envs to avoid N*26 API calls
    non_workshop = [e for e in environments if not e.endswith("-workshop")]
    workshop_envs = [e for e in environments if e.endswith("-workshop")]

    for env in non_workshop:
        try:
            r = requests.post(f"{API_BASE}/v2/apm/topology",
                              headers=HDR,
                              json={"timeRange": f"{week_ago}/{now}", "environmentName": env},
                              timeout=15)
            nodes = (r.json().get("data") or {}).get("nodes", [])
            for n in nodes:
                if not n.get("inferred"):
                    svc_envs[n["serviceName"]].add(env)
        except Exception:
            continue

    # Sample one workshop env to check if services are the same
    if workshop_envs:
        try:
            sample_env = workshop_envs[0]
            r = requests.post(f"{API_BASE}/v2/apm/topology",
                              headers=HDR,
                              json={"timeRange": f"{week_ago}/{now}", "environmentName": sample_env},
                              timeout=15)
            nodes = (r.json().get("data") or {}).get("nodes", [])
            workshop_svcs = {n["serviceName"] for n in nodes if not n.get("inferred")}
            # Check if all workshop envs share same services as sampled env
            for svc in workshop_svcs:
                svc_envs[svc].add(f"workshop ({len(workshop_envs)} envs)")
        except Exception:
            pass

    return {svc: sorted(envs) for svc, envs in svc_envs.items()}


def fetch_service_languages():
    """
    Per-service language mapping is not available via dimension or MTS APIs
    (telemetry.sdk.language is a span resource attribute, not a metric dimension,
    and customProperties on service.name dimensions are always empty).
    Returns empty dict — caller falls back to org-wide language signals.
    """
    return {}


def fetch_muting_rules():
    """Return all active muting rules."""
    try:
        data = api_get("/v2/alertmuting", {"limit": 1000})
        return data.get("results", [])
    except Exception:
        return []


def fetch_incidents(days=90):
    """Return recent incidents across all detectors."""
    try:
        start_ms = int((datetime.now(timezone.utc) - timedelta(days=days)).timestamp() * 1000)
        data = api_get("/v2/incident", {"limit": 1000, "startTime": start_ms, "includeResolved": "true"})
        return data.get("results", data if isinstance(data, list) else [])
    except Exception:
        return []


def fetch_integrations():
    """Return all configured integrations."""
    try:
        data = api_get("/v2/integration", {"limit": 1000})
        return data.get("results", [])
    except Exception:
        return []


def fetch_organization():
    """Return org-level limits and usage from /v2/organization."""
    try:
        return api_get("/v2/organization")
    except Exception:
        return {}


def fetch_dashboard_chart_counts(dashboards, max_fetch=50):
    """
    Fetch chart count per dashboard by reading each dashboard's chartIds.
    Limits to max_fetch most-recently-updated dashboards to stay fast.
    Returns dict: {dashboard_id: chart_count}
    """
    recent = sorted(dashboards, key=lambda d: d.get("lastUpdated") or 0, reverse=True)[:max_fetch]
    counts = {}
    for d in recent:
        did = d.get("id")
        if not did:
            continue
        try:
            detail = api_get(f"/v2/dashboard/{did}")
            charts = detail.get("charts", detail.get("chartIds", []))
            counts[did] = len(charts)
        except Exception:
            counts[did] = 0
    return counts


def fetch_ingestion_trend():
    """
    Use SignalFlow to get monthly MTS count for the last 6 months.
    Returns list of {month, mts_count} dicts, newest last.
    """
    program = "data('sf.org.numDatapointsReceived').sum().publish()"
    now_ms  = int(time.time() * 1000)
    six_months_ago_ms = now_ms - 6 * 30 * 86400 * 1000
    try:
        r = requests.post(
            f"{API_BASE}/v2/signalflow/execute",
            headers=HDR,
            json={
                "program":     program,
                "start":       six_months_ago_ms,
                "stop":        now_ms,
                "resolution":  86400000 * 30,  # monthly
                "immediate":   True,
            },
            timeout=30,
            stream=True,
        )
        monthly = []
        for line in r.iter_lines():
            if not line:
                continue
            try:
                msg = json.loads(line)
            except Exception:
                continue
            if msg.get("type") == "data":
                ts = msg.get("logicalTimestampMs", 0)
                values = list(msg.get("data", {}).values())
                if values:
                    month = datetime.fromtimestamp(ts / 1000, tz=timezone.utc).strftime("%Y-%m")
                    monthly.append({"month": month, "value": values[0]})
        return sorted(monthly, key=lambda x: x["month"])
    except Exception:
        return []


def fetch_signalflow_metric(program, days=90):
    """Generic SignalFlow executor — returns list of (ts_ms, value) tuples."""
    now_ms   = int(time.time() * 1000)
    start_ms = now_ms - days * 86400 * 1000
    try:
        r = requests.post(
            f"{API_BASE}/v2/signalflow/execute",
            headers=HDR,
            json={"program": program, "start": start_ms, "stop": now_ms,
                  "resolution": 3600000, "immediate": True},
            timeout=30,
            stream=True,
        )
        results = []
        for line in r.iter_lines():
            if not line:
                continue
            try:
                msg = json.loads(line)
            except Exception:
                continue
            if msg.get("type") == "data":
                ts = msg.get("logicalTimestampMs", 0)
                values = list(msg.get("data", {}).values())
                if values:
                    results.append((ts, values[0]))
        return results
    except Exception:
        return []


def fetch_signalflow_by_dimension(program_template, dimension_values, days=90):
    """
    Run a SignalFlow program for each value in dimension_values.
    Returns dict: {value: [(ts_ms, count), ...]}
    Used for per-product ingestion breakdown.
    """
    results = {}
    for val in dimension_values:
        prog = program_template.format(val=val)
        pts  = fetch_signalflow_metric(prog, days=days)
        if pts:
            results[val] = pts
    return results


def fetch_incident_details(incidents):
    """
    Enrich incidents with duration and resolution info.
    Returns list of dicts with duration_min, acknowledged, resolved fields.
    """
    enriched = []
    for inc in incidents:
        created   = inc.get("createdAt") or inc.get("timestamp", 0)
        resolved  = inc.get("resolvedAt") or inc.get("endTime")
        ack_time  = inc.get("acknowledgedAt")
        duration_min = round((resolved - created) / 60000) if resolved and created else None
        mtta_min     = round((ack_time - created) / 60000) if ack_time and created else None
        enriched.append({
            "id":              inc.get("id", ""),
            "detectorId":      inc.get("detectorId", ""),
            "detectorName":    inc.get("detectorName", ""),
            "severity":        inc.get("severity", ""),
            "status":          inc.get("status", ""),
            "created":         created,
            "resolved":        resolved,
            "acknowledged":    bool(ack_time),
            "acknowledgedBy":  inc.get("acknowledgedBy", ""),
            "duration_min":    duration_min,
            "mtta_min":        mtta_min,
        })
    return enriched


def fetch_top_mts(limit=20):
    """
    Find highest-cardinality metrics using the MTS summary API.
    Returns list of {metric, mts_count}.
    """
    try:
        data = api_get("/v2/metrictimeseries", {"limit": 1, "query": "*"})
        # The API returns total count in metadata; we need per-metric breakdown
        # Use dimension search to find top metrics by MTS count
        r = api_get("/v2/metric", {"limit": limit, "orderBy": "-numMTS"})
        results = r.get("results", [])
        return [{"metric": m.get("name", ""), "mts_count": m.get("numMTS", 0)}
                for m in results if m.get("numMTS", 0) > 0]
    except Exception:
        return []


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
    session_ids_by_email = defaultdict(dict)  # email -> {sessionId: created_ts}

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
            sid = props.get("sessionId", "")
            if sid:
                session_ids_by_email[email][sid] = ts
        elif action == "session deleted":
            logouts_by_email[email].append(ts)
            sid = props.get("sessionId", "")
            if sid and sid in session_ids_by_email[email]:
                # record duration
                duration_ms = ts - session_ids_by_email[email].pop(sid)
                session_ids_by_email[email][f"_dur_{sid}"] = duration_ms

    # Compute avg session duration per user (minutes)
    def avg_session_duration(email):
        durations = [v for k, v in session_ids_by_email[email].items()
                     if k.startswith("_dur_") and v > 0]
        if not durations:
            return None
        avg_ms = sum(durations) / len(durations)
        return round(avg_ms / 60000, 1)  # minutes

    # HTTP activity analysis
    http_by_email     = defaultdict(list)   # email -> [timestamp ms, ...]
    resource_by_email = defaultdict(set)
    write_count_email = defaultdict(int)
    read_count_email  = defaultdict(int)
    write_ops_detail  = defaultdict(list)   # email -> [{method, uri, resource, ts}, ...]
    # Feature area usage: resource_type -> count per email
    feature_counts_by_email = defaultdict(lambda: defaultdict(int))
    # API vs UI split: track client type
    api_count_by_email = defaultdict(int)
    ui_count_by_email  = defaultdict(int)

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
        client = props.get("sf_clientType", props.get("sf_userAgent", ""))

        if rtype:
            resource_by_email[email].add(rtype)
            feature_counts_by_email[email][rtype] += 1

        # API vs UI split: heuristic — browser UA = UI, else API
        if client and ("Mozilla" in client or "Chrome" in client or "Safari" in client or "Firefox" in client):
            ui_count_by_email[email] += 1
        elif client:
            api_count_by_email[email] += 1

        if method and method != "GET":
            write_count_email[email] += 1
            write_ops_detail[email].append({
                "method":   method,
                "uri":      uri,
                "resource": rtype,
                "ts":       ts,
            })
        elif method == "GET":
            read_count_email[email] += 1

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
        heatmap = defaultdict(int)
        for ts in login_ts_list:
            dt = datetime.fromtimestamp(ts / 1000, tz=timezone.utc)
            heatmap[(dt.weekday(), dt.hour)] += 1
        return dict(heatmap)

    # Monthly cohort: which month the user joined
    def cohort_month(created_ms):
        if not created_ms:
            return None
        dt = datetime.fromtimestamp(created_ms / 1000, tz=timezone.utc)
        return dt.strftime("%Y-%m")

    # Activity per month bucket (for trend)
    def activity_by_month(ts_list):
        buckets = defaultdict(int)
        for ts in ts_list:
            dt = datetime.fromtimestamp(ts / 1000, tz=timezone.utc)
            buckets[dt.strftime("%Y-%m")] += 1
        return dict(sorted(buckets.items()))

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

        # Feature fingerprint: top 3 resource types by usage count
        feat_counts = dict(feature_counts_by_email[email])
        top_features = sorted(feat_counts.items(), key=lambda x: -x[1])[:5]

        # API vs UI: if no client type info, leave as None
        api_c = api_count_by_email[email]
        ui_c  = ui_count_by_email[email]
        total_attributed = api_c + ui_c
        if total_attributed > 0:
            api_pct = round(api_c / total_attributed * 100)
        else:
            api_pct = None

        # Time-to-first-value: days from join to first write op
        member_since_ms = member.get("created")
        first_write_ts  = None
        if write_ops_detail[email]:
            first_write_ts = min(op["ts"] for op in write_ops_detail[email])
        if member_since_ms and first_write_ts:
            ttfv_days = round((first_write_ts - member_since_ms) / (86400 * 1000))
        else:
            ttfv_days = None

        users.append({
            "email":              email,
            "full_name":          member.get("fullName", ""),
            "admin":              member.get("admin", False),
            "roles":              [r.get("title", "") for r in member.get("roles", [])],
            "member_since":       member_since_ms,
            "cohort_month":       cohort_month(member_since_ms),
            "last_login":         last_login,
            "last_activity":      last_activity,
            "login_count":        len(logins),
            "http_count":         len(http_ts),
            "read_ops":           read_count_email[email],
            "write_ops":          write_count_email[email],
            "resources_used":     sorted(resource_by_email[email]),
            "auth_methods":       sorted(auth_methods[email]),
            "active":             (last_activity is not None and
                                  last_activity >= int((datetime.now(timezone.utc) - timedelta(days=days)).timestamp() * 1000)),
            "logins_per_week":    logins_per_week(logins_by_email[email], days),
            "login_heatmap":      login_heatmap(logins_by_email[email]),
            "write_ops_detail":   sorted(write_ops_detail[email], key=lambda x: x["ts"], reverse=True),
            "write_ops_all_ts":   [op["ts"] for op in write_ops_detail[email]],
            "feature_counts":     feat_counts,
            "top_features":       top_features,
            "avg_session_min":    avg_session_duration(email),
            "api_call_count":     api_c,
            "ui_action_count":    ui_c,
            "api_pct":            api_pct,
            "activity_by_month":  activity_by_month(all_ts),
            "ttfv_days":          ttfv_days,
            "activity_last30":    0,   # filled in post-loop
            "activity_prev30":    0,
            "activity_delta":     0,
        })

    # Compute 30d vs prev-30d engagement delta per user
    now_ms      = int(time.time() * 1000)
    last30_ms   = now_ms - 30 * 86400 * 1000
    prev30_ms   = now_ms - 60 * 86400 * 1000

    def activity_in_window(ts_list, start_ms, end_ms):
        return sum(1 for ts in ts_list if start_ms <= ts <= end_ms)

    for u in users:
        all_ts_list = sorted(
            logins_by_email[u["email"]] + http_by_email[u["email"]]
        )
        last30 = activity_in_window(all_ts_list, last30_ms, now_ms)
        prev30 = activity_in_window(all_ts_list, prev30_ms, last30_ms)
        u["activity_last30"]  = last30
        u["activity_prev30"]  = prev30
        u["activity_delta"]   = last30 - prev30   # positive = growing, negative = churning

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
      - Recency         (25pts): days since last activity, linear decay
      - Login cadence   (20pts): logins over the window vs expected weekly cadence
      - Write activity  (20pts): write ops (log scale, caps at 50 ops = full score)
      - Read activity   (15pts): read ops (log scale, caps at 200 ops = full score)
      - Asset footprint (10pts): detectors + dashboards + charts owned (log scale)
      - Feature breadth (10pts): number of distinct feature areas used (max 8)
    """
    score = 0

    # Recency (25pts): full score if active today, 0 if no activity or >days ago
    if user["last_activity"]:
        now_ms     = time.time() * 1000
        days_since = (now_ms - user["last_activity"]) / (86400 * 1000)
        recency    = max(0.0, 1.0 - days_since / days)
        score     += recency * 25

    # Login cadence (20pts): target = at least 1 login/week over the window
    weeks         = max(days / 7, 1)
    target_logins = weeks
    cadence       = min(user["login_count"] / target_logins, 1.0)
    score        += cadence * 20

    # Write activity (20pts): log scale, 50 ops = full score
    if user["write_ops"] > 0:
        write_score = min(math.log10(user["write_ops"] + 1) / math.log10(51), 1.0)
        score      += write_score * 20

    # Read activity (15pts): log scale, 200 ops = full score
    if user.get("read_ops", 0) > 0:
        read_score = min(math.log10(user["read_ops"] + 1) / math.log10(201), 1.0)
        score     += read_score * 15

    # Asset footprint (10pts): log scale, 20 assets = full score
    email = user["email"]
    owned = ownership.get(email, {})
    n_assets = (len(owned.get("detectors", [])) +
                len(owned.get("dashboards", [])) +
                len(owned.get("charts", [])))
    if n_assets > 0:
        asset_score = min(math.log10(n_assets + 1) / math.log10(21), 1.0)
        score      += asset_score * 10

    # Feature breadth (10pts): distinct resource types used, 8 = full score
    n_features = len(user.get("feature_counts", {}))
    if n_features > 0:
        score += min(n_features / 8, 1.0) * 10

    return round(score)


def tag_user(user, ownership, score):
    """Return a role tag for the user based on behaviour patterns."""
    email = user["email"]
    owned = ownership.get(email, {})
    n_assets = (len(owned.get("detectors", [])) + len(owned.get("dashboards", [])) +
                len(owned.get("charts", [])))
    n_features = len(user.get("feature_counts", {}))
    delta = user.get("activity_delta", 0)

    if score >= 70 and n_assets >= 5 and n_features >= 3:
        return "Champion"
    if user.get("api_pct", 0) and user["api_pct"] >= 60 and user["write_ops"] >= 10:
        return "Automator"
    if user["write_ops"] >= 20 and n_assets >= 10:
        return "Power Builder"
    if user["login_count"] >= 10 and user["write_ops"] == 0:
        return "Viewer"
    if not user["active"]:
        return "Inactive"
    if delta < -5:
        return "Churning"
    if delta > 5:
        return "Growing"
    return "Active"


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


def analyze_cohorts(users, days):
    """
    Group users by join month (cohort). For each cohort report:
      - size: total users in cohort
      - active: still active in the reporting window
      - retention: active/size %
    """
    cohorts = defaultdict(lambda: {"size": 0, "active": 0})
    for u in users:
        month = u.get("cohort_month")
        if not month:
            month = "unknown"
        cohorts[month]["size"] += 1
        if u["active"]:
            cohorts[month]["active"] += 1
    results = []
    for month, data in sorted(cohorts.items()):
        retention = round(data["active"] / data["size"] * 100) if data["size"] else 0
        results.append({"month": month, "size": data["size"],
                        "active": data["active"], "retention_pct": retention})
    return results


def analyze_feature_heatmap(users):
    """
    Org-wide feature area usage heatmap.
    Returns:
      - by_feature: {resource_type: total_count}
      - by_user_feature: {email: {resource_type: count}}
      - unused_features: known feature areas with zero activity
    """
    KNOWN_FEATURES = [
        "detector", "dashboard", "chart", "alertmuting", "token",
        "team", "integration", "metrictimeseries", "dimension",
        "organization", "session", "trace", "rum", "synthetics",
        "logsobserver", "metric",
    ]
    by_feature = defaultdict(int)
    by_user_feature = {}
    for u in users:
        fc = u.get("feature_counts", {})
        by_user_feature[u["email"]] = fc
        for rtype, cnt in fc.items():
            by_feature[rtype] += cnt
    unused = [f for f in KNOWN_FEATURES if by_feature.get(f, 0) == 0]
    return {
        "by_feature":      dict(sorted(by_feature.items(), key=lambda x: -x[1])),
        "by_user_feature": by_user_feature,
        "unused_features": unused,
    }


def analyze_muting_activity(users, muting_rules):
    """Identify users with high muting rule activity (alert fatigue signal)."""
    muting_writers = []
    for u in users:
        mute_writes = sum(1 for op in u.get("write_ops_detail", [])
                          if "muting" in op.get("uri", "").lower()
                          or "muting" in op.get("resource", "").lower())
        if mute_writes > 0:
            muting_writers.append({"email": u["email"], "mute_writes": mute_writes})
    muting_writers.sort(key=lambda x: -x["mute_writes"])
    return {
        "writers": muting_writers,
        "active_rules": len(muting_rules),
        "total_rules": len(muting_rules),
    }


def analyze_collaboration(users, detectors, dashboards, charts, members):
    """
    Identify asset read sharing: who reads assets owned by others.
    Since read events reference URIs like /v2/dashboard/{id}, we can cross-ref
    with asset ownership to find cross-user reads.
    Returns top shared assets (assets with GET events from non-owners).
    """
    id_to_owner = {}
    for d in detectors:
        aid = d.get("id")
        owner = d.get("lastUpdatedBy") or d.get("creator", "")
        if aid:
            id_to_owner[aid] = ("detector", d.get("name", ""), owner)
    for d in dashboards:
        aid = d.get("id")
        owner = d.get("lastUpdatedBy") or d.get("creator", "")
        if aid:
            id_to_owner[aid] = ("dashboard", d.get("name", ""), owner)
    for c in charts:
        aid = c.get("id")
        owner = c.get("lastUpdatedBy") or c.get("creator", "")
        if aid:
            id_to_owner[aid] = ("chart", c.get("name", ""), owner)

    cross_reads = defaultdict(lambda: defaultdict(int))  # asset_id -> {reader_email: count}
    for u in users:
        for op in u.get("write_ops_detail", []):
            pass  # write ops already covered elsewhere
        # parse read URIs from http_count (we don't have raw read events per-user here,
        # but we can use write_ops_detail URI patterns as a proxy for active assets)

    # Simpler: identify detectors/dashboards modified by >1 distinct user
    multi_editor_assets = []
    id_to_email = {m["userId"]: m["email"] for m in members}
    for d in detectors:
        creator = id_to_email.get(d.get("creator", ""), d.get("creator", ""))
        modifier = id_to_email.get(d.get("lastUpdatedBy", ""), d.get("lastUpdatedBy", ""))
        if creator and modifier and creator != modifier:
            multi_editor_assets.append({
                "type": "detector", "name": d.get("name", ""),
                "creator": creator, "last_modified_by": modifier,
            })
    for d in dashboards:
        creator = id_to_email.get(d.get("creator", ""), d.get("creator", ""))
        modifier = id_to_email.get(d.get("lastUpdatedBy", ""), d.get("lastUpdatedBy", ""))
        if creator and modifier and creator != modifier:
            multi_editor_assets.append({
                "type": "dashboard", "name": d.get("name", ""),
                "creator": creator, "last_modified_by": modifier,
            })
    return {"multi_editor_assets": multi_editor_assets[:30]}


def analyze_detector_alert_history(detectors, incidents):
    """
    Cross-reference detectors with incident history.
    Flags detectors that have never fired (silent/broken) vs. noisy (fired too often).
    Returns list of detector dicts enriched with incident_count and status.
    """
    incident_counts = defaultdict(int)
    for inc in incidents:
        did = inc.get("detectorId", "")
        if did:
            incident_counts[did] += 1

    results = []
    for d in detectors:
        did  = d.get("id", "")
        cnt  = incident_counts.get(did, 0)
        age  = days_ago(d.get("created") or d.get("lastUpdated"))
        # Only flag as "never fired" if detector is >7 days old
        if cnt == 0 and age and age > 7:
            status = "silent"
        elif cnt >= 20:
            status = "noisy"
        elif cnt > 0:
            status = "healthy"
        else:
            status = "new"
        results.append({
            "id":             did,
            "name":           d.get("name", "—"),
            "incident_count": cnt,
            "status":         status,
            "lastUpdated":    d.get("lastUpdated"),
            "owner":          d.get("lastUpdatedBy", "—"),
        })
    results.sort(key=lambda x: x["incident_count"])
    return results


def analyze_product_adoption(otel_signals, integrations, http_events, apm_services=None, dimensions_cache=None):
    """
    Determine which Splunk O11y product areas are adopted vs. not.
    Returns dict: {product: {adopted: bool, detail: str}}
    """
    products = {}

    # APM: prefer dimension API service_names, fall back to APM topology count
    dim_services  = otel_signals.get("service_names", [])
    topo_services = apm_services or []
    apm_names     = dim_services if dim_services else [s["serviceName"] for s in topo_services if not s.get("inferred")]
    apm_on        = bool(apm_names)
    products["APM / Tracing"] = {
        "adopted": apm_on,
        "detail": f"{len(apm_names)} service(s) sending traces" if apm_on else "No APM services detected",
    }

    # Infrastructure Monitoring: check for host / k8s integrations
    infra_types = {"AWS", "GCP", "Azure", "Kubernetes", "OracleCloud",
                   "HerokuApp", "Nagios", "collectd", "telegraf"}
    active_integrations = [i for i in integrations if i.get("enabled", True)]
    infra_integrations  = [i for i in active_integrations
                           if any(t.lower() in i.get("type", "").lower() for t in infra_types)
                           or i.get("type", "") in infra_types]
    products["Infrastructure Monitoring"] = {
        "adopted": len(infra_integrations) > 0,
        "detail": f"{len(infra_integrations)} infra integration(s) active" if infra_integrations
                  else "No AWS/GCP/Azure/K8s integrations configured",
    }

    # RUM: check for rum resource type in http_events or dimension keys
    rum_http = any(e.get("properties", {}).get("sf_resourceType", "").startswith("rum")
                   for e in http_events)
    products["RUM"] = {
        "adopted": rum_http,
        "detail": "RUM API activity detected" if rum_http else "No RUM activity detected",
    }

    # Log Observer: logsobserver resource type
    logs_http = any("log" in e.get("properties", {}).get("sf_resourceType", "").lower()
                    for e in http_events)
    products["Log Observer"] = {
        "adopted": logs_http,
        "detail": "Log Observer API activity detected" if logs_http else "No Log Observer activity",
    }

    # Synthetics: synthetics resource type
    synth_http = any("synthetic" in e.get("properties", {}).get("sf_resourceType", "").lower()
                     for e in http_events)
    products["Synthetics"] = {
        "adopted": synth_http,
        "detail": "Synthetics API activity detected" if synth_http else "No Synthetics activity",
    }

    # Profiling: look for profiling SDK name
    profiling_on = any("profil" in s.lower() for s in otel_signals.get("sdk_names", []))
    products["Profiling"] = {
        "adopted": profiling_on,
        "detail": "Profiling SDK detected" if profiling_on else "No profiling SDK detected",
    }

    # On-Call / Incident intelligence: check muting rules or incident integrations
    oncall_integrations = [i for i in active_integrations
                           if any(k in i.get("type", "").lower()
                                  for k in ["pagerduty", "victorops", "opsgenie", "slack",
                                            "servicenow", "webhook"])]
    products["Alerting / On-Call"] = {
        "adopted": len(oncall_integrations) > 0,
        "detail": f"{len(oncall_integrations)} notification integration(s): " +
                  ", ".join(i.get("type", "") for i in oncall_integrations[:3]) if oncall_integrations
                  else "No notification integrations configured",
    }

    return products


def analyze_integration_coverage(integrations):
    """Summarise integration types, enabled/disabled counts, and cloud coverage."""
    enabled   = [i for i in integrations if i.get("enabled", True)]
    disabled  = [i for i in integrations if not i.get("enabled", True)]
    by_type   = defaultdict(list)
    for i in enabled:
        by_type[i.get("type", "unknown")].append(i.get("name", "") or i.get("id", ""))
    disabled_list = [
        {"name": i.get("name", "") or i.get("id", ""), "type": i.get("type", "unknown")}
        for i in disabled
    ]
    return {
        "total":         len(integrations),
        "enabled":       len(enabled),
        "disabled":      len(disabled),
        "by_type":       dict(sorted(by_type.items())),
        "disabled_list": disabled_list,
    }


def analyze_org_capacity(org_data):
    """
    Extract limit vs. usage percentages from org data.
    Returns list of {metric, used, limit, pct} dicts for display.
    """
    # Fields vary by org plan; try known keys
    LIMIT_PAIRS = [
        ("numHosts",                  "numHostsLimit",              "Hosts"),
        ("numContainers",             "numContainersLimit",         "Containers"),
        ("numCustomMetricTimeSeries", "numCustomMTSLimit",          "Custom MTS"),
        ("numDetectors",              "numDetectorsLimit",          "Detectors"),
        ("numActiveAlertingDetectors","numActiveAlertingDetectorsLimit","Active Detectors"),
    ]
    results = []
    for used_key, limit_key, label in LIMIT_PAIRS:
        used  = org_data.get(used_key)
        limit = org_data.get(limit_key)
        if used is not None and limit and limit > 0:
            pct = round(used / limit * 100, 1)
            results.append({"metric": label, "used": used, "limit": limit, "pct": pct})
    return results


def analyze_dashboard_complexity(dashboards, chart_counts):
    """
    Classify dashboards by complexity based on chart count.
    Returns {empty, simple, moderate, rich, complex} buckets + per-dashboard list.
    """
    buckets = {"empty": [], "simple": [], "moderate": [], "rich": [], "complex": []}
    for d in dashboards:
        did = d.get("id", "")
        cnt = chart_counts.get(did)
        if cnt is None:
            continue  # not fetched
        name = d.get("name", "—")
        entry = {"id": did, "name": name, "chart_count": cnt,
                 "lastUpdated": d.get("lastUpdated")}
        if cnt == 0:
            buckets["empty"].append(entry)
        elif cnt <= 3:
            buckets["simple"].append(entry)
        elif cnt <= 8:
            buckets["moderate"].append(entry)
        elif cnt <= 20:
            buckets["rich"].append(entry)
        else:
            buckets["complex"].append(entry)
    return buckets


def analyze_token_scope_hygiene(tokens, users):
    """
    Flag tokens with broad API scope being used programmatically.
    Specifically: tokens with full API scope attributed to automation (high api_pct).
    """
    # Map email -> api_pct
    email_api_pct = {u["email"]: u.get("api_pct") for u in users}
    issues = []
    for t in tokens:
        scopes = t.get("authScopes", [])
        if "API" in scopes or not scopes:  # no scopes = full API
            name = t.get("name", "")
            # flag if token has been used (via any user with high api%)
            issues.append({
                "name":       name,
                "id":         t.get("id", ""),
                "scopes":     ", ".join(scopes) if scopes else "full (no restriction)",
                "expiry":     t.get("expiry"),
                "risk":       "high" if not scopes else "medium",
            })
    return sorted(issues, key=lambda x: x["risk"])


def analyze_detector_service_coverage(detectors, apm_services, members):
    """
    Identify APM services with no detectors covering them.
    Heuristic: parse detector names / programs for service name mentions.
    """
    id_to_email = {m["userId"]: m["email"] for m in members}
    apm_svc_names = {s["serviceName"].lower() for s in apm_services}

    covered = set()
    for d in detectors:
        name = d.get("name", "").lower()
        prog = str(d.get("programOptions", "")).lower()
        for svc in apm_svc_names:
            if svc in name or svc in prog:
                covered.add(svc)

    uncovered = sorted(apm_svc_names - covered)
    return {
        "covered":   sorted(covered),
        "uncovered": uncovered,
        "total":     len(apm_svc_names),
    }


def analyze_ingestion_trend(signalflow_results):
    """
    Convert raw SignalFlow results into a clean monthly trend list.
    Returns list of {month, value} dicts.
    """
    if not signalflow_results:
        return []
    by_month = defaultdict(float)
    for ts_ms, val in signalflow_results:
        month = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc).strftime("%Y-%m")
        by_month[month] = max(by_month[month], val or 0)
    return [{"month": m, "value": v} for m, v in sorted(by_month.items())]


def analyze_incident_mtta(incidents_enriched, members):
    """
    #3 — Mean time to acknowledge per user + org-wide alert fatigue index.
    Returns:
      - per_user: {email: {acked, total, avg_mtta_min}}
      - org_fatigue: {total_incidents, days, alerts_per_user_per_day}
      - unacked_pct: % of incidents never acknowledged
    """
    id_to_email = {m["userId"]: m["email"] for m in members}
    per_user    = defaultdict(lambda: {"acked": 0, "total": 0, "mtta_mins": []})

    for inc in incidents_enriched:
        acker = id_to_email.get(inc.get("acknowledgedBy", ""), inc.get("acknowledgedBy", ""))
        if acker:
            per_user[acker]["total"] += 1
            if inc["acknowledged"]:
                per_user[acker]["acked"] += 1
                if inc["mtta_min"] is not None:
                    per_user[acker]["mtta_mins"].append(inc["mtta_min"])

    results = []
    for email, d in per_user.items():
        avg_mtta = round(sum(d["mtta_mins"]) / len(d["mtta_mins"]), 1) if d["mtta_mins"] else None
        results.append({"email": email, "acked": d["acked"], "total": d["total"],
                        "avg_mtta_min": avg_mtta})
    results.sort(key=lambda x: (x["avg_mtta_min"] or 9999))

    total  = len(incidents_enriched)
    acked  = sum(1 for i in incidents_enriched if i["acknowledged"])
    unacked_pct = round((total - acked) / total * 100) if total else 0
    return {"per_user": results, "total_incidents": total,
            "unacked_pct": unacked_pct, "acked": acked}


def analyze_alert_fatigue(incidents_enriched, users, days):
    """
    #16 — Org-wide alert fatigue index: incidents per user per day.
    Also computes detector signal/noise ratio (#5).
    """
    n_users = max(len([u for u in users if u["active"]]), 1)
    total   = len(incidents_enriched)
    alerts_per_user_per_day = round(total / n_users / max(days, 1), 2)

    # Detector S/N ratio: short-lived incidents (auto-resolved <5min) = noise
    det_stats = defaultdict(lambda: {"total": 0, "noise": 0, "name": ""})
    for inc in incidents_enriched:
        did  = inc["detectorId"]
        det_stats[did]["total"] += 1
        det_stats[did]["name"]   = inc.get("detectorName", did)
        dur  = inc.get("duration_min")
        if dur is not None and dur < 5:
            det_stats[did]["noise"] += 1

    det_quality = []
    for did, s in det_stats.items():
        if s["total"] == 0:
            continue
        noise_pct = round(s["noise"] / s["total"] * 100)
        det_quality.append({
            "detector_id": did, "name": s["name"],
            "total": s["total"], "noise": s["noise"],
            "noise_pct": noise_pct,
            "quality": "noisy" if noise_pct >= 50 else "ok",
        })
    det_quality.sort(key=lambda x: -x["noise_pct"])

    return {
        "alerts_per_user_per_day": alerts_per_user_per_day,
        "total_incidents": total,
        "benchmark_ok": alerts_per_user_per_day <= 5,
        "detector_quality": det_quality,
    }


def analyze_detector_notification_routing(detectors):
    """
    #8 — Break down detector notifications by channel type.
    Returns {channel_type: count} + per-detector routing detail.
    """
    channel_counts = defaultdict(int)
    routing_detail = []

    CHANNEL_MAP = {
        "Email":      "email",
        "Slack":      "slack",
        "PagerDuty":  "pagerduty",
        "VictorOps":  "victorops",
        "OpsGenie":   "opsgenie",
        "Webhook":    "webhook",
        "ServiceNow": "servicenow",
        "BigPanda":   "bigpanda",
        "Jira":       "jira",
        "MSTeams":    "msteams",
    }

    for d in detectors:
        notifs = d.get("notifications", []) or []
        channels = set()
        for n in notifs:
            ntype = n.get("type", "")
            mapped = next((v for k, v in CHANNEL_MAP.items()
                           if k.lower() in ntype.lower()), "other")
            channels.add(mapped)
            channel_counts[mapped] += 1
        routing_detail.append({
            "name":     d.get("name", ""),
            "id":       d.get("id", ""),
            "channels": sorted(channels),
            "has_notif": bool(channels),
        })

    return {
        "channel_counts": dict(sorted(channel_counts.items(), key=lambda x: -x[1])),
        "routing_detail": routing_detail,
        "email_only":     [r for r in routing_detail if r["channels"] == ["email"]],
        "no_routing":     [r for r in routing_detail if not r["has_notif"]],
    }


def analyze_alert_routing_by_service(detectors, apm_services, members):
    """
    #12 — For each APM service: does it have a detector AND does that detector
    have notifications configured?
    """
    id_to_email = {m["userId"]: m["email"] for m in members}
    apm_svc_names = {s["serviceName"].lower() for s in apm_services}

    svc_status = {svc: {"detector": False, "notified": False} for svc in apm_svc_names}

    for d in detectors:
        name  = d.get("name", "").lower()
        prog  = str(d.get("programOptions", "")).lower()
        has_n = bool(d.get("notifications"))
        for svc in apm_svc_names:
            if svc in name or svc in prog:
                svc_status[svc]["detector"] = True
                if has_n:
                    svc_status[svc]["notified"] = True

    results = []
    for svc, status in sorted(svc_status.items()):
        if status["detector"] and status["notified"]:
            tier = "covered"
        elif status["detector"]:
            tier = "detector-only"
        else:
            tier = "uncovered"
        results.append({"service": svc, "tier": tier,
                         "detector": status["detector"], "notified": status["notified"]})
    return results


def analyze_data_volume_by_product(signalflow_results_map):
    """
    #9 — Break ingestion volume by telemetry type using per-product SignalFlow results.
    signalflow_results_map: {product_label: [(ts_ms, value), ...]}
    Returns list of {product, total, pct} sorted by volume.
    """
    totals = {}
    for product, pts in signalflow_results_map.items():
        if pts:
            totals[product] = sum(v for _, v in pts if v)
    grand = sum(totals.values()) or 1
    return sorted(
        [{"product": p, "total": v, "pct": round(v / grand * 100, 1)}
         for p, v in totals.items()],
        key=lambda x: -x["total"]
    )


def analyze_inactive_admin_risk(users, tokens):
    """
    #20 — Inactive admins who still have active (non-expired) tokens = highest risk.
    """
    now_s = time.time()
    active_token_names = {
        t["name"] for t in tokens
        if not (t.get("expiry") and t["expiry"] / 1000 < now_s)
    }
    risks = []
    for u in users:
        if not u["admin"] or u["active"]:
            continue
        # inactive admin — check if they have tokens
        # We can't directly map user->token without attribution data,
        # so flag all inactive admins + report total active tokens as org-level risk
        days_inactive = days_ago(u["last_activity"]) if u["last_activity"] else None
        risks.append({
            "email":         u["email"],
            "member_since":  u["member_since"],
            "days_inactive": days_inactive,
            "last_activity": u["last_activity"],
        })
    return {
        "inactive_admins":     risks,
        "active_token_count":  len(active_token_names),
        "risk_level":          "high" if risks else "low",
    }


def analyze_token_rotation(tokens):
    """
    #18 — Flag tokens older than 1 year with no rotation (no recent update).
    Token 'created' field gives age; no 'lastRotated' field exists so we use age alone.
    """
    now_s  = time.time()
    issues = []
    for t in tokens:
        created = t.get("created")
        if not created:
            continue
        age_days = round((now_s - created / 1000) / 86400)
        if age_days > 365:
            exp = t.get("expiry")
            expired = bool(exp and exp / 1000 < now_s)
            issues.append({
                "name":     t.get("name", ""),
                "age_days": age_days,
                "scopes":   ", ".join(t.get("authScopes", [])) or "full",
                "expired":  expired,
            })
    issues.sort(key=lambda x: -x["age_days"])
    return issues


def analyze_signalflow_usage(http_events, members):
    """
    #1/#2 — Who runs SignalFlow queries? Classify program complexity.
    Also captures search/filter behavior (dimension/MTS lookups).
    """
    id_to_email = {m["userId"]: m["email"] for m in members}
    sf_by_email     = defaultdict(int)
    search_by_email = defaultdict(int)

    SEARCH_RESOURCES = {"metrictimeseries", "dimension", "metric", "event"}

    for e in http_events:
        props  = e.get("properties", {})
        email  = props.get("sf_email", "")
        uri    = props.get("sf_requestUri", "")
        rtype  = props.get("sf_resourceType", "")
        method = props.get("sf_requestMethod", "")
        if not email:
            continue
        if "signalflow" in uri.lower():
            sf_by_email[email] += 1
        if rtype.lower() in SEARCH_RESOURCES and method == "GET":
            search_by_email[email] += 1

    results = []
    all_emails = set(list(sf_by_email.keys()) + list(search_by_email.keys()))
    for email in all_emails:
        results.append({
            "email":        email,
            "signalflow":   sf_by_email[email],
            "data_searches": search_by_email[email],
        })
    results.sort(key=lambda x: -(x["signalflow"] + x["data_searches"]))
    return results


def analyze_dashboard_sharing(http_events, dashboards, members):
    """
    #4 — Dashboard group creation events = publishing behavior.
    Also estimates read frequency per dashboard from GET events.
    """
    group_creates_by_email = defaultdict(int)
    dash_reads = defaultdict(int)

    for e in http_events:
        props  = e.get("properties", {})
        email  = props.get("sf_email", "")
        uri    = props.get("sf_requestUri", "")
        method = props.get("sf_requestMethod", "")
        rtype  = props.get("sf_resourceType", "")
        if not email:
            continue
        if "dashboardgroup" in uri.lower() and method == "POST":
            group_creates_by_email[email] += 1
        if rtype == "dashboard" and method == "GET":
            # extract dashboard ID from URI /v2/dashboard/{id}
            parts = uri.rstrip("/").split("/")
            if len(parts) >= 4:
                dash_reads[parts[-1]] += 1

    # Top read dashboards
    id_to_name = {d.get("id", ""): d.get("name", "") for d in dashboards}
    top_read = sorted(
        [{"id": did, "name": id_to_name.get(did, did), "reads": cnt}
         for did, cnt in dash_reads.items()],
        key=lambda x: -x["reads"]
    )[:20]

    publishers = [{"email": e, "group_creates": c}
                  for e, c in sorted(group_creates_by_email.items(), key=lambda x: -x[1])]
    return {"publishers": publishers, "top_read_dashboards": top_read,
            "total_dash_reads": sum(dash_reads.values())}


def analyze_detector_creation_velocity(detectors):
    """
    #15 — Timeline of detector creation by month.
    Shows whether monitoring is growing, flat, or was one-time.
    """
    by_month = defaultdict(int)
    for d in detectors:
        created = d.get("created")
        if created:
            month = datetime.fromtimestamp(created / 1000, tz=timezone.utc).strftime("%Y-%m")
            by_month[month] += 1
    return [{"month": m, "count": c} for m, c in sorted(by_month.items())]


def analyze_new_vs_returning(users, days):
    """
    #14 — Split users into new (<30d tenure) vs. established, show activity patterns.
    """
    now_ms   = int(time.time() * 1000)
    new_users = []
    est_users = []
    for u in users:
        ms = u.get("member_since")
        if ms and (now_ms - ms) < 30 * 86400 * 1000:
            new_users.append(u)
        else:
            est_users.append(u)

    def cohort_stats(group):
        if not group:
            return {"count": 0, "active": 0, "avg_score": 0, "avg_logins": 0}
        active = sum(1 for u in group if u["active"])
        return {
            "count":      len(group),
            "active":     active,
            "retention":  round(active / len(group) * 100),
            "avg_score":  round(sum(u.get("engagement_score", 0) for u in group) / len(group)),
            "avg_logins": round(sum(u["login_count"] for u in group) / len(group), 1),
        }

    return {"new": cohort_stats(new_users), "established": cohort_stats(est_users),
            "new_users": new_users, "established_users": est_users}


def analyze_privilege_escalation(members, http_events):
    """
    #17 — Detect recently granted admin: admin members with recent PATCH/PUT
    on /v2/organization/member events, or admin members joined recently.
    """
    now_ms   = int(time.time() * 1000)
    window   = 30 * 86400 * 1000  # 30 days

    # Members who are admin AND joined/were modified in last 30d
    recently_elevated = []
    for m in members:
        if not m.get("admin"):
            continue
        created = m.get("created", 0)
        if now_ms - created < window:
            recently_elevated.append({
                "email":        m["email"],
                "joined":       created,
                "days_ago":     round((now_ms - created) / (86400 * 1000)),
                "source":       "new admin account",
            })

    # Also scan HTTP events for org member PUT/PATCH (role changes)
    role_changes = []
    for e in http_events:
        props  = e.get("properties", {})
        uri    = props.get("sf_requestUri", "")
        method = props.get("sf_requestMethod", "")
        actor  = props.get("sf_email", "")
        if method in ("PUT", "PATCH") and "organization/member" in uri:
            role_changes.append({
                "actor": actor,
                "uri":   uri,
                "ts":    e.get("timestamp", 0),
            })

    return {"recently_elevated": recently_elevated, "role_changes": role_changes}


def analyze_slo_detectors(detectors):
    """
    #11 — Identify detectors using SLO/burn-rate patterns in their programs.
    Heuristic: look for 'error_ratio', 'burn_rate', 'slo', 'budget' in name/program.
    """
    SLO_KEYWORDS = ["error_ratio", "burn_rate", "slo", "error budget", "error rate",
                    "availability", "latency_p99", "apdex"]
    slo_dets = []
    generic_dets = []
    for d in detectors:
        name = d.get("name", "").lower()
        prog = str(d.get("programOptions", {})).lower()
        text = name + " " + prog
        if any(kw in text for kw in SLO_KEYWORDS):
            slo_dets.append({"name": d.get("name", ""), "id": d.get("id", "")})
        else:
            generic_dets.append(d.get("name", ""))
    return {
        "slo_count":     len(slo_dets),
        "generic_count": len(generic_dets),
        "slo_detectors": slo_dets,
        "maturity":      "SRE-mature" if len(slo_dets) >= 3 else
                         "developing" if len(slo_dets) >= 1 else "basic",
    }


def analyze_instrumentation_completeness(apm_services, otel_signals, integrations, http_events):
    """
    #13 — Score each APM service on traces + metrics + logs coverage.
    traces: present in APM topology
    metrics: infer from OTel SDK presence
    logs: check for log observer activity
    """
    has_logs    = any("log" in e.get("properties", {}).get("sf_resourceType", "").lower()
                      for e in http_events)
    has_metrics = bool(otel_signals.get("sdk_names"))
    svc_names   = [s["serviceName"] for s in apm_services if not s.get("inferred")]
    results = []
    for svc in svc_names:
        score = 1  # always has traces (it's in APM topology)
        if has_metrics:
            score += 1
        if has_logs:
            score += 1
        tier = {3: "full", 2: "partial", 1: "traces-only"}[score]
        results.append({
            "service": svc,
            "traces":  True,
            "metrics": has_metrics,
            "logs":    has_logs,
            "score":   score,
            "tier":    tier,
        })
    results.sort(key=lambda x: x["score"])
    return results


def analyze_cardinality_hotspots(top_mts):
    """
    #10 — Surface top metrics by MTS count (cardinality/cost drivers).
    """
    if not top_mts:
        return []
    total = sum(m["mts_count"] for m in top_mts) or 1
    return [
        {**m, "pct": round(m["mts_count"] / total * 100, 1)}
        for m in sorted(top_mts, key=lambda x: -x["mts_count"])
    ]


def analyze_detector_last_fired(detectors, incidents):
    """
    For each detector, find when it last fired an incident.
    Returns dict: {detector_id: last_fired_ms}
    """
    last_fired = {}
    for inc in incidents:
        did = inc.get("detectorId") or inc.get("id", "")
        ts  = inc.get("createdAt") or inc.get("timestamp", 0)
        if did and ts:
            if did not in last_fired or ts > last_fired[did]:
                last_fired[did] = ts
    result = []
    now_ms = int(time.time() * 1000)
    for d in detectors:
        did = d.get("id", "")
        lf  = last_fired.get(did)
        days_since = round((now_ms - lf) / (86400 * 1000)) if lf else None
        result.append({
            "id":          did,
            "name":        d.get("name", ""),
            "last_fired":  lf,
            "days_since":  days_since,
            "never_fired": lf is None,
        })
    result.sort(key=lambda x: (x["never_fired"], x["days_since"] or 999999))
    return result


def analyze_token_usage(tokens, http_events):
    """
    Identify tokens by activity: recently used vs. created-but-never-used.
    Uses lastUsed API field when available; falls back to session events.
    Returns: {active: [...], dormant: [...], never_used: [...]}
    """
    now_ms = int(time.time() * 1000)
    now_s  = time.time()
    thirty_days_ms = 30 * 86400 * 1000
    ninety_days_ms = 90 * 86400 * 1000

    # Build set of token IDs/names seen in session events
    seen_token_ids = set()
    for e in http_events:
        props = e.get("properties", {})
        tok_id = props.get("sf_tokenId", "")
        if tok_id:
            seen_token_ids.add(tok_id)

    active, dormant, never_used = [], [], []
    for t in tokens:
        created   = t.get("created", 0)
        exp       = t.get("expiry")
        expired   = bool(exp and exp / 1000 < now_s)
        name      = t.get("name", "")
        tok_id    = t.get("id", "")
        last_used = t.get("lastUsed")  # ms timestamp if API returns it
        age_days  = round((now_ms - created) / (86400 * 1000)) if created else None
        entry = {"name": name, "age_days": age_days, "expired": expired,
                 "scopes": ", ".join(t.get("authScopes", [])) or "full",
                 "last_used": last_used}

        if last_used:
            days_since = (now_ms - last_used) / (86400 * 1000)
            if days_since <= 30:
                active.append(entry)
            elif days_since <= 90:
                dormant.append(entry)
            else:
                dormant.append(entry)
        elif tok_id in seen_token_ids:
            active.append(entry)
        elif created and (now_ms - created) < thirty_days_ms:
            active.append(entry)  # recently created = likely in use
        elif not created or (now_ms - created) < thirty_days_ms:
            never_used.append(entry)
        else:
            dormant.append(entry)
    return {"active": active, "dormant": dormant, "never_used": never_used}


def analyze_user_funnel(users, ownership):
    """
    User journey funnel: Joined → Logged In → First Write → Asset Owner → Champion.
    Returns list of {stage, count, pct} ordered by funnel stage.
    """
    total = len(users) or 1
    # Ownership keys are resolved emails — match directly
    owner_emails = set(ownership.keys())
    joined    = len(users)
    logged_in = sum(1 for u in users if u["login_count"] > 0)
    writers   = sum(1 for u in users if u["write_ops"] > 0)
    owners    = sum(1 for u in users if u["email"] in owner_emails and
                    any(ownership[u["email"]].get(k) for k in ("detectors", "dashboards", "charts")))
    champions = sum(1 for u in users if u.get("user_tag") == "Champion")

    stages = [
        ("Joined",          joined,    100),
        ("Logged In",       logged_in, round(logged_in / total * 100)),
        ("Created Asset",   writers,   round(writers   / total * 100)),
        ("Asset Owner",     owners,    round(owners    / total * 100)),
        ("Champion",        champions, round(champions / total * 100)),
    ]
    return stages


def analyze_recommended_actions(users, assets, det_issues, tok_scope_issues,
                                  inactive_admin_risk, token_rotation, notif_routing,
                                  det_svc_coverage, instrumentation, priv_escalation,
                                  slo_detectors, alert_fatigue,
                                  role_dist=None, token_expiry_pipeline=None,
                                  det_tag_coverage=None):
    """
    Auto-generate prioritized recommended actions from report data.
    Returns list of {priority, category, action, detail} dicts.
    """
    actions = []

    def add(priority, category, action, detail=""):
        actions.append({"priority": priority, "category": category,
                        "action": action, "detail": detail})

    # Security
    if priv_escalation and priv_escalation.get("recently_elevated"):
        n = len(priv_escalation["recently_elevated"])
        add("critical", "Security",
            f"Review {n} recently-elevated admin account(s)",
            "New admin accounts granted in the last 30 days")
    if inactive_admin_risk and inactive_admin_risk.get("inactive_admins"):
        n = len(inactive_admin_risk["inactive_admins"])
        tok = inactive_admin_risk.get("active_token_count", 0)
        add("critical", "Security",
            f"Deactivate or review {n} inactive admin(s) with {tok} active token(s)",
            "Inactive admins with live credentials are a breach risk")
    if role_dist and role_dist.get("risk"):
        pct = role_dist["admin_pct"]
        add("high", "Security",
            f"Review admin-heavy org: {pct}% of users have admin role",
            "Apply principle of least privilege — downgrade non-admin users to power/usage")
    if token_expiry_pipeline and token_expiry_pipeline.get("missing_pairs"):
        mp = token_expiry_pipeline["missing_pairs"]
        add("medium", "Security",
            f"{len(mp)} token group(s) have INGEST but no API token (incomplete setup)",
            ", ".join(mp[:3]) + ("..." if len(mp) > 3 else ""))
    if token_rotation:
        expired = [t for t in token_rotation if t.get("expired")]
        old     = [t for t in token_rotation if not t.get("expired")]
        if expired:
            add("high", "Security", f"Delete {len(expired)} expired token(s)", ", ".join(t['name'] for t in expired[:3]))
        if old:
            add("high", "Security", f"Rotate {len(old)} token(s) older than 1 year", f"Oldest: {old[0]['age_days']}d")

    # Alerting
    if notif_routing:
        nr = notif_routing.get("no_routing", [])
        if nr:
            add("high", "Alerting",
                f"Add notification routing to {len(nr)} detector(s)",
                "Detectors fire silently — no one gets paged")
        eo = notif_routing.get("email_only", [])
        if eo:
            add("medium", "Alerting",
                f"Upgrade {len(eo)} email-only detector(s) to PagerDuty/Slack",
                "Email-only routing leads to missed incidents")
    if det_svc_coverage:
        uncov = det_svc_coverage.get("uncovered", [])
        if uncov:
            add("high", "Alerting",
                f"Create detectors for {len(uncov)} uncovered APM service(s)",
                ", ".join(uncov[:4]) + ("..." if len(uncov) > 4 else ""))
    if slo_detectors and slo_detectors.get("maturity") == "basic":
        add("medium", "Alerting",
            "Adopt SLO-based detectors (error budget / burn rate)",
            "Zero SLO detectors detected — monitoring is threshold-only")
    if alert_fatigue and not alert_fatigue.get("benchmark_ok"):
        apd = alert_fatigue["alerts_per_user_per_day"]
        add("medium", "Alerting",
            f"Reduce alert fatigue ({apd} alerts/user/day — benchmark ≤5)",
            "Tune noisy detectors or add deduplication")

    # Adoption
    inactive = [u for u in users if not u["active"]]
    if inactive:
        add("medium", "Adoption",
            f"Re-engage {len(inactive)} inactive user(s)",
            "No activity in the reporting window")
    churning = [u for u in users if u.get("user_tag") == "Churning"]
    if churning:
        add("medium", "Adoption",
            f"Check in with {len(churning)} churning user(s)",
            ", ".join(u['email'] for u in churning[:3]))

    # Asset hygiene
    stale_det = assets["detectors"]["stale"]
    stale_dash = assets["dashboards"]["stale"]
    if stale_det > 10:
        add("low", "Hygiene", f"Review/archive {stale_det} stale detector(s)", "Not updated in >90 days")
    if stale_dash > 20:
        add("low", "Hygiene", f"Review/archive {stale_dash} stale dashboard(s)", "Not updated in >90 days")
    if det_tag_coverage and det_tag_coverage.get("tagged_pct", 100) < 50:
        pct = det_tag_coverage["tagged_pct"]
        n   = len(det_tag_coverage.get("untagged", []))
        add("low", "Hygiene",
            f"Add tags to {n} untagged detector(s) ({pct}% coverage)",
            "Tags associate detectors with services/teams — needed for routing and filtering")

    # Instrumentation
    if instrumentation:
        traces_only = [s for s in instrumentation if s["tier"] == "traces-only"]
        if traces_only:
            add("medium", "Instrumentation",
                f"Add metrics/logs to {len(traces_only)} traces-only service(s)",
                ", ".join(s['service'] for s in traces_only[:3]))

    # Sort: critical → high → medium → low
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    actions.sort(key=lambda x: order.get(x["priority"], 9))
    return actions


def analyze_org_trends(users, assets, detectors):
    """
    Detect anomalies and trend arrows vs. prior-30d period.
    Returns list of {metric, current, prior, delta, direction, anomaly} dicts.
    """
    now_ms  = int(time.time() * 1000)
    last30  = now_ms - 30  * 86400 * 1000
    prev30  = now_ms - 60  * 86400 * 1000

    # Active users last30 vs prev30
    def active_in_window(start, end):
        return sum(1 for u in users
                   if u["last_activity"] and start <= u["last_activity"] <= end)

    active_last = active_in_window(last30, now_ms)
    active_prev = active_in_window(prev30, last30)

    # Write ops last30 vs prev30 — use full timestamp list, not truncated detail
    def writes_in_window(start, end):
        return sum(1 for u in users
                   for ts in u.get("write_ops_all_ts", [])
                   if start <= ts <= end)

    writes_last = writes_in_window(last30, now_ms)
    writes_prev = writes_in_window(prev30, last30)

    # Detectors created last30 vs prev30
    dets_last = sum(1 for d in detectors
                    if d.get("created") and last30 <= d["created"] <= now_ms)
    dets_prev = sum(1 for d in detectors
                    if d.get("created") and prev30 <= d["created"] <= last30)

    def trend_entry(metric, current, prior):
        delta = current - prior
        pct   = round(delta / prior * 100) if prior else None
        if delta > 0:
            direction = "up"
        elif delta < 0:
            direction = "down"
        else:
            direction = "flat"
        # Anomaly: >30% drop in active users or writes
        anomaly = (metric == "Active Users" and pct is not None and pct <= -30)
        return {"metric": metric, "current": current, "prior": prior,
                "delta": delta, "pct": pct, "direction": direction, "anomaly": anomaly}

    return [
        trend_entry("Active Users",        active_last, active_prev),
        trend_entry("Write Operations",    writes_last, writes_prev),
        trend_entry("New Detectors",       dets_last,   dets_prev),
    ]


def analyze_apm_dependency_graph(apm_nodes, apm_edges, baseline_path=None):
    """
    Build a minimal adjacency list suitable for HTML SVG rendering.
    If baseline_path points to a trace fingerprint baseline JSON, overlay
    fingerprint data: edge weights (occurrence counts) and per-node fingerprint counts.
    Returns {nodes: [{id, label, hub, fp_count}], edges: [{from, to, weight}],
             fingerprints: [...], baseline_env: str}
    """
    real     = [n for n in apm_nodes if not n.get("inferred")]
    inferred = [n for n in apm_nodes if n.get("inferred")]

    in_deg = defaultdict(int)
    for e in apm_edges:
        dst = e.get("toNode") or e.get("to", "")
        if dst:
            in_deg[dst] += 1

    nodes = []
    for n in real:
        svc = n.get("serviceName", "")
        nodes.append({"id": svc, "label": svc, "hub": in_deg.get(svc, 0) >= 2,
                      "inferred": False, "fp_count": 0})
    for n in inferred[:10]:
        svc = n.get("serviceName", "")
        nodes.append({"id": svc, "label": svc[:20], "hub": False, "inferred": True,
                      "fp_count": 0})

    svc_ids = {n["id"] for n in nodes}
    edge_weights = defaultdict(int)  # (src, dst) -> total occurrences
    for e in apm_edges:
        src = e.get("fromNode") or e.get("from", "")
        dst = e.get("toNode")   or e.get("to", "")
        if src in svc_ids and dst in svc_ids and src != dst:
            edge_weights[(src, dst)] = edge_weights.get((src, dst), 0)  # init

    # Load trace fingerprint baseline if provided
    fp_entries   = []
    baseline_env = None
    node_fp_counts = defaultdict(int)

    if baseline_path:
        try:
            bl = json.loads(Path(baseline_path).read_text())
            baseline_env = bl.get("environment", "")
            fps = bl.get("fingerprints", {})
            for fp in fps.values():
                svcs   = fp.get("services", [])
                occ    = fp.get("occurrences", 1)
                root   = fp.get("root_op", "")
                # Accumulate edge weights from fingerprint service sequences
                for i in range(len(svcs) - 1):
                    src, dst = svcs[i], svcs[i + 1]
                    if src != dst:
                        edge_weights[(src, dst)] += occ
                        # Ensure nodes exist for baseline services not in APM topology
                        if src not in svc_ids:
                            svc_ids.add(src)
                            nodes.append({"id": src, "label": src, "hub": False,
                                          "inferred": True, "fp_count": 0})
                        if dst not in svc_ids:
                            svc_ids.add(dst)
                            nodes.append({"id": dst, "label": dst, "hub": False,
                                          "inferred": True, "fp_count": 0})
                # Count fingerprints per service
                for svc in set(svcs):
                    node_fp_counts[svc] += 1
                fp_entries.append({
                    "hash":        fp.get("hash", ""),
                    "root_op":     root,
                    "services":    svcs,
                    "occurrences": occ,
                    "auto_promoted": fp.get("auto_promoted", False),
                    "watch_hits":  fp.get("watch_hits", 0),
                })
        except Exception:
            pass  # baseline optional — silently skip if unreadable

    # Apply fingerprint counts to nodes
    for node in nodes:
        node["fp_count"] = node_fp_counts.get(node["id"], 0)

    max_weight = max(edge_weights.values()) if edge_weights else 1
    if max_weight == 0:
        max_weight = 1
    edges = [
        {"from": src, "to": dst,
         "weight": cnt,
         "weight_pct": round(cnt / max_weight * 100)}
        for (src, dst), cnt in edge_weights.items()
        if src in svc_ids and dst in svc_ids and src != dst
    ]

    return {
        "nodes":        nodes,
        "edges":        edges,
        "fingerprints": sorted(fp_entries, key=lambda x: -x["occurrences"]),
        "baseline_env": baseline_env,
    }


def analyze_team_health(team_data, det_svc_coverage, alert_routing_svc):
    """
    Extend team rollup with a health score: active rate, asset coverage,
    and alert coverage for services the team owns.
    """
    svc_tier = {r["service"]: r["tier"] for r in (alert_routing_svc or [])}
    results = []
    for t in team_data:
        active_rate = round(t["active"] / t["member_count"] * 100) if t["member_count"] else 0
        asset_score = min(round(math.log10(t["detectors"] + t["dashboards"] + 1) / math.log10(21) * 50), 50)
        health = round(active_rate * 0.5 + asset_score)
        results.append({**t, "active_rate": active_rate, "health_score": health})
    results.sort(key=lambda x: -x["health_score"])
    return results



def analyze_detector_complexity(detectors):
    """
    #6 — Score each detector's SignalFlow program by complexity.
    Library-based detectors (autodetect/signalflow-library imports) wrap their
    logic inside the library, so raw call counts will be low — we flag these
    separately as 'library' style vs 'custom' hand-written SignalFlow.
    Returns list of {name, id, complexity, score, program_len, style} sorted desc.
    """
    import re
    results = []
    for d in detectors:
        prog = d.get("programText") or d.get("programV2") or d.get("program") or ""
        prog_lower = prog.lower()

        # Detect library-based vs custom SignalFlow
        is_library = bool(re.search(r"^from\s+signalfx\.|^import\s+signalfx\.", prog, re.MULTILINE))
        style = "library" if is_library else "custom"

        data_calls   = prog_lower.count("data(")
        filter_calls = prog_lower.count("filter(")
        detect_calls = prog_lower.count("detect(")
        fn_calls     = prog_lower.count("(")
        prog_len     = len(prog)

        score = data_calls * 3 + filter_calls * 2 + detect_calls * 2 + max(fn_calls - 5, 0)
        complexity = "high" if score >= 20 else "medium" if score >= 8 else "low"

        results.append({
            "id":           d.get("id", ""),
            "name":         d.get("name", ""),
            "data_calls":   data_calls,
            "filter_calls": filter_calls,
            "detect_calls": detect_calls,
            "score":        score,
            "complexity":   complexity,
            "prog_len":     prog_len,
            "style":        style,
        })
    results.sort(key=lambda x: (-x["score"], x["style"]))
    return results


def analyze_user_last_touched(users, detectors, dashboards):
    """
    #7 — For each user, find the most recently modified asset (any type).
    Returns dict: {email: {asset_type, asset_name, ts}}
    """
    id_to_name_det  = {d.get("id"): (d.get("name", ""), d.get("lastUpdated", 0)) for d in detectors}
    id_to_name_dash = {d.get("id"): (d.get("name", ""), d.get("lastUpdated", 0)) for d in dashboards}

    # Build: email -> most recent write op with asset name resolved
    result = {}
    for u in users:
        detail = u.get("write_ops_detail", [])
        if not detail:
            continue
        # Most recent op
        op = detail[0]
        uri  = op.get("uri", "")
        rtype = op.get("resource", "")
        ts    = op.get("ts", 0)
        # Try to resolve asset name from URI
        parts = uri.rstrip("/").split("/")
        asset_id = parts[-1] if parts else ""
        name = ""
        if "detector" in uri.lower():
            name = id_to_name_det.get(asset_id, ("", 0))[0]
            rtype = "detector"
        elif "dashboard" in uri.lower():
            name = id_to_name_dash.get(asset_id, ("", 0))[0]
            rtype = "dashboard"
        result[u["email"]] = {
            "asset_type": rtype or "api",
            "asset_name": name or asset_id[:40] or "—",
            "ts":         ts,
        }
    return result


def analyze_dashboard_groups(dashboards):
    """
    #8 — Group dashboards by their groupId, show group-level ownership.
    Returns list of {group_id, dashboard_count, latest_update, owners}
    """
    groups = defaultdict(lambda: {"dashboards": [], "owners": set()})
    for d in dashboards:
        gid = d.get("groupId", "__ungrouped__")
        groups[gid]["dashboards"].append(d)
        owner = d.get("lastUpdatedBy") or d.get("creator", "")
        if owner:
            groups[gid]["owners"].add(owner)

    result = []
    for gid, data in groups.items():
        dashes = data["dashboards"]
        latest = max((d.get("lastUpdated") or 0 for d in dashes), default=0)
        result.append({
            "group_id":        gid,
            "dashboard_count": len(dashes),
            "latest_update":   latest,
            "owners":          sorted(data["owners"]),
            "names":           [d.get("name", "") for d in sorted(dashes, key=lambda x: -(x.get("lastUpdated") or 0))[:5]],
        })
    result.sort(key=lambda x: -x["dashboard_count"])
    return result


def analyze_notification_health(integrations, detectors):
    """
    #9 — Check notification integrations for broken/missing config fields.
    Returns list of {name, type, issue} for flagged integrations.
    """
    REQUIRED_FIELDS = {
        "pagerduty":  ["sfxToken", "apiKey"],
        "slack":      ["webhookUrl", "url"],
        "victorops":  ["postUrl"],
        "opsgenie":   ["apiKey"],
        "webhook":    ["url"],
        "msteams":    ["webhookUrl", "url"],
        "servicenow": ["instanceName"],
    }
    issues = []
    for integ in integrations:
        if not integ.get("enabled", True):
            continue
        itype = integ.get("type", "").lower()
        name  = integ.get("name", "")
        for key, fields in REQUIRED_FIELDS.items():
            if key in itype:
                missing = [f for f in fields if not integ.get(f)]
                if len(missing) == len(fields):  # all required fields missing
                    issues.append({
                        "name":    name,
                        "type":    itype,
                        "issue":   f"missing config fields: {', '.join(fields)}",
                    })
                break

    # Also flag detectors routing to integrations that have issues
    issue_names = {i["name"] for i in issues}
    affected_detectors = []
    for d in detectors:
        for n in d.get("notifications", []) or []:
            if n.get("type", "") in issue_names or n.get("credentialId", "") in issue_names:
                affected_detectors.append(d.get("name", ""))
                break

    return {"broken_integrations": issues, "affected_detectors": affected_detectors}


def analyze_service_error_rates(apm_services, signalflow_fn):
    """
    #10 — Use SignalFlow to get error rates per service.
    signalflow_fn is a callable(program, days) -> [(ts, val), ...]
    Returns list of {service, error_rate_pct, has_data}
    """
    results = []
    for svc in apm_services[:10]:  # cap at 10 to avoid too many SignalFlow calls
        svc_name = svc.get("serviceName", "")
        if not svc_name or svc.get("inferred"):
            continue
        prog = (f"A = data('service.request.count',"
                f"filter=filter('sf_service','{svc_name}')&filter('sf_error','true')).sum()\n"
                f"B = data('service.request.count',"
                f"filter=filter('sf_service','{svc_name}')).sum()\n"
                f"(A/B*100).publish()")
        try:
            pts = signalflow_fn(prog, 7)
            if pts:
                avg_err = sum(v for _, v in pts if v) / len(pts)
                results.append({"service": svc_name, "error_rate_pct": round(avg_err, 2), "has_data": True})
            else:
                results.append({"service": svc_name, "error_rate_pct": None, "has_data": False})
        except Exception:
            results.append({"service": svc_name, "error_rate_pct": None, "has_data": False})
    results.sort(key=lambda x: -(x["error_rate_pct"] or -1))
    return results


def analyze_report_diff(current_users, current_detectors, current_dashboards, snapshot_dir=None):
    """
    #11 — Compare current report to the last saved snapshot.
    Returns {added_users, removed_users, new_detectors, removed_detectors, coverage_delta}
    """
    snap_dir = Path(snapshot_dir or "reports/.snapshots")
    snap_dir.mkdir(parents=True, exist_ok=True)

    current_snap = {
        "users":      sorted(u["email"] for u in current_users),
        "detectors":  sorted(d.get("id", "") for d in current_detectors),
        "dashboards": sorted(d.get("id", "") for d in current_dashboards),
        "ts":         int(time.time()),
    }

    # Find last snapshot
    snaps = sorted(snap_dir.glob("snapshot_*.json"))
    diff = None
    if snaps:
        try:
            prev = json.loads(snaps[-1].read_text())
            prev_users = set(prev.get("users", []))
            curr_users = set(current_snap["users"])
            prev_dets  = set(prev.get("detectors", []))
            curr_dets  = set(current_snap["detectors"])
            prev_dash  = set(prev.get("dashboards", []))
            curr_dash  = set(current_snap["dashboards"])
            diff = {
                "snapshot_age_days": round((current_snap["ts"] - prev.get("ts", current_snap["ts"])) / 86400, 1),
                "added_users":       sorted(curr_users - prev_users),
                "removed_users":     sorted(prev_users - curr_users),
                "new_detectors":     len(curr_dets - prev_dets),
                "removed_detectors": len(prev_dets - curr_dets),
                "new_dashboards":    len(curr_dash - prev_dash),
                "removed_dashboards":len(prev_dash - curr_dash),
            }
        except Exception:
            diff = None

    # Save current as new snapshot
    ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    (snap_dir / f"snapshot_{ts_str}.json").write_text(json.dumps(current_snap))
    # Keep only last 10 snapshots
    all_snaps = sorted(snap_dir.glob("snapshot_*.json"))
    for old in all_snaps[:-10]:
        old.unlink()

    return diff


def analyze_orphaned_assets(detectors, dashboards, charts, members):
    """
    #12 — Find assets whose lastUpdatedBy/creator is not in the current member list.
    Returns {orphaned_detectors, orphaned_dashboards, orphaned_charts}
    """
    known_ids    = {m["userId"] for m in members}
    known_emails = {m["email"] for m in members}

    def is_orphaned(asset):
        owner = asset.get("lastUpdatedBy") or asset.get("creator", "")
        if not owner:
            return True  # no owner at all = orphaned
        return owner not in known_ids and owner not in known_emails

    orph_det  = [{"name": d.get("name",""), "id": d.get("id",""),
                  "owner": d.get("lastUpdatedBy") or d.get("creator",""),
                  "lastUpdated": d.get("lastUpdated")}
                 for d in detectors if is_orphaned(d)]
    orph_dash = [{"name": d.get("name",""), "id": d.get("id",""),
                  "owner": d.get("lastUpdatedBy") or d.get("creator",""),
                  "lastUpdated": d.get("lastUpdated")}
                 for d in dashboards if is_orphaned(d)]
    orph_ch   = len([c for c in charts if is_orphaned(c)])

    return {
        "orphaned_detectors":  orph_det,
        "orphaned_dashboards": orph_dash,
        "orphaned_chart_count": orph_ch,
    }


def analyze_alert_severity_distribution(incidents):
    """
    #14 — Break incidents down by severity level.
    Returns {severity: count} dict + flags orgs with only high-severity firing.
    """
    by_severity = defaultdict(int)
    for inc in incidents:
        sev = inc.get("severity", "unknown").lower()
        by_severity[sev] += 1

    total = sum(by_severity.values()) or 1
    dist  = {k: {"count": v, "pct": round(v / total * 100)}
             for k, v in sorted(by_severity.items(), key=lambda x: -x[1])}

    # Flag if only critical/major firing (no graduated alerting)
    low_sev_count = sum(v for k, v in by_severity.items() if k in ("minor", "warning", "info"))
    high_sev_count = sum(v for k, v in by_severity.items() if k in ("critical", "major"))
    missing_gradation = high_sev_count > 0 and low_sev_count == 0

    return {"distribution": dist, "missing_gradation": missing_gradation,
            "total": total}


def analyze_onboarding_velocity(users):
    """
    #15 — Plot TTFV (time-to-first-value) by join month to track onboarding improvement.
    Returns list of {month, avg_ttfv_days, user_count} newest first.
    """
    by_month = defaultdict(list)
    for u in users:
        if u.get("ttfv_days") is not None and u.get("cohort_month"):
            by_month[u["cohort_month"]].append(u["ttfv_days"])

    result = []
    for month, vals in sorted(by_month.items()):
        result.append({
            "month":         month,
            "avg_ttfv_days": round(sum(vals) / len(vals), 1),
            "user_count":    len(vals),
        })
    return result


def analyze_role_distribution(members):
    """
    Break down org members by role (admin/power/etc.) and flag admin-heavy orgs.
    Returns {roles: {role: count}, admin_pct: float, risk: bool, members: [...]}
    """
    role_counts = defaultdict(int)
    per_member  = []
    for m in members:
        roles = [r.get("title", "unknown") for r in m.get("roles", [])]
        role  = roles[0] if roles else "unknown"
        role_counts[role] += 1
        per_member.append({"email": m["email"], "role": role,
                           "created": m.get("created"), "fullName": m.get("fullName","")})
    total     = len(members) or 1
    admin_cnt = role_counts.get("admin", 0)
    admin_pct = round(admin_cnt / total * 100)
    return {
        "roles":     dict(role_counts),
        "admin_pct": admin_pct,
        "risk":      admin_pct > 50,
        "members":   sorted(per_member, key=lambda x: x["role"]),
    }


def analyze_environment_inventory(environments, apm_nodes, apm_edges):
    """
    Classify environments as production-like vs workshop/test noise, and count
    APM services per environment from the topology nodes.
    Returns {production: [...], workshop: [...], test: [...], total: int}
    """
    import re
    _WORKSHOP_PAT = re.compile(r"workshop|weeklychallenge|test|lab|demo|dev|unknown|staging", re.I)
    _PROD_PAT     = re.compile(r"^(production|prod|live)$", re.I)

    # Build env -> service count from apm_nodes (each node has sf_environment dimension if available)
    # Since we only have node names here, use the environments list directly
    prod, workshop, other = [], [], []
    for env in environments:
        if not env or env.strip() == "":
            continue
        if _PROD_PAT.match(env):
            prod.append(env)
        elif _WORKSHOP_PAT.search(env):
            workshop.append(env)
        else:
            other.append(env)

    return {
        "production": sorted(prod),
        "workshop":   sorted(workshop),
        "other":      sorted(other),
        "total":      len(environments),
        "noise_pct":  round(len(workshop) / max(len(environments), 1) * 100),
    }


def analyze_token_expiry_pipeline(tokens):
    """
    Extended token expiry analysis: 7d / 30d / 90d / 1yr buckets,
    scope breakdown (INGEST/API/RUM), and missing-pair detection
    (INGEST without API = incomplete setup).
    Returns {expiring_90d, expiring_1yr, scope_counts, missing_pairs, entries}
    """
    now_ms  = int(time.time() * 1000)
    ms_90d  = 90  * 86400 * 1000
    ms_1yr  = 365 * 86400 * 1000

    scope_counts  = defaultdict(int)
    expiring_90d  = []
    expiring_1yr  = []
    name_scopes   = defaultdict(set)  # base_name -> set of scopes

    for t in tokens:
        if t.get("disabled"):
            continue
        scopes = t.get("authScopes", [])
        for s in scopes:
            scope_counts[s] += 1
        expiry = t.get("expiry")
        days_left = int((expiry - now_ms) / (86400*1000)) if expiry else None

        # Group by name prefix (strip trailing -INGEST/-API/-RUM)
        import re
        base = re.sub(r"-(INGEST|API|RUM|ingest|api|rum)$", "", t["name"])
        for s in scopes:
            name_scopes[base].add(s)

        entry = {"name": t["name"], "scopes": ",".join(scopes), "days_left": days_left}
        if expiry and 0 < (expiry - now_ms) < ms_90d:
            expiring_90d.append(entry)
        if expiry and 0 < (expiry - now_ms) < ms_1yr:
            expiring_1yr.append(entry)

    # Find INGEST tokens whose base name has no matching API token
    missing_pairs = [base for base, scopes in name_scopes.items()
                     if "INGEST" in scopes and "API" not in scopes]

    return {
        "expiring_90d":   sorted(expiring_90d, key=lambda x: x["days_left"] or 9999),
        "expiring_1yr":   sorted(expiring_1yr, key=lambda x: x["days_left"] or 9999),
        "scope_counts":   dict(scope_counts),
        "missing_pairs":  missing_pairs,
    }


def analyze_detector_tag_coverage(detectors):
    """
    Check what % of detectors have tags, and what tags exist.
    Returns {tagged_pct, untagged: [...], tag_freq: {tag: count}}
    """
    tag_freq  = defaultdict(int)
    untagged  = []
    tagged    = []
    for d in detectors:
        tags = d.get("tags") or []
        if tags:
            tagged.append({"id": d["id"], "name": d["name"], "tags": tags})
            for t in tags:
                tag_freq[t] += 1
        else:
            untagged.append({"id": d["id"], "name": d["name"],
                             "creator": d.get("creator",""), "lastUpdated": d.get("lastUpdated")})
    total = len(detectors) or 1
    return {
        "tagged_pct": round(len(tagged) / total * 100),
        "tagged":     tagged,
        "untagged":   untagged,
        "tag_freq":   dict(sorted(tag_freq.items(), key=lambda x: -x[1])),
    }


def analyze_silent_detectors_by_creator(detectors, members):
    """
    For detectors with zero notification routing, group by creator to identify
    who to target for outreach.
    Returns list of {email, silent_count, total_count, detectors: [...]}
    """
    id_to_email = {m.get("userId", m.get("id","")): m["email"] for m in members}

    by_creator = defaultdict(lambda: {"silent": [], "all": []})
    for d in detectors:
        creator_id = d.get("creator","")
        email = id_to_email.get(creator_id, creator_id or "unknown")
        rules = d.get("rules", [])
        silent = all(not r.get("notifications") for r in rules)
        entry = {"name": d["name"], "id": d["id"], "lastUpdated": d.get("lastUpdated")}
        by_creator[email]["all"].append(entry)
        if silent:
            by_creator[email]["silent"].append(entry)

    result = []
    for email, data in by_creator.items():
        if data["silent"]:
            result.append({
                "email":        email,
                "silent_count": len(data["silent"]),
                "total_count":  len(data["all"]),
                "detectors":    data["silent"],
            })
    return sorted(result, key=lambda x: -x["silent_count"])


def analyze_asset_age_distribution(detectors, dashboards):
    """
    Bucket detectors and dashboards by asset age (created timestamp).
    Returns {detectors: {bucket: count}, dashboards: {bucket: count}}
    """
    now_ms = int(time.time() * 1000)
    buckets = ["<30d", "30–90d", "90–180d", "180d–1yr", ">1yr"]

    def bucket(created_ms):
        if not created_ms:
            return "unknown"
        age_d = (now_ms - created_ms) / (86400 * 1000)
        if age_d < 30:   return "<30d"
        if age_d < 90:   return "30–90d"
        if age_d < 180:  return "90–180d"
        if age_d < 365:  return "180d–1yr"
        return ">1yr"

    det_dist  = defaultdict(int)
    dash_dist = defaultdict(int)
    for d in detectors:
        det_dist[bucket(d.get("created"))] += 1
    for d in dashboards:
        dash_dist[bucket(d.get("created"))] += 1

    return {
        "buckets":    buckets,
        "detectors":  dict(det_dist),
        "dashboards": dict(dash_dist),
    }


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


def analyze_app_insights(apm_nodes, apm_edges, otel_signals, svc_lang_map, environments, svc_envs=None):
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
    # APM topology edges use "fromNode"/"toNode" keys
    svc_names = {n.get("serviceName") for n in real_services}
    dep_graph = []
    in_degree = defaultdict(int)   # how many services call this one
    out_degree = defaultdict(int)  # how many services this one calls

    for edge in apm_edges:
        src = edge.get("fromNode") or edge.get("from", "")
        dst = edge.get("toNode")   or edge.get("to", "")
        if src and dst and src != dst:  # skip self-loops
            dep_graph.append({"from": src, "to": dst})
            out_degree[src] += 1
            in_degree[dst] += 1

    # Hub services = highest in-degree (most depended-upon)
    hub_services = sorted(svc_names, key=lambda s: -in_degree.get(s, 0))[:5]

    # Language breakdown — org-wide from dimension API (per-service not available)
    lang_counts = defaultdict(int)
    for s in enriched_services:
        if s["language"]:
            lang_counts[s["language"]] += 1
    if not lang_counts and otel_signals.get("languages"):
        for lang in otel_signals["languages"]:
            lang_counts[lang] = 1  # present org-wide; per-service mapping unavailable

    # Environment categorization
    env_categories = {"workshop": [], "production": [], "staging": [], "dev": [], "other": []}
    for env in environments:
        if env.endswith("-workshop"):
            env_categories["workshop"].append(env)
        elif env in ("production", "prod"):
            env_categories["production"].append(env)
        elif env in ("staging", "stage"):
            env_categories["staging"].append(env)
        elif env in ("dev", "development", "local"):
            env_categories["dev"].append(env)
        else:
            env_categories["other"].append(env)

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
        "env_categories":     env_categories,
        "stack_types":        stack_types,
        "svc_envs":           svc_envs or {},
    }


def analyze_teams(teams, members, users, ownership):
    """Group user activity and asset ownership by team."""
    id_to_email = {m["userId"]: m["email"] for m in members}
    email_to_user = {u["email"]: u for u in users}

    results = []
    for team in teams:
        # API may return members as list of IDs or list of dicts with id/userId key
        raw_members = team.get("members", team.get("memberIds", []))
        member_ids = [
            m if isinstance(m, str) else m.get("id", m.get("userId", ""))
            for m in raw_members
        ]
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


def analyze_detector_health(detectors, tokens, muting_rules=None):
    """Flag detectors that are muted, have no notifications, or are disabled."""
    # Build set of detector IDs covered by active muting rules
    muted_detector_ids = set()
    if muting_rules:
        now_ms = int(time.time() * 1000)
        for rule in muting_rules:
            # Rule is active if stopTime is in the future (or absent = indefinite)
            stop = rule.get("stopTime")
            start = rule.get("startTime", 0)
            if stop and stop < now_ms:
                continue  # expired rule
            if start > now_ms:
                continue  # not started yet
            for did in rule.get("detectors", []):
                muted_detector_ids.add(did)

    issues = []
    for d in detectors:
        flags = []
        if not d.get("teams") and not d.get("notifications"):
            flags.append("no-notifications")
        if d.get("disabled"):
            flags.append("disabled")
        if d.get("muted") or d.get("id") in muted_detector_ids:
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

    # Service rows — with environments
    svc_envs_map = ai.get("svc_envs", {})
    svc_rows = ""
    for s in sorted(ai["services"], key=lambda x: x["name"]):
        envs = svc_envs_map.get(s["name"], [])
        env_badges = ""
        for env in envs:
            if env.startswith("workshop"):
                color = "#d97706"
            elif env in ("production", "prod"):
                color = "#16a34a"
            elif env in ("staging", "stage"):
                color = "#2563eb"
            elif env in ("dev", "development"):
                color = "#7c3aed"
            else:
                color = "#64748b"
            env_badges += (f'<span style="background:{color};color:#fff;padding:1px 6px;'
                           f'border-radius:8px;font-size:11px;margin:1px;display:inline-block">'
                           f'{env}</span>')
        svc_rows += (f'<tr><td>{s["name"]}</td>'
                     f'<td>{env_badges if env_badges else "—"}</td></tr>')

    # Inferred dep rows
    dep_rows = ""
    for n in sorted(ai["inferred_deps"], key=lambda x: x.get("serviceName", "")):
        dtype = n.get("type", "unknown")
        color = "#dc2626" if dtype == "database" else "#64748b"
        dep_rows += (f'<tr><td>{n.get("serviceName","?")}</td>'
                     f'<td><span style="background:{color};color:#fff;padding:1px 7px;'
                     f'border-radius:9px;font-size:11px">{dtype}</span></td></tr>')

    # Language badges (org-wide)
    lang_badges = ""
    for lang in sorted(ai["language_breakdown"].keys()):
        lang_badges += (f'<span style="background:#3b82f6;color:#fff;padding:3px 10px;'
                        f'border-radius:12px;font-size:12px;margin:2px;display:inline-block">'
                        f'{lang}</span> ')

    # Stack type badges
    stack_badges = ""
    for st in ai["stack_types"]:
        stack_badges += (f'<span style="background:#10b981;color:#fff;padding:3px 10px;'
                         f'border-radius:12px;font-size:12px;margin:2px;display:inline-block">'
                         f'{st}</span> ')

    # Environment breakdown by category
    ec = ai.get("env_categories", {})
    env_section = ""
    cat_colors = {"production": "#16a34a", "staging": "#2563eb", "dev": "#7c3aed", "other": "#64748b", "workshop": "#d97706"}
    cat_labels = {"production": "Production", "staging": "Staging", "dev": "Dev", "other": "Other", "workshop": "Workshop"}
    for cat in ["production", "staging", "dev", "other", "workshop"]:
        envs = ec.get(cat, [])
        if not envs:
            continue
        color = cat_colors[cat]
        label = cat_labels[cat]
        if cat == "workshop":
            env_section += f'<div style="margin-bottom:6px"><span style="font-size:11px;color:var(--muted);font-weight:600">{label} ({len(envs)})</span><br>'
            for e in sorted(envs)[:6]:
                env_section += (f'<span style="background:{color};color:#fff;padding:2px 8px;'
                                f'border-radius:10px;font-size:11px;margin:1px;display:inline-block">{e}</span>')
            if len(envs) > 6:
                env_section += f'<span style="font-size:11px;color:#94a3b8"> +{len(envs)-6} more</span>'
            env_section += '</div>'
        else:
            env_section += f'<div style="margin-bottom:6px"><span style="font-size:11px;color:var(--muted);font-weight:600">{label}</span><br>'
            for e in sorted(envs):
                env_section += (f'<span style="background:{color};color:#fff;padding:2px 8px;'
                                f'border-radius:10px;font-size:11px;margin:1px;display:inline-block">{e}</span>')
            env_section += '</div>'

    return f"""
  <div class="card" id="sec-app-insights" style="scroll-margin-top:52px">
    <h2>Application Insights</h2>
    <div class="stat-grid" style="margin-bottom:20px">
      <div class="stat"><div class="val">{ai['service_count']}</div><div class="lbl">Services</div></div>
      <div class="stat"><div class="val">{len(ai['inferred_deps'])}</div><div class="lbl">Inferred Deps</div></div>
      <div class="stat"><div class="val">{len(ai['dependency_graph'])}</div><div class="lbl">Service Calls</div></div>
      <div class="stat"><div class="val">{len(ai['environments'])}</div><div class="lbl">Environments</div></div>
    </div>
    {'<div style="margin-bottom:12px"><b style="font-size:12px;color:var(--muted)">STACK TYPES</b><br><div style="margin-top:4px">' + stack_badges + '</div></div>' if stack_badges else ''}
    {'<div style="margin-bottom:12px"><b style="font-size:12px;color:var(--muted)">LANGUAGES (org-wide)</b><br><div style="margin-top:4px">' + lang_badges + '</div></div>' if lang_badges else ''}
    <div style="display:flex;gap:24px;flex-wrap:wrap;margin-top:8px">
      <div style="flex:1;min-width:200px">
        <b style="font-size:12px;color:var(--muted)">ENVIRONMENTS ({len(ai['environments'])} total)</b>
        <div style="margin-top:8px">{env_section}</div>
      </div>
      {'<div style="flex:2;min-width:300px"><b style="font-size:12px;color:var(--muted)">SERVICES</b><table style="margin-top:8px"><thead><tr><th>Service</th><th>Environments</th></tr></thead><tbody>' + svc_rows + '</tbody></table></div>' if svc_rows else ''}
      {'<div style="flex:1;min-width:180px"><b style="font-size:12px;color:var(--muted)">INFERRED DEPENDENCIES</b><table style="margin-top:8px"><thead><tr><th>Name</th><th>Type</th></tr></thead><tbody>' + dep_rows + '</tbody></table></div>' if dep_rows else ''}
    </div>
  </div>"""


def _html_feature_heatmap(heatmap_data, users):
    """Render feature area usage heatmap: users × resource types."""
    if not heatmap_data or not heatmap_data["by_feature"]:
        return ""

    features = list(heatmap_data["by_feature"].keys())[:12]  # top 12 features
    # Only show users with any feature activity
    active_users = [u for u in users if u.get("feature_counts")]
    active_users = sorted(active_users, key=lambda u: -sum(u["feature_counts"].values()))[:25]

    if not active_users:
        return ""

    # Build header
    header_cells = "".join(
        f'<th style="writing-mode:vertical-rl;transform:rotate(180deg);padding:4px 6px;'
        f'font-size:10px;white-space:nowrap">{f}</th>'
        for f in features
    )

    # Color scale: 0=white, max=blue
    def cell_color(count, max_count):
        if count == 0 or max_count == 0:
            return "#f8fafc", "#94a3b8"
        intensity = min(count / max_count, 1.0)
        # blue scale: light to dark
        r = int(255 - intensity * 180)
        g = int(255 - intensity * 140)
        b = 255
        text = "#fff" if intensity > 0.5 else "#1e293b"
        return f"rgb({r},{g},{b})", text

    max_count = max(
        (u["feature_counts"].get(f, 0) for u in active_users for f in features),
        default=1
    )

    rows = ""
    for u in active_users:
        fc = u["feature_counts"]
        cells = ""
        for f in features:
            cnt = fc.get(f, 0)
            bg, fg = cell_color(cnt, max_count)
            title = f"{f}: {cnt}"
            cells += (f'<td title="{title}" style="text-align:center;background:{bg};'
                      f'color:{fg};font-size:11px;padding:4px 6px">'
                      f'{"" if cnt == 0 else cnt}</td>')
        email_short = u["email"].split("@")[0]
        rows += f'<tr><td style="font-size:11px;white-space:nowrap;padding:4px 8px">{email_short}</td>{cells}</tr>'

    # Unused features
    unused = heatmap_data.get("unused_features", [])
    unused_html = ""
    if unused:
        badges = "".join(
            f'<span style="background:var(--hover);color:#94a3b8;padding:2px 8px;'
            f'border-radius:8px;font-size:11px;margin:2px;display:inline-block">{f}</span>'
            for f in unused
        )
        unused_html = f'<div style="margin-top:16px"><b style="font-size:12px;color:var(--muted)">ZERO ACTIVITY (potential unused features):</b><div style="margin-top:6px">{badges}</div></div>'

    return f"""
  <div class="card">
    <h2>Feature Area Usage Heatmap</h2>
    <p style="font-size:12px;color:var(--muted);margin-bottom:12px">API resource types accessed per user — deeper blue = higher usage count</p>
    <div style="overflow-x:auto">
      <table style="font-size:12px">
        <thead><tr><th>User</th>{header_cells}</tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
    {unused_html}
  </div>"""


def _html_cohort_table(cohort_data):
    """Render cohort retention table."""
    if not cohort_data:
        return ""
    rows = ""
    for c in cohort_data:
        pct = c["retention_pct"]
        color = "#22c55e" if pct >= 70 else "#eab308" if pct >= 40 else "#ef4444"
        bar_w = pct
        rows += f"""
        <tr>
          <td>{c['month']}</td>
          <td style="text-align:center">{c['size']}</td>
          <td style="text-align:center">{c['active']}</td>
          <td>
            <div style="display:flex;align-items:center;gap:8px">
              <div style="background:#e2e8f0;border-radius:3px;height:8px;width:100px;display:inline-block">
                <div style="background:{color};width:{bar_w}%;height:100%;border-radius:3px"></div>
              </div>
              <span style="font-weight:700;color:{color}">{pct}%</span>
            </div>
          </td>
        </tr>"""
    return f"""
  <div class="card">
    <h2>User Cohort Retention</h2>
    <p style="font-size:12px;color:var(--muted);margin-bottom:12px">Users grouped by join month — retention = active in reporting window</p>
    <table>
      <thead><tr><th>Cohort (Join Month)</th><th style="text-align:center">Size</th><th style="text-align:center">Still Active</th><th>Retention</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>"""


def _html_session_duration(users):
    """Render session duration distribution."""
    users_with_dur = [(u["email"], u["avg_session_min"])
                      for u in users if u.get("avg_session_min") is not None]
    if not users_with_dur:
        return ""
    users_with_dur.sort(key=lambda x: -x[1])
    max_dur = users_with_dur[0][1] if users_with_dur else 1
    rows = ""
    for email, avg_min in users_with_dur:
        w = min(round(avg_min / max(max_dur, 1) * 200), 200)
        if avg_min >= 60:
            dur_str = f"{avg_min/60:.1f}h"
            color = "#8b5cf6"
        elif avg_min >= 20:
            dur_str = f"{avg_min:.0f}m"
            color = "#3b82f6"
        else:
            dur_str = f"{avg_min:.0f}m"
            color = "#94a3b8"
        rows += f"""
        <tr>
          <td style="font-size:12px">{email}</td>
          <td>
            <div style="display:flex;align-items:center;gap:8px">
              <div style="background:#e2e8f0;border-radius:3px;height:8px;width:{w}px;display:inline-block">
                <div style="background:{color};width:100%;height:100%;border-radius:3px"></div>
              </div>
              <span style="font-size:12px;color:{color};font-weight:600">{dur_str}</span>
            </div>
          </td>
        </tr>"""
    return f"""
  <div class="card">
    <h2>Avg Session Duration</h2>
    <p style="font-size:12px;color:var(--muted);margin-bottom:12px">Computed from session created/deleted event pairs</p>
    <table>{rows}</table>
  </div>"""


def _html_api_vs_ui(users):
    """Render API vs UI usage split per user."""
    users_with_data = [u for u in users
                       if u.get("api_call_count", 0) + u.get("ui_action_count", 0) > 0]
    if not users_with_data:
        return ""
    users_with_data.sort(key=lambda u: -(u.get("api_call_count", 0) + u.get("ui_action_count", 0)))
    rows = ""
    for u in users_with_data[:20]:
        api_c = u.get("api_call_count", 0)
        ui_c  = u.get("ui_action_count", 0)
        total = api_c + ui_c
        if total == 0:
            continue
        api_pct = round(api_c / total * 100)
        ui_pct  = 100 - api_pct
        rows += f"""
        <tr>
          <td style="font-size:12px">{u['email']}</td>
          <td style="text-align:center">{total}</td>
          <td>
            <div style="display:flex;height:14px;border-radius:4px;overflow:hidden;width:200px">
              <div style="background:#3b82f6;width:{ui_pct}%" title="UI: {ui_c}"></div>
              <div style="background:#f59e0b;width:{api_pct}%" title="API: {api_c}"></div>
            </div>
            <div style="font-size:10px;color:var(--muted);margin-top:2px">
              <span style="color:#3b82f6">■ UI {ui_pct}%</span>
              &nbsp;<span style="color:#f59e0b">■ API {api_pct}%</span>
            </div>
          </td>
        </tr>"""
    return f"""
  <div class="card">
    <h2>API vs UI Activity Split</h2>
    <p style="font-size:12px;color:var(--muted);margin-bottom:12px">Based on User-Agent in HttpRequest events — blue=UI, amber=programmatic API</p>
    <table>
      <thead><tr><th>User</th><th style="text-align:center">Total Requests</th><th>Split</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>"""


def _html_muting_activity(muting_data):
    """Render alert muting activity (fatigue signal)."""
    if not muting_data or not muting_data["writers"]:
        return ""
    writers = muting_data["writers"]
    rows = ""
    for w in writers:
        color = "#ef4444" if w["mute_writes"] >= 5 else "#f97316" if w["mute_writes"] >= 2 else "#eab308"
        rows += f"""
        <tr>
          <td>{w['email']}</td>
          <td style="text-align:center;font-weight:700;color:{color}">{w['mute_writes']}</td>
        </tr>"""
    active = muting_data.get("active_rules", 0)
    return f"""
  <div class="card">
    <h2>Alert Muting Activity <span style="font-size:12px;color:var(--muted);font-weight:400">— potential alert fatigue signal</span></h2>
    <div class="stat-grid" style="margin-bottom:16px">
      <div class="stat"><div class="val" style="color:#f97316">{active}</div><div class="lbl">Active Muting Rules</div></div>
      <div class="stat"><div class="val">{len(writers)}</div><div class="lbl">Users Creating Mutes</div></div>
    </div>
    <table>
      <thead><tr><th>User</th><th style="text-align:center">Muting Rule Writes</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>"""


def _html_collaboration(collab_data):
    """Render cross-user collaboration (multi-editor assets)."""
    if not collab_data or not collab_data["multi_editor_assets"]:
        return ""
    assets = collab_data["multi_editor_assets"]
    rows = ""
    type_colors = {"detector": "#8b5cf6", "dashboard": "#3b82f6", "chart": "#10b981"}
    for a in assets:
        color = type_colors.get(a["type"], "#64748b")
        rows += f"""
        <tr>
          <td><span style="background:{color};color:#fff;padding:1px 7px;border-radius:8px;font-size:11px">{a['type']}</span></td>
          <td style="font-size:12px">{a['name']}</td>
          <td style="font-size:12px">{a['creator']}</td>
          <td style="font-size:12px">{a['last_modified_by']}</td>
        </tr>"""
    return f"""
  <div class="card">
    <h2>Cross-User Collaboration <span style="font-size:12px;color:var(--muted);font-weight:400">— assets edited by multiple users</span></h2>
    <p style="font-size:12px;color:var(--muted);margin-bottom:12px">{len(assets)} asset(s) modified by a different user than the creator</p>
    <table>
      <thead><tr><th>Type</th><th>Asset Name</th><th>Created By</th><th>Last Modified By</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>"""


def _html_activity_trend(users):
    """Render org-wide monthly activity trend."""
    combined = defaultdict(int)
    for u in users:
        for month, cnt in u.get("activity_by_month", {}).items():
            combined[month] += cnt
    if not combined:
        return ""
    months = sorted(combined.keys())[-12:]  # last 12 months
    values = [combined[m] for m in months]
    max_v  = max(values) if values else 1
    bar_height = 60
    bars = ""
    for m, v in zip(months, values):
        h = max(2, round(v / max_v * bar_height))
        month_label = m[5:]  # MM
        bars += (f'<div style="display:flex;flex-direction:column;align-items:center;gap:2px">'
                 f'<span style="font-size:9px;color:var(--muted)">{v}</span>'
                 f'<div style="background:#3b82f6;width:24px;height:{h}px;border-radius:3px 3px 0 0" title="{m}: {v}"></div>'
                 f'<span style="font-size:9px;color:#94a3b8">{month_label}</span>'
                 f'</div>')
    return f"""
  <div class="card">
    <h2>Org-Wide Activity Trend <span style="font-size:12px;color:var(--muted);font-weight:400">— combined logins + API events by month</span></h2>
    <div style="display:flex;align-items:flex-end;gap:6px;padding:8px 0">{bars}</div>
  </div>"""


def _html_product_adoption(products):
    if not products:
        return ""
    rows = ""
    for name, info in products.items():
        icon  = "✓" if info["adopted"] else "✗"
        color = "#22c55e" if info["adopted"] else "#ef4444"
        rows += f"""
        <tr>
          <td style="font-weight:600">{name}</td>
          <td style="text-align:center">
            <span style="color:{color};font-size:16px;font-weight:700">{icon}</span>
          </td>
          <td style="font-size:12px;color:var(--muted)">{info['detail']}</td>
        </tr>"""
    adopted = sum(1 for i in products.values() if i["adopted"])
    total   = len(products)
    pct     = round(adopted / total * 100) if total else 0
    color   = "#22c55e" if pct >= 70 else "#eab308" if pct >= 40 else "#ef4444"
    return f"""
  <div class="card">
    <h2>Product Adoption Coverage</h2>
    <div style="margin-bottom:16px;display:flex;align-items:center;gap:16px">
      <span style="font-size:28px;font-weight:800;color:{color}">{adopted}/{total}</span>
      <div style="flex:1;background:#e2e8f0;border-radius:4px;height:10px">
        <div style="background:{color};width:{pct}%;height:100%;border-radius:4px"></div>
      </div>
      <span style="color:{color};font-weight:700">{pct}% adopted</span>
    </div>
    <table>
      <thead><tr><th>Product</th><th style="text-align:center">Status</th><th>Detail</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>"""


def _html_integration_coverage(integ_data):
    if not integ_data or integ_data["total"] == 0:
        return ""

    enabled_rows = ""
    for itype, names in sorted(integ_data["by_type"].items()):
        enabled_rows += f"""
        <tr>
          <td style="font-size:12px">{itype}</td>
          <td style="font-size:12px;color:var(--muted)">{', '.join(names[:5])}{'...' if len(names) > 5 else ''}</td>
          <td style="text-align:center">{len(names)}</td>
        </tr>"""

    disabled_rows = ""
    for d in integ_data.get("disabled_list", []):
        disabled_rows += f"""
        <tr>
          <td style="font-size:12px;color:#94a3b8">{d['type']}</td>
          <td style="font-size:12px;color:#94a3b8">{d['name']}</td>
          <td style="text-align:center">
            <span style="background:#94a3b8;color:#fff;padding:1px 7px;border-radius:8px;font-size:11px">disabled</span>
          </td>
        </tr>"""

    all_rows = enabled_rows + disabled_rows
    empty_msg = '<tr><td colspan="3" style="color:#94a3b8;font-size:12px;text-align:center">No integrations configured</td></tr>' if not all_rows else ""

    return f"""
  <div class="card">
    <h2>Integration Coverage</h2>
    <div class="stat-grid" style="margin-bottom:16px">
      <div class="stat"><div class="val">{integ_data['total']}</div><div class="lbl">Total</div></div>
      <div class="stat"><div class="val" style="color:#22c55e">{integ_data['enabled']}</div><div class="lbl">Enabled</div></div>
      <div class="stat"><div class="val" style="color:#94a3b8">{integ_data['disabled']}</div><div class="lbl">Disabled</div></div>
    </div>
    <table>
      <thead><tr><th>Type</th><th>Name</th><th style="text-align:center">Status</th></tr></thead>
      <tbody>{all_rows}{empty_msg}</tbody>
    </table>
  </div>"""


def _html_org_capacity(capacity):
    if not capacity:
        return ""
    rows = ""
    for c in capacity:
        pct   = c["pct"]
        color = "#22c55e" if pct < 70 else "#eab308" if pct < 90 else "#ef4444"
        rows += f"""
        <tr>
          <td>{c['metric']}</td>
          <td style="text-align:right">{c['used']:,}</td>
          <td style="text-align:right">{c['limit']:,}</td>
          <td>
            <div style="display:flex;align-items:center;gap:8px">
              <div style="background:#e2e8f0;border-radius:3px;height:8px;width:120px">
                <div style="background:{color};width:{min(pct,100)}%;height:100%;border-radius:3px"></div>
              </div>
              <span style="font-size:12px;font-weight:700;color:{color}">{pct}%</span>
            </div>
          </td>
        </tr>"""
    return f"""
  <div class="card">
    <h2>Org Capacity & Limits</h2>
    <table>
      <thead><tr><th>Metric</th><th style="text-align:right">Used</th><th style="text-align:right">Limit</th><th>Usage</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>"""


def _html_detector_alert_history(det_history):
    if not det_history:
        return ""
    silent  = [d for d in det_history if d["status"] == "silent"]
    noisy   = [d for d in det_history if d["status"] == "noisy"]
    healthy = [d for d in det_history if d["status"] == "healthy"]

    def status_badge(s):
        colors = {"silent": "#ef4444", "noisy": "#f97316", "healthy": "#22c55e", "new": "#94a3b8"}
        return (f'<span style="background:{colors.get(s,"#94a3b8")};color:#fff;'
                f'padding:2px 8px;border-radius:8px;font-size:11px">{s}</span>')

    rows = ""
    for d in (noisy + silent)[:30]:
        rows += f"""
        <tr>
          <td style="font-size:12px">{d['name']}</td>
          <td style="text-align:center;font-weight:700">{d['incident_count']}</td>
          <td>{status_badge(d['status'])}</td>
          <td style="font-size:11px;color:#94a3b8">{ts_to_str(d['lastUpdated'])}</td>
        </tr>"""
    return f"""
  <div class="card">
    <h2>Detector Alert History</h2>
    <div class="stat-grid" style="margin-bottom:16px">
      <div class="stat"><div class="val" style="color:#22c55e">{len(healthy)}</div><div class="lbl">Healthy (fired)</div></div>
      <div class="stat"><div class="val" style="color:#ef4444">{len(silent)}</div><div class="lbl">Silent / Broken</div></div>
      <div class="stat"><div class="val" style="color:#f97316">{len(noisy)}</div><div class="lbl">Noisy (≥20 incidents)</div></div>
    </div>
    <table>
      <thead><tr><th>Detector</th><th style="text-align:center">Incidents (90d)</th><th>Status</th><th>Last Updated</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>"""


def _html_ingestion_trend(trend_data):
    if not trend_data:
        return ""
    values = [t["value"] for t in trend_data]
    max_v  = max(values) if values else 1
    bar_h  = 60
    bars   = ""
    for t in trend_data:
        h     = max(2, round(t["value"] / max(max_v, 1) * bar_h))
        label = t["month"][5:]
        v_str = f"{t['value']/1e6:.1f}M" if t["value"] >= 1e6 else f"{t['value']/1e3:.0f}K" if t["value"] >= 1000 else str(int(t["value"]))
        bars += (f'<div style="display:flex;flex-direction:column;align-items:center;gap:2px">'
                 f'<span style="font-size:9px;color:var(--muted)">{v_str}</span>'
                 f'<div style="background:#8b5cf6;width:28px;height:{h}px;border-radius:3px 3px 0 0" title="{t["month"]}: {int(t["value"])}"></div>'
                 f'<span style="font-size:9px;color:#94a3b8">{label}</span>'
                 f'</div>')
    return f"""
  <div class="card">
    <h2>Data Ingestion Trend <span style="font-size:12px;color:var(--muted);font-weight:400">— datapoints received per month</span></h2>
    <div style="display:flex;align-items:flex-end;gap:8px;padding:8px 0">{bars}</div>
  </div>"""


def _html_dashboard_complexity(complexity):
    if not complexity:
        return ""
    totals = {k: len(v) for k, v in complexity.items()}
    grand  = sum(totals.values())
    if grand == 0:
        return ""
    rows = ""
    colors = {"empty": "#ef4444", "simple": "#f97316", "moderate": "#eab308",
              "rich": "#22c55e", "complex": "#3b82f6"}
    ranges = {"empty": "0 charts", "simple": "1–3", "moderate": "4–8",
              "rich": "9–20", "complex": ">20"}
    for bucket, items in complexity.items():
        if not items:
            continue
        color = colors[bucket]
        pct   = round(len(items) / grand * 100)
        examples = ", ".join(i["name"][:25] for i in items[:3])
        rows += f"""
        <tr>
          <td><span style="background:{color};color:#fff;padding:2px 8px;border-radius:8px;font-size:11px">{bucket}</span></td>
          <td style="font-size:11px;color:#94a3b8">{ranges[bucket]}</td>
          <td style="text-align:center;font-weight:700">{len(items)}</td>
          <td>
            <div style="background:#e2e8f0;border-radius:3px;height:8px;width:{max(pct,2)}px;display:inline-block">
              <div style="background:{color};width:100%;height:100%;border-radius:3px"></div>
            </div>
            <span style="font-size:11px;color:var(--muted);margin-left:6px">{pct}%</span>
          </td>
          <td style="font-size:11px;color:var(--muted)">{examples}{'...' if len(items) > 3 else ''}</td>
        </tr>"""
    return f"""
  <div class="card">
    <h2>Dashboard Complexity <span style="font-size:12px;color:var(--muted);font-weight:400">— sampled from most recently updated</span></h2>
    <table>
      <thead><tr><th>Tier</th><th>Range</th><th style="text-align:center">Count</th><th>Share</th><th>Examples</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>"""


def _html_detector_service_coverage(coverage):
    if not coverage or coverage["total"] == 0:
        return ""
    uncovered = coverage["uncovered"]
    covered   = coverage["covered"]
    pct       = round(len(covered) / coverage["total"] * 100) if coverage["total"] else 0
    color     = "#22c55e" if pct >= 80 else "#eab308" if pct >= 50 else "#ef4444"
    unc_badges = "".join(
        f'<span style="background:#ef4444;color:#fff;padding:2px 8px;border-radius:8px;'
        f'font-size:11px;margin:2px;display:inline-block">{s}</span>'
        for s in uncovered
    ) or '<span style="color:#94a3b8;font-size:12px">All services covered</span>'
    cov_badges = "".join(
        f'<span style="background:#22c55e;color:#fff;padding:2px 8px;border-radius:8px;'
        f'font-size:11px;margin:2px;display:inline-block">{s}</span>'
        for s in covered
    )
    return f"""
  <div class="card">
    <h2>Detector → Service Coverage</h2>
    <div style="margin-bottom:12px;display:flex;align-items:center;gap:12px">
      <span style="font-size:24px;font-weight:800;color:{color}">{len(covered)}/{coverage['total']}</span>
      <div style="flex:1;background:#e2e8f0;border-radius:4px;height:10px">
        <div style="background:{color};width:{pct}%;height:100%;border-radius:4px"></div>
      </div>
      <span style="color:{color};font-weight:700">{pct}% covered</span>
    </div>
    <div style="margin-bottom:10px">
      <b style="font-size:11px;color:#ef4444">UNCOVERED SERVICES:</b><br>
      <div style="margin-top:4px">{unc_badges}</div>
    </div>
    <div>
      <b style="font-size:11px;color:#22c55e">COVERED SERVICES:</b><br>
      <div style="margin-top:4px">{cov_badges}</div>
    </div>
  </div>"""


def _html_token_scope_hygiene(tok_issues):
    if not tok_issues:
        return ""
    rows = ""
    for t in tok_issues[:20]:
        risk_color = "#ef4444" if t["risk"] == "high" else "#f97316"
        rows += f"""
        <tr>
          <td style="font-size:12px">{t['name']}</td>
          <td style="font-size:12px;color:var(--muted)">{t['scopes']}</td>
          <td>{ts_to_str(t['expiry'])}</td>
          <td><span style="background:{risk_color};color:#fff;padding:2px 8px;border-radius:8px;font-size:11px">{t['risk']}</span></td>
        </tr>"""
    return f"""
  <div class="card">
    <h2>Token Scope Hygiene <span style="font-size:12px;color:var(--muted);font-weight:400">— over-privileged tokens</span></h2>
    <p style="font-size:12px;color:var(--muted);margin-bottom:12px">{len(tok_issues)} token(s) with broad or unrestricted API scope</p>
    <table>
      <thead><tr><th>Token</th><th>Scopes</th><th>Expiry</th><th>Risk</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>"""


def _html_ttfv(users):
    """Time-to-first-value per user."""
    u_with_ttfv = [(u["email"], u["ttfv_days"]) for u in users if u.get("ttfv_days") is not None]
    if not u_with_ttfv:
        return ""
    u_with_ttfv.sort(key=lambda x: x[1])
    rows = ""
    for email, days_val in u_with_ttfv:
        color = "#22c55e" if days_val <= 3 else "#eab308" if days_val <= 14 else "#ef4444"
        rows += f"""
        <tr>
          <td style="font-size:12px">{email}</td>
          <td style="font-weight:700;color:{color}">{days_val}d</td>
          <td style="font-size:11px;color:var(--muted)">{'Same day' if days_val == 0 else f'{days_val} days after joining'}</td>
        </tr>"""
    avg = round(sum(d for _, d in u_with_ttfv) / len(u_with_ttfv), 1)
    return f"""
  <div class="card">
    <h2>Time to First Value <span style="font-size:12px;color:var(--muted);font-weight:400">— days from join to first write operation</span></h2>
    <p style="font-size:12px;color:var(--muted);margin-bottom:12px">Avg: <b>{avg}d</b> — lower is better onboarding experience</p>
    <table>
      <thead><tr><th>User</th><th>Days</th><th>Notes</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>"""


def _html_engagement_trend(users):
    """30d vs prev-30d engagement delta per user."""
    rows = ""
    for u in sorted(users, key=lambda u: -abs(u.get("activity_delta", 0))):
        delta = u.get("activity_delta", 0)
        last30 = u.get("activity_last30", 0)
        prev30 = u.get("activity_prev30", 0)
        if last30 == 0 and prev30 == 0:
            continue
        arrow = "▲" if delta > 0 else "▼" if delta < 0 else "→"
        color = "#22c55e" if delta > 0 else "#ef4444" if delta < 0 else "#94a3b8"
        tag   = u.get("user_tag", "")
        tag_color = {"Champion": "#8b5cf6", "Automator": "#f59e0b", "Power Builder": "#3b82f6",
                     "Viewer": "#64748b", "Churning": "#ef4444", "Growing": "#22c55e",
                     "Inactive": "#94a3b8", "Active": "#10b981"}.get(tag, "#64748b")
        tag_html = (f'<span style="background:{tag_color};color:#fff;padding:1px 7px;'
                    f'border-radius:8px;font-size:10px;margin-left:4px">{tag}</span>') if tag else ""
        rows += f"""
        <tr>
          <td style="font-size:12px">{u['email']}{tag_html}</td>
          <td style="text-align:center">{prev30}</td>
          <td style="text-align:center">{last30}</td>
          <td style="text-align:center;font-weight:700;color:{color}">{arrow} {abs(delta)}</td>
        </tr>"""
    if not rows:
        return ""
    return f"""
  <div class="card">
    <h2>Engagement Trend <span style="font-size:12px;color:var(--muted);font-weight:400">— last 30d vs previous 30d activity</span></h2>
    <table>
      <thead><tr><th>User</th><th style="text-align:center">Prev 30d</th><th style="text-align:center">Last 30d</th><th style="text-align:center">Delta</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>"""


def _html_incident_mtta(mtta_data):
    if not mtta_data or not mtta_data.get("per_user"):
        return ""
    rows = ""
    for u in mtta_data["per_user"][:20]:
        mtta = f"{u['avg_mtta_min']}m" if u["avg_mtta_min"] is not None else "—"
        ack_pct = round(u["acked"] / u["total"] * 100) if u["total"] else 0
        color = "#22c55e" if ack_pct >= 80 else "#eab308" if ack_pct >= 50 else "#ef4444"
        rows += f"""
        <tr>
          <td style="font-size:12px">{u['email']}</td>
          <td style="text-align:center">{u['total']}</td>
          <td style="text-align:center">{u['acked']}</td>
          <td style="text-align:center;font-weight:700;color:{color}">{ack_pct}%</td>
          <td style="text-align:center">{mtta}</td>
        </tr>"""
    unacked_color = "#ef4444" if mtta_data["unacked_pct"] > 30 else "#eab308" if mtta_data["unacked_pct"] > 10 else "#22c55e"
    return f"""
  <div class="card">
    <h2>Incident Acknowledgement &amp; MTTA</h2>
    <div class="stat-grid" style="margin-bottom:16px">
      <div class="stat"><div class="val">{mtta_data['total_incidents']}</div><div class="lbl">Total Incidents</div></div>
      <div class="stat"><div class="val">{mtta_data['acked']}</div><div class="lbl">Acknowledged</div></div>
      <div class="stat"><div class="val" style="color:{unacked_color}">{mtta_data['unacked_pct']}%</div><div class="lbl">Never Ack'd</div></div>
    </div>
    <table>
      <thead><tr><th>User</th><th style="text-align:center">Total</th><th style="text-align:center">Ack'd</th><th style="text-align:center">Ack Rate</th><th style="text-align:center">Avg MTTA</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>"""


def _html_alert_fatigue(fatigue_data):
    if not fatigue_data:
        return ""
    apd = fatigue_data["alerts_per_user_per_day"]
    color = "#22c55e" if fatigue_data["benchmark_ok"] else "#ef4444"
    dq = fatigue_data.get("detector_quality", [])
    noisy = [d for d in dq if d["quality"] == "noisy"]
    rows = ""
    for d in dq[:15]:
        c = "#ef4444" if d["quality"] == "noisy" else "#22c55e"
        rows += f"""
        <tr>
          <td style="font-size:12px">{d['name'][:60]}</td>
          <td style="text-align:center">{d['total']}</td>
          <td style="text-align:center">{d['noise']}</td>
          <td style="text-align:center;font-weight:700;color:{c}">{d['noise_pct']}%</td>
          <td style="text-align:center">{d['quality']}</td>
        </tr>"""
    table_html = f"""<table>
      <thead><tr><th>Detector</th><th style="text-align:center">Incidents</th><th style="text-align:center">Noise (&lt;5m)</th><th style="text-align:center">Noise%</th><th style="text-align:center">Quality</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>""" if rows else ""
    return f"""
  <div class="card">
    <h2>Alert Fatigue Index &amp; Detector Signal Quality</h2>
    <div class="stat-grid" style="margin-bottom:16px">
      <div class="stat"><div class="val" style="color:{color}">{apd}</div><div class="lbl">Alerts/User/Day</div></div>
      <div class="stat"><div class="val">{fatigue_data['total_incidents']}</div><div class="lbl">Total Incidents</div></div>
      <div class="stat"><div class="val" style="color:#ef4444">{len(noisy)}</div><div class="lbl">Noisy Detectors</div></div>
    </div>
    <p style="font-size:12px;color:var(--muted)">Benchmark: ≤5 alerts/user/day. Short-lived (&lt;5min) incidents counted as noise.</p>
    {table_html}
  </div>"""


def _html_detector_notification_routing(routing_data):
    if not routing_data:
        return ""
    cc = routing_data.get("channel_counts", {})
    no_routing = routing_data.get("no_routing", [])
    email_only = routing_data.get("email_only", [])
    if not cc and not no_routing:
        return ""
    channel_bars = ""
    total_ch = sum(cc.values()) or 1
    colors = {"email": "#3b82f6", "slack": "#8b5cf6", "pagerduty": "#ef4444",
              "victorops": "#f97316", "opsgenie": "#06b6d4", "webhook": "#6366f1",
              "msteams": "#0ea5e9", "servicenow": "#22c55e", "other": "#94a3b8"}
    for ch, cnt in cc.items():
        pct = round(cnt / total_ch * 100)
        c = colors.get(ch, "#94a3b8")
        w = min(pct, 100)
        channel_bars += f"""
        <tr>
          <td style="font-size:12px">{ch}</td>
          <td><div style="background:#e2e8f0;border-radius:3px;height:8px;width:200px;display:inline-block;vertical-align:middle">
            <div style="background:{c};width:{w}%;height:100%;border-radius:3px"></div></div></td>
          <td style="text-align:center">{cnt}</td>
          <td style="text-align:center">{pct}%</td>
        </tr>"""
    no_routing_html = (f'<p style="font-size:12px;color:#ef4444;margin-top:8px">⚠ {len(no_routing)} detector(s) have no notification routing</p>'
                       if no_routing else "")
    email_html = (f'<p style="font-size:12px;color:#eab308;margin-top:4px">⚠ {len(email_only)} detector(s) route to email only</p>'
                  if email_only else "")
    return f"""
  <div class="card">
    <h2>Detector Notification Routing</h2>
    <table>
      <thead><tr><th>Channel</th><th>Distribution</th><th style="text-align:center">Count</th><th style="text-align:center">%</th></tr></thead>
      <tbody>{channel_bars}</tbody>
    </table>
    {no_routing_html}{email_html}
  </div>"""


def _html_alert_routing_by_service(routing_data):
    if not routing_data:
        return ""
    covered   = [r for r in routing_data if r["tier"] == "covered"]
    det_only  = [r for r in routing_data if r["tier"] == "detector-only"]
    uncovered = [r for r in routing_data if r["tier"] == "uncovered"]
    rows = ""
    tier_colors = {"covered": "#22c55e", "detector-only": "#eab308", "uncovered": "#ef4444"}
    for r in sorted(routing_data, key=lambda x: {"covered": 0, "detector-only": 1, "uncovered": 2}[x["tier"]]):
        c = tier_colors[r["tier"]]
        rows += f"""
        <tr>
          <td style="font-size:12px">{r['service']}</td>
          <td style="text-align:center">{'✓' if r['detector'] else '✗'}</td>
          <td style="text-align:center">{'✓' if r['notified'] else '✗'}</td>
          <td style="text-align:center"><span style="color:{c};font-weight:700">{r['tier']}</span></td>
        </tr>"""
    if not rows:
        return ""
    return f"""
  <div class="card">
    <h2>Alert Routing Coverage by Service</h2>
    <div class="stat-grid" style="margin-bottom:12px">
      <div class="stat"><div class="val" style="color:#22c55e">{len(covered)}</div><div class="lbl">Covered</div></div>
      <div class="stat"><div class="val" style="color:#eab308">{len(det_only)}</div><div class="lbl">Detector Only</div></div>
      <div class="stat"><div class="val" style="color:#ef4444">{len(uncovered)}</div><div class="lbl">Uncovered</div></div>
    </div>
    <table>
      <thead><tr><th>Service</th><th style="text-align:center">Detector</th><th style="text-align:center">Notified</th><th style="text-align:center">Tier</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>"""


def _html_data_volume_by_product(vol_data):
    if not vol_data:
        return ""
    rows = ""
    colors = {"Infrastructure": "#3b82f6", "APM": "#8b5cf6", "Logs": "#22c55e",
              "RUM": "#f97316", "Synthetics": "#06b6d4", "Profiling": "#ec4899"}
    for item in vol_data:
        c = colors.get(item["product"], "#94a3b8")
        w = min(item["pct"], 100)
        val_fmt = f"{item['total']:,.0f}"
        rows += f"""
        <tr>
          <td style="font-size:12px">{item['product']}</td>
          <td><div style="background:#e2e8f0;border-radius:3px;height:8px;width:200px;display:inline-block;vertical-align:middle">
            <div style="background:{c};width:{w}%;height:100%;border-radius:3px"></div></div></td>
          <td style="text-align:right">{val_fmt}</td>
          <td style="text-align:center">{item['pct']}%</td>
        </tr>"""
    return f"""
  <div class="card">
    <h2>Data Volume by Telemetry Type</h2>
    <table>
      <thead><tr><th>Product</th><th>Volume</th><th style="text-align:right">Datapoints</th><th style="text-align:center">Share</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>"""


def _html_inactive_admin_risk(risk_data):
    if not risk_data or not risk_data.get("inactive_admins"):
        return ""
    risks = risk_data["inactive_admins"]
    rows = ""
    for r in risks:
        days_str = f"{r['days_inactive']}d ago" if r["days_inactive"] is not None else "never"
        rows += f"""
        <tr>
          <td style="font-size:12px">{r['email']}</td>
          <td style="text-align:center">{ts_to_str(r['last_activity']) if r['last_activity'] else 'never'}</td>
          <td style="text-align:center">{days_str}</td>
        </tr>"""
    tok_note = (f'<p style="font-size:12px;margin-top:8px;color:#ef4444">'
                f'⚠ Org has {risk_data["active_token_count"]} active token(s) — '
                f'inactive admin accounts increase credential risk.</p>'
                if risk_data["active_token_count"] > 0 else "")
    return f"""
  <div class="card">
    <h2>Inactive Admin Risk <span style="font-size:12px;color:#ef4444;font-weight:400">— {len(risks)} inactive admin(s)</span></h2>
    <table>
      <thead><tr><th>Admin</th><th style="text-align:center">Last Activity</th><th style="text-align:center">Inactive For</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
    {tok_note}
  </div>"""


def _html_token_rotation(rotation_data):
    if not rotation_data:
        return ""
    rows = ""
    for t in rotation_data[:20]:
        age_color = "#ef4444" if t["age_days"] > 730 else "#eab308" if t["age_days"] > 365 else "#22c55e"
        exp_badge = (' <span style="background:#ef4444;color:#fff;padding:1px 6px;border-radius:8px;font-size:10px">EXPIRED</span>'
                     if t["expired"] else "")
        rows += f"""
        <tr>
          <td style="font-size:12px">{t['name']}{exp_badge}</td>
          <td style="text-align:center;font-weight:700;color:{age_color}">{t['age_days']}d</td>
          <td style="font-size:11px;color:var(--muted)">{t['scopes']}</td>
        </tr>"""
    return f"""
  <div class="card">
    <h2>Token Rotation Cadence <span style="font-size:12px;color:var(--muted);font-weight:400">— tokens older than 1 year</span></h2>
    <table>
      <thead><tr><th>Token</th><th style="text-align:center">Age</th><th>Scopes</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>"""


def _html_signalflow_usage(sf_data):
    if not sf_data:
        return ""
    rows = ""
    for u in sf_data[:20]:
        total = u["signalflow"] + u["data_searches"]
        rows += f"""
        <tr>
          <td style="font-size:12px">{u['email']}</td>
          <td style="text-align:center">{u['signalflow']}</td>
          <td style="text-align:center">{u['data_searches']}</td>
          <td style="text-align:center;font-weight:700">{total}</td>
        </tr>"""
    if not rows:
        return ""
    return f"""
  <div class="card">
    <h2>SignalFlow &amp; Data Search Usage</h2>
    <table>
      <thead><tr><th>User</th><th style="text-align:center">SignalFlow Queries</th><th style="text-align:center">Data Searches</th><th style="text-align:center">Total</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>"""


def _html_dashboard_sharing(sharing_data):
    if not sharing_data:
        return ""
    top = sharing_data.get("top_read_dashboards", [])
    publishers = sharing_data.get("publishers", [])
    top_rows = ""
    for d in top[:15]:
        top_rows += f"""
        <tr>
          <td style="font-size:12px">{d['name'][:60]}</td>
          <td style="text-align:center;font-weight:700">{d['reads']}</td>
        </tr>"""
    pub_rows = ""
    for p in publishers[:10]:
        pub_rows += f"""
        <tr>
          <td style="font-size:12px">{p['email']}</td>
          <td style="text-align:center">{p['group_creates']}</td>
        </tr>"""
    top_table = (f'<h3 style="font-size:13px;margin-top:16px;margin-bottom:6px">Most-Read Dashboards</h3>'
                 f'<table><thead><tr><th>Dashboard</th><th style="text-align:center">Views</th></tr></thead>'
                 f'<tbody>{top_rows}</tbody></table>') if top_rows else ""
    pub_table = (f'<h3 style="font-size:13px;margin-top:16px;margin-bottom:6px">Dashboard Publishers (Group Creates)</h3>'
                 f'<table><thead><tr><th>User</th><th style="text-align:center">Groups Created</th></tr></thead>'
                 f'<tbody>{pub_rows}</tbody></table>') if pub_rows else ""
    total = sharing_data.get("total_dash_reads", 0)
    return f"""
  <div class="card">
    <h2>Dashboard Sharing &amp; View Frequency</h2>
    <p style="font-size:12px;color:var(--muted);margin-bottom:4px">Total dashboard views tracked: <strong>{total}</strong></p>
    {top_table}
    {pub_table}
  </div>"""


def _html_detector_creation_velocity(vel_data):
    if not vel_data:
        return ""
    recent = vel_data[-12:]
    if not recent:
        return ""
    max_count = max(d["count"] for d in recent) or 1
    bars = ""
    for item in recent:
        w = min(round(item["count"] / max_count * 200), 200)
        bars += f"""
        <tr>
          <td style="font-size:12px">{item['month']}</td>
          <td><div style="background:#e2e8f0;border-radius:3px;height:8px;width:{w}px;display:inline-block;vertical-align:middle">
            <div style="background:#3b82f6;width:100%;height:100%;border-radius:3px"></div></div></td>
          <td style="text-align:center;font-weight:700">{item['count']}</td>
        </tr>"""
    total = sum(d["count"] for d in vel_data)
    return f"""
  <div class="card">
    <h2>Detector Creation Velocity <span style="font-size:12px;color:var(--muted);font-weight:400">— {total} total detectors, last 12 months shown</span></h2>
    <table>
      <thead><tr><th>Month</th><th>Volume</th><th style="text-align:center">New Detectors</th></tr></thead>
      <tbody>{bars}</tbody>
    </table>
  </div>"""


def _html_new_vs_returning(nvr_data):
    if not nvr_data:
        return ""
    n = nvr_data["new"]
    e = nvr_data["established"]
    new_users = nvr_data.get("new_users", [])
    rows = ""
    for u in new_users[:10]:
        since = ts_to_str(u.get("member_since")) if u.get("member_since") else "—"
        rows += f"""
        <tr>
          <td style="font-size:12px">{u['email']}</td>
          <td style="text-align:center">{since}</td>
          <td style="text-align:center">{u.get('engagement_score', 0)}</td>
          <td style="text-align:center">{u['login_count']}</td>
        </tr>"""
    new_table = (f'<h3 style="font-size:13px;margin-top:16px;margin-bottom:6px">New Users (joined last 30d)</h3>'
                 f'<table><thead><tr><th>User</th><th style="text-align:center">Joined</th><th style="text-align:center">Score</th><th style="text-align:center">Logins</th></tr></thead>'
                 f'<tbody>{rows}</tbody></table>') if rows else ""
    return f"""
  <div class="card">
    <h2>New vs Returning Users</h2>
    <div class="stat-grid" style="margin-bottom:12px">
      <div class="stat"><div class="val">{n['count']}</div><div class="lbl">New (&lt;30d)</div></div>
      <div class="stat"><div class="val">{n.get('retention', 0)}%</div><div class="lbl">New Active</div></div>
      <div class="stat"><div class="val">{n.get('avg_score', 0)}</div><div class="lbl">New Avg Score</div></div>
      <div class="stat"><div class="val">{e['count']}</div><div class="lbl">Established</div></div>
      <div class="stat"><div class="val">{e.get('retention', 0)}%</div><div class="lbl">Est. Active</div></div>
      <div class="stat"><div class="val">{e.get('avg_score', 0)}</div><div class="lbl">Est. Avg Score</div></div>
    </div>
    {new_table}
  </div>"""


def _html_privilege_escalation(esc_data):
    if not esc_data:
        return ""
    elevated = esc_data.get("recently_elevated", [])
    role_changes = esc_data.get("role_changes", [])
    if not elevated and not role_changes:
        return ""
    rows = ""
    for r in elevated:
        rows += f"""
        <tr>
          <td style="font-size:12px">{r['email']}</td>
          <td style="text-align:center">{ts_to_str(r['joined'])}</td>
          <td style="text-align:center">{r['days_ago']}d ago</td>
          <td>{r['source']}</td>
        </tr>"""
    rc_rows = ""
    for rc in role_changes[:10]:
        rc_rows += f"""
        <tr>
          <td style="font-size:12px">{rc['actor']}</td>
          <td style="font-size:11px;color:var(--muted)">{rc['uri']}</td>
          <td style="text-align:center">{ts_to_str(rc['ts'])}</td>
        </tr>"""
    elevated_table = (f'<h3 style="font-size:13px;margin-bottom:6px">Recently Elevated Admins</h3>'
                      f'<table><thead><tr><th>Admin</th><th style="text-align:center">Joined</th><th style="text-align:center">Days Ago</th><th>Source</th></tr></thead>'
                      f'<tbody>{rows}</tbody></table>') if rows else ""
    rc_table = (f'<h3 style="font-size:13px;margin-top:16px;margin-bottom:6px">Role Change Events (last 90d)</h3>'
                f'<table><thead><tr><th>Actor</th><th>URI</th><th style="text-align:center">When</th></tr></thead>'
                f'<tbody>{rc_rows}</tbody></table>') if rc_rows else ""
    return f"""
  <div class="card" style="border-left:4px solid #ef4444">
    <h2>Privilege Escalation Detection <span style="font-size:12px;color:#ef4444;font-weight:400">— {len(elevated)} new admin(s), {len(role_changes)} role change(s)</span></h2>
    {elevated_table}
    {rc_table}
  </div>"""


def _html_slo_detectors(slo_data):
    if not slo_data or slo_data.get("slo_count", 0) == 0:
        return ""
    maturity_color = {"SRE-mature": "#22c55e", "developing": "#eab308", "basic": "#ef4444"}
    c = maturity_color.get(slo_data["maturity"], "#94a3b8")
    rows = ""
    for d in slo_data.get("slo_detectors", [])[:20]:
        rows += f'<tr><td style="font-size:12px">{d["name"][:70]}</td></tr>'
    return f"""
  <div class="card">
    <h2>SLO Detector Coverage</h2>
    <div class="stat-grid" style="margin-bottom:12px">
      <div class="stat"><div class="val" style="color:{c}">{slo_data['slo_count']}</div><div class="lbl">SLO Detectors</div></div>
      <div class="stat"><div class="val">{slo_data['generic_count']}</div><div class="lbl">Generic Detectors</div></div>
      <div class="stat"><div class="val" style="color:{c}">{slo_data['maturity']}</div><div class="lbl">SRE Maturity</div></div>
    </div>
    <table><thead><tr><th>SLO-Pattern Detector</th></tr></thead><tbody>{rows}</tbody></table>
  </div>"""


def _html_instrumentation_completeness(inst_data):
    if not inst_data:
        return ""
    full    = [s for s in inst_data if s["tier"] == "full"]
    partial = [s for s in inst_data if s["tier"] == "partial"]
    traces_only = [s for s in inst_data if s["tier"] == "traces-only"]
    rows = ""
    tier_colors = {"full": "#22c55e", "partial": "#eab308", "traces-only": "#ef4444"}
    for s in inst_data[:30]:
        c = tier_colors.get(s["tier"], "#94a3b8")
        t_icon = "✓" if s["traces"] else "✗"
        m_icon = "✓" if s["metrics"] else "✗"
        l_icon = "✓" if s["logs"] else "✗"
        rows += f"""
        <tr>
          <td style="font-size:12px">{s['service']}</td>
          <td style="text-align:center">{t_icon}</td>
          <td style="text-align:center">{m_icon}</td>
          <td style="text-align:center">{l_icon}</td>
          <td style="text-align:center"><span style="color:{c};font-weight:700">{s['tier']}</span></td>
        </tr>"""
    return f"""
  <div class="card">
    <h2>Instrumentation Completeness</h2>
    <div class="stat-grid" style="margin-bottom:12px">
      <div class="stat"><div class="val" style="color:#22c55e">{len(full)}</div><div class="lbl">Full (T+M+L)</div></div>
      <div class="stat"><div class="val" style="color:#eab308">{len(partial)}</div><div class="lbl">Partial</div></div>
      <div class="stat"><div class="val" style="color:#ef4444">{len(traces_only)}</div><div class="lbl">Traces Only</div></div>
    </div>
    <table>
      <thead><tr><th>Service</th><th style="text-align:center">Traces</th><th style="text-align:center">Metrics</th><th style="text-align:center">Logs</th><th style="text-align:center">Tier</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>"""


def _html_cardinality_hotspots(hotspot_data):
    if not hotspot_data:
        return ""
    rows = ""
    max_count = hotspot_data[0]["mts_count"] if hotspot_data else 1
    for h in hotspot_data[:20]:
        w = min(round(h["mts_count"] / max_count * 200), 200)
        c = "#ef4444" if h["pct"] >= 20 else "#eab308" if h["pct"] >= 10 else "#3b82f6"
        rows += f"""
        <tr>
          <td style="font-size:12px">{h.get('metric', h.get('name', '?'))}</td>
          <td><div style="background:#e2e8f0;border-radius:3px;height:8px;width:{w}px;display:inline-block;vertical-align:middle">
            <div style="background:{c};width:100%;height:100%;border-radius:3px"></div></div></td>
          <td style="text-align:right;font-weight:700">{h['mts_count']:,}</td>
          <td style="text-align:center">{h['pct']}%</td>
        </tr>"""
    if not rows:
        return ""
    return f"""
  <div class="card">
    <h2>Cardinality Hotspots <span style="font-size:12px;color:var(--muted);font-weight:400">— top metrics by MTS count</span></h2>
    <table>
      <thead><tr><th>Metric</th><th>Volume</th><th style="text-align:right">MTS Count</th><th style="text-align:center">Share</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>"""


def _card(title, body, anchor="", border_color=None):
    """Wrap content in a collapsible card with an anchor."""
    border = f"border-left:4px solid {border_color};" if border_color else ""
    aid    = f' id="{anchor}"' if anchor else ""
    return f"""
  <details{aid} class="card" style="{border}" open>
    <summary style="cursor:pointer;list-style:none;display:flex;justify-content:space-between;align-items:center">
      <span class="card-title">{title}</span>
      <span class="toggle-icon" style="font-size:11px;color:#94a3b8">▲</span>
    </summary>
    <div class="card-body" style="margin-top:16px">
      {body}
    </div>
  </details>"""


def _html_detector_complexity(complexity_data):
    if not complexity_data:
        return ""
    high    = [d for d in complexity_data if d["complexity"] == "high"]
    library = [d for d in complexity_data if d.get("style") == "library"]
    custom  = [d for d in complexity_data if d.get("style") == "custom"]

    rows = ""
    for d in complexity_data[:20]:
        c      = {"high": "#ef4444", "medium": "#eab308", "low": "#22c55e"}.get(d["complexity"], "#94a3b8")
        style  = d.get("style", "custom")
        style_badge = (
            '<span style="background:#6366f122;color:#6366f1;border-radius:5px;padding:1px 6px;font-size:10px">library</span>'
            if style == "library" else
            '<span style="background:#22c55e22;color:#22c55e;border-radius:5px;padding:1px 6px;font-size:10px">custom</span>'
        )
        score_str = f'<span style="color:{c};font-weight:700">{d["score"]}</span>' if d["score"] > 0 else '<span style="color:#94a3b8">—</span>'
        rows += f"""
        <tr>
          <td style="font-size:12px">{d['name'][:60]}</td>
          <td style="text-align:center">{style_badge}</td>
          <td style="text-align:center;font-size:12px">{d['data_calls'] or '—'}</td>
          <td style="text-align:center;font-size:12px">{d['filter_calls'] or '—'}</td>
          <td style="text-align:center;font-size:12px">{d['detect_calls'] or '—'}</td>
          <td style="text-align:center">{score_str}</td>
          <td style="text-align:center"><span style="color:{c};font-size:12px">{d['complexity']}</span></td>
        </tr>"""

    note = ""
    if library:
        note = (f'<p style="font-size:12px;color:var(--muted);background:var(--hover);border-left:3px solid #6366f1;'
                f'padding:8px 12px;border-radius:4px;margin-bottom:14px">'
                f'<strong>{len(library)}/{len(complexity_data)} detectors use the AutoDetect/library style</strong> — '
                f'their SignalFlow logic lives inside the Splunk library, so <code>data()</code>/<code>detect()</code> '
                f'counts appear as 0 here. Scores only reflect explicit inline SignalFlow for '
                f'<strong>{len(custom)} custom detector(s)</strong>.</p>')

    body = note + f"""
    <div class="stat-grid" style="margin-bottom:16px">
      <div class="stat"><div class="val" style="color:#6366f1">{len(library)}</div><div class="lbl">Library-based</div></div>
      <div class="stat"><div class="val" style="color:#22c55e">{len(custom)}</div><div class="lbl">Custom SignalFlow</div></div>
      <div class="stat"><div class="val" style="color:#ef4444">{len(high)}</div><div class="lbl">High Complexity</div></div>
    </div>
    <table>
      <thead><tr><th>Detector</th><th style="text-align:center">Style</th><th style="text-align:center">data()</th><th style="text-align:center">filter()</th><th style="text-align:center">detect()</th><th style="text-align:center">Score</th><th style="text-align:center">Complexity</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>"""
    return _card("Detector Program Complexity", body, anchor="sec-det-complexity")


def _html_user_last_touched(last_touched, users):
    if not last_touched:
        return ""
    rows = ""
    for u in users:
        info = last_touched.get(u["email"])
        if not info:
            continue
        rows += f"""
        <tr>
          <td style="font-size:12px">{u['email']}</td>
          <td style="font-size:12px;color:var(--muted)">{info['asset_type']}</td>
          <td style="font-size:12px">{info['asset_name']}</td>
          <td style="text-align:center;font-size:11px">{ts_to_str(info['ts'])}</td>
        </tr>"""
    if not rows:
        return ""
    body = f"""<table>
      <thead><tr><th>User</th><th>Type</th><th>Last Asset</th><th style="text-align:center">When</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>"""
    return _card("User Last Resource Touched", body, anchor="sec-last-touched")


def _html_dashboard_groups(group_data):
    if not group_data:
        return ""
    rows = ""
    for g in group_data[:20]:
        owner_str = ", ".join(g["owners"][:2]) + ("..." if len(g["owners"]) > 2 else "") if g["owners"] else "—"
        names_str = ", ".join(g["names"][:3]) + ("..." if len(g["names"]) > 3 else "")
        rows += f"""
        <tr>
          <td style="font-size:11px;color:var(--muted)">{str(g['group_id'] or '')[:30]}</td>
          <td style="text-align:center;font-weight:700">{g['dashboard_count']}</td>
          <td style="font-size:12px">{names_str}</td>
          <td style="font-size:11px;color:var(--muted)">{owner_str}</td>
          <td style="font-size:11px">{ts_to_str(g['latest_update'])}</td>
        </tr>"""
    body = f"""<table>
      <thead><tr><th>Group ID</th><th style="text-align:center">Dashboards</th><th>Sample Names</th><th>Owners</th><th>Latest Update</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>"""
    return _card(f"Dashboard Group Ownership ({len(group_data)} groups)", body, anchor="sec-dash-groups")


def _html_notification_health(notif_health):
    if not notif_health or not notif_health.get("broken_integrations"):
        return ""
    issues = notif_health["broken_integrations"]
    affected = notif_health["affected_detectors"]
    rows = ""
    for i in issues:
        rows += f"""
        <tr>
          <td style="font-size:12px">{i['name']}</td>
          <td style="font-size:11px;color:var(--muted)">{i['type']}</td>
          <td style="color:#ef4444;font-size:12px">{i['issue']}</td>
        </tr>"""
    aff_html = (f'<p style="font-size:12px;color:#ef4444;margin-top:8px">'
                f'⚠ {len(affected)} detector(s) route to broken integrations</p>') if affected else ""
    body = f"""<table>
      <thead><tr><th>Integration</th><th>Type</th><th>Issue</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>{aff_html}"""
    return _card("Notification Channel Health", body, anchor="sec-notif-health", border_color="#ef4444")


def _html_service_error_rates(error_rates):
    if not error_rates:
        return ""
    has_data = [s for s in error_rates if s["has_data"]]
    if not has_data:
        return ""
    rows = ""
    for s in error_rates:
        if not s["has_data"]:
            continue
        pct = s["error_rate_pct"] or 0
        c = "#ef4444" if pct >= 5 else "#eab308" if pct >= 1 else "#22c55e"
        w = min(round(pct * 10), 200)
        rows += f"""
        <tr>
          <td style="font-size:12px">{s['service']}</td>
          <td>
            <div style="background:#e2e8f0;border-radius:3px;height:8px;width:200px;display:inline-block;vertical-align:middle">
              <div style="background:{c};width:{w}px;height:100%;border-radius:3px"></div>
            </div>
          </td>
          <td style="text-align:center;font-weight:700;color:{c}">{pct}%</td>
        </tr>"""
    body = f"""<table>
      <thead><tr><th>Service</th><th>Error Rate (7d avg)</th><th style="text-align:center">%</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>"""
    return _card("APM Service Error Rates", body, anchor="sec-svc-errors")


def _html_report_diff(diff):
    if not diff:
        return ""
    added   = diff.get("added_users", [])
    removed = diff.get("removed_users", [])
    body = f"""
    <div class="stat-grid" style="margin-bottom:12px">
      <div class="stat"><div class="val" style="color:#22c55e">+{len(added)}</div><div class="lbl">Users Added</div></div>
      <div class="stat"><div class="val" style="color:#ef4444">-{len(removed)}</div><div class="lbl">Users Removed</div></div>
      <div class="stat"><div class="val" style="color:#22c55e">+{diff.get('new_detectors',0)}</div><div class="lbl">New Detectors</div></div>
      <div class="stat"><div class="val" style="color:#ef4444">-{diff.get('removed_detectors',0)}</div><div class="lbl">Removed Detectors</div></div>
      <div class="stat"><div class="val" style="color:#22c55e">+{diff.get('new_dashboards',0)}</div><div class="lbl">New Dashboards</div></div>
      <div class="stat"><div class="val" style="color:#ef4444">-{diff.get('removed_dashboards',0)}</div><div class="lbl">Removed Dashboards</div></div>
    </div>
    <p style="font-size:12px;color:var(--muted)">Compared to snapshot from {diff.get('snapshot_age_days',0)} days ago.</p>
    {"<p style='margin-top:8px;font-size:12px'><strong>New users:</strong> " + ", ".join(added[:5]) + ("..." if len(added)>5 else "") + "</p>" if added else ""}
    {"<p style='margin-top:4px;font-size:12px'><strong>Removed users:</strong> " + ", ".join(removed[:5]) + ("..." if len(removed)>5 else "") + "</p>" if removed else ""}"""
    return _card(f"Report Changelog (vs {diff.get('snapshot_age_days',0)}d ago)", body, anchor="sec-diff")


def _html_orphaned_assets(orphan_data):
    if not orphan_data:
        return ""
    o_det  = orphan_data.get("orphaned_detectors", [])
    o_dash = orphan_data.get("orphaned_dashboards", [])
    o_ch   = orphan_data.get("orphaned_chart_count", 0)
    if not o_det and not o_dash and not o_ch:
        return ""
    rows = ""
    for item, itype in [(d, "detector") for d in o_det[:10]] + [(d, "dashboard") for d in o_dash[:10]]:
        rows += f"""
        <tr>
          <td style="font-size:11px;color:var(--muted)">{itype}</td>
          <td style="font-size:12px">{item['name'][:60]}</td>
          <td style="font-size:11px;color:#ef4444">{item['owner'] or 'no owner'}</td>
          <td style="font-size:11px">{ts_to_str(item.get('lastUpdated'))}</td>
        </tr>"""
    body = f"""
    <div class="stat-grid" style="margin-bottom:12px">
      <div class="stat"><div class="val" style="color:#ef4444">{len(o_det)}</div><div class="lbl">Orphaned Detectors</div></div>
      <div class="stat"><div class="val" style="color:#ef4444">{len(o_dash)}</div><div class="lbl">Orphaned Dashboards</div></div>
      <div class="stat"><div class="val" style="color:#eab308">{o_ch}</div><div class="lbl">Orphaned Charts</div></div>
    </div>
    <p style="font-size:12px;color:var(--muted);margin-bottom:8px">Assets whose last modifier is no longer a member of the org.</p>
    <table>
      <thead><tr><th>Type</th><th>Name</th><th>Former Owner</th><th>Last Updated</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>"""
    return _card("Orphaned Assets", body, anchor="sec-orphaned", border_color="#ef4444")


def _html_alert_severity_dist(sev_data):
    if not sev_data or not sev_data.get("distribution"):
        return ""
    dist  = sev_data["distribution"]
    colors = {"critical": "#ef4444", "major": "#f97316", "minor": "#eab308",
              "warning": "#06b6d4", "info": "#22c55e", "unknown": "#94a3b8"}
    rows = ""
    for sev, info in dist.items():
        c = colors.get(sev, "#94a3b8")
        w = min(info["pct"] * 2, 200)
        rows += f"""
        <tr>
          <td><span style="background:{c};color:#fff;padding:2px 8px;border-radius:8px;font-size:11px">{sev}</span></td>
          <td><div style="background:#e2e8f0;border-radius:3px;height:8px;width:{w}px;display:inline-block;vertical-align:middle">
            <div style="background:{c};width:100%;height:100%;border-radius:3px"></div></div></td>
          <td style="text-align:center;font-weight:700">{info['count']}</td>
          <td style="text-align:center">{info['pct']}%</td>
        </tr>"""
    warn = ('<p style="font-size:12px;color:#eab308;margin-top:8px">⚠ Only high-severity incidents detected — consider adding Minor/Warning detectors for graduated alerting.</p>'
            if sev_data.get("missing_gradation") else "")
    body = f"""<table>
      <thead><tr><th>Severity</th><th>Distribution</th><th style="text-align:center">Count</th><th style="text-align:center">%</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>{warn}"""
    return _card(f"Alert Severity Distribution ({sev_data['total']} incidents)", body, anchor="sec-severity")


def _html_onboarding_velocity(vel_data):
    if not vel_data:
        return ""
    rows = ""
    max_ttfv = max(d["avg_ttfv_days"] for d in vel_data) or 1
    for item in vel_data:
        w = min(round(item["avg_ttfv_days"] / max_ttfv * 200), 200)
        c = "#22c55e" if item["avg_ttfv_days"] <= 3 else "#eab308" if item["avg_ttfv_days"] <= 14 else "#ef4444"
        rows += f"""
        <tr>
          <td style="font-size:12px">{item['month']}</td>
          <td style="text-align:center">{item['user_count']}</td>
          <td>
            <div style="background:#e2e8f0;border-radius:3px;height:8px;width:{w}px;display:inline-block;vertical-align:middle">
              <div style="background:{c};width:100%;height:100%;border-radius:3px"></div>
            </div>
          </td>
          <td style="text-align:center;font-weight:700;color:{c}">{item['avg_ttfv_days']}d</td>
        </tr>"""
    if not rows:
        return ""
    body = f"""<p style="font-size:12px;color:var(--muted);margin-bottom:8px">Average days from account creation to first write operation, by cohort month.</p>
    <table>
      <thead><tr><th>Join Month</th><th style="text-align:center">Users</th><th>TTFV</th><th style="text-align:center">Avg Days</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>"""
    return _card("Onboarding Velocity (TTFV by Cohort)", body, anchor="sec-onboarding-vel")



def _html_role_distribution(role_data):
    if not role_data:
        return ""
    roles      = role_data.get("roles", {})
    admin_pct  = role_data.get("admin_pct", 0)
    risk       = role_data.get("risk", False)
    members    = role_data.get("members", [])
    total      = sum(roles.values()) or 1

    role_colors = {"admin": "#ef4444", "power": "#f97316", "usage": "#3b82f6", "unknown": "#94a3b8"}
    bars = ""
    for role, cnt in sorted(roles.items(), key=lambda x: -x[1]):
        pct = round(cnt / total * 100)
        c   = role_colors.get(role, "#6366f1")
        bars += f"""
        <tr>
          <td style="font-size:12px;font-weight:600">{role}</td>
          <td style="width:160px">
            <div style="background:#e2e8f0;border-radius:3px;height:10px">
              <div style="background:{c};width:{pct}%;height:100%;border-radius:3px"></div>
            </div>
          </td>
          <td style="text-align:right;font-size:12px;font-weight:700">{cnt}</td>
          <td style="text-align:right;font-size:11px;color:var(--muted)">{pct}%</td>
        </tr>"""

    risk_badge = (f'<span style="background:#ef4444;color:#fff;padding:2px 8px;border-radius:8px;'
                  f'font-size:11px;margin-left:8px">⚠ {admin_pct}% admins — review least-privilege</span>'
                  if risk else
                  f'<span style="background:#22c55e;color:#fff;padding:2px 8px;border-radius:8px;'
                  f'font-size:11px;margin-left:8px">{admin_pct}% admins</span>')

    member_rows = ""
    for m in members:
        role = m["role"]
        c    = role_colors.get(role, "#6366f1")
        created_str = ""
        if m.get("created"):
            dt = datetime.fromtimestamp(m["created"] / 1000, tz=timezone.utc)
            created_str = dt.strftime("%Y-%m-%d")
        member_rows += f"""
        <tr>
          <td style="font-size:12px">{m['email']}</td>
          <td style="font-size:12px">{m.get('fullName','')}</td>
          <td><span style="background:{c};color:#fff;padding:2px 8px;border-radius:8px;font-size:11px">{role}</span></td>
          <td style="font-size:12px;color:var(--muted)">{created_str}</td>
        </tr>"""

    body = f"""
    <div style="display:flex;align-items:center;margin-bottom:12px">
      <span style="font-size:13px;color:var(--muted)">{total} total members</span>
      {risk_badge}
    </div>
    <table style="margin-bottom:12px"><tbody>{bars}</tbody></table>
    <h4 style="font-size:12px;margin:14px 0 6px">Member Roster</h4>
    <table>
      <thead><tr><th>Email</th><th>Name</th><th>Role</th><th>Joined</th></tr></thead>
      <tbody>{member_rows}</tbody>
    </table>"""
    border = "#ef4444" if risk else "#22c55e"
    risk_attr = ' data-admin-risk="1"' if risk else ''
    return _card("Role Distribution", body, anchor="sec-roles", border_color=border) \
           .replace('<details', f'<details{risk_attr}', 1)


def _html_environment_inventory(env_data):
    if not env_data:
        return ""
    prod     = env_data.get("production", [])
    workshop = env_data.get("workshop", [])
    other    = env_data.get("other", [])
    total    = env_data.get("total", 0)
    noise    = env_data.get("noise_pct", 0)

    def env_list(envs, color):
        if not envs:
            return "<span style='color:#94a3b8;font-size:12px'>none</span>"
        return "".join(
            f'<span style="display:inline-block;background:{color}22;border:1px solid {color}44;'
            f'border-radius:6px;padding:2px 8px;margin:2px;font-size:11px;color:{color}">{e}</span>'
            for e in envs
        )

    body = f"""
    <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px">
      <div style="background:#f0fdf4;border-radius:8px;padding:10px 18px;text-align:center">
        <div style="font-size:22px;font-weight:700;color:#22c55e">{len(prod)}</div>
        <div style="font-size:11px;color:var(--muted)">Production</div>
      </div>
      <div style="background:var(--hover);border-radius:8px;padding:10px 18px;text-align:center">
        <div style="font-size:22px;font-weight:700;color:#6366f1">{len(other)}</div>
        <div style="font-size:11px;color:var(--muted)">Other/Custom</div>
      </div>
      <div style="background:#fff7ed;border-radius:8px;padding:10px 18px;text-align:center">
        <div style="font-size:22px;font-weight:700;color:#f97316">{len(workshop)}</div>
        <div style="font-size:11px;color:var(--muted)">Workshop/Test noise</div>
      </div>
    </div>
    {"<p style='background:#fff7ed;border-left:3px solid #f97316;padding:8px 12px;font-size:12px;border-radius:4px;margin-bottom:12px'>" + str(noise) + "% of environments appear to be workshop/test noise — consider filtering these from adoption metrics.</p>" if noise > 30 else ""}
    <h4 style="font-size:12px;margin:0 0 6px">Production</h4>
    <div style="margin-bottom:10px">{env_list(prod, "#22c55e")}</div>
    <h4 style="font-size:12px;margin:0 0 6px">Other / Custom</h4>
    <div style="margin-bottom:10px">{env_list(other, "#6366f1")}</div>
    <h4 style="font-size:12px;margin:0 0 6px">Workshop / Test (noise)</h4>
    <div>{env_list(workshop, "#f97316")}</div>"""
    return _card(f"Environment Inventory ({total} total)", body, anchor="sec-environments")


def _html_token_expiry_pipeline(tok_data):
    if not tok_data:
        return ""
    exp_90d   = tok_data.get("expiring_90d", [])
    scope_cnt = tok_data.get("scope_counts", {})
    missing   = tok_data.get("missing_pairs", [])

    scope_colors = {"INGEST": "#22c55e", "API": "#6366f1", "RUM": "#f97316"}
    scope_pills = "".join(
        f'<span style="background:{scope_colors.get(s,"#94a3b8")}22;border:1px solid {scope_colors.get(s,"#94a3b8")}44;'
        f'border-radius:6px;padding:3px 10px;margin-right:6px;font-size:12px;color:{scope_colors.get(s,"#64748b")};font-weight:700">'
        f'{s}: {cnt}</span>'
        for s, cnt in sorted(scope_cnt.items())
    )

    exp_rows = ""
    for t in exp_90d:
        dl   = t["days_left"]
        c    = "#ef4444" if dl < 7 else "#f97316" if dl < 30 else "#eab308"
        exp_rows += f"""
        <tr>
          <td style="font-size:12px">{t['name']}</td>
          <td style="font-size:12px;color:var(--muted)">{t['scopes']}</td>
          <td style="text-align:right"><span style="color:{c};font-weight:700">{dl}d</span></td>
        </tr>"""

    missing_html = ""
    if missing:
        missing_html = (f'<p style="background:#fff7ed;border-left:3px solid #f97316;padding:8px 12px;'
                        f'font-size:12px;border-radius:4px;margin-top:12px">'
                        f'<strong>{len(missing)} token group(s)</strong> have an INGEST token but no matching API token '
                        f'(incomplete setup): {", ".join(missing[:5])}{"..." if len(missing)>5 else ""}</p>')

    body = f"""
    <div style="margin-bottom:12px">{scope_pills or '<span style="color:#94a3b8">no tokens</span>'}</div>
    {"<h4 style='font-size:12px;margin:0 0 6px'>Expiring within 90 days</h4><table><thead><tr><th>Token</th><th>Scopes</th><th style='text-align:right'>Days Left</th></tr></thead><tbody>" + exp_rows + "</tbody></table>" if exp_rows else "<p style='font-size:12px;color:#22c55e'>No tokens expiring within 90 days.</p>"}
    {missing_html}"""
    border = "#ef4444" if exp_90d or missing else "#22c55e"
    return _card("Token Expiry & Scope Audit", body, anchor="sec-token-expiry", border_color=border)


def _html_detector_tag_coverage(tag_data):
    if not tag_data:
        return ""
    pct      = tag_data.get("tagged_pct", 0)
    untagged = tag_data.get("untagged", [])
    tag_freq = tag_data.get("tag_freq", {})

    c = "#22c55e" if pct >= 80 else "#eab308" if pct >= 40 else "#ef4444"
    bar = f"""
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:14px">
      <div style="flex:1;background:#e2e8f0;border-radius:6px;height:14px">
        <div style="background:{c};width:{pct}%;height:100%;border-radius:6px"></div>
      </div>
      <span style="font-weight:700;color:{c};min-width:45px">{pct}% tagged</span>
    </div>"""

    tag_pills = "".join(
        f'<span style="display:inline-block;background:#eef2ff;border-radius:6px;padding:2px 8px;'
        f'margin:2px;font-size:11px;color:#6366f1">{t} <strong>×{n}</strong></span>'
        for t, n in list(tag_freq.items())[:20]
    ) or "<span style='color:#94a3b8;font-size:12px'>no tags in use</span>"

    untagged_rows = ""
    for d in untagged[:20]:
        age_str = ""
        if d.get("lastUpdated"):
            days = int((int(time.time()*1000) - d["lastUpdated"]) / 86400000)
            age_str = f"{days}d ago"
        untagged_rows += f"<tr><td style='font-size:12px'>{d['name']}</td><td style='font-size:11px;color:var(--muted)'>{age_str}</td></tr>"
    if len(untagged) > 20:
        untagged_rows += f"<tr><td colspan='2' style='color:#94a3b8;font-size:11px'>... and {len(untagged)-20} more</td></tr>"

    body = bar
    body += f"<h4 style='font-size:12px;margin:0 0 6px'>Tags in use</h4><div style='margin-bottom:12px'>{tag_pills}</div>"
    if untagged_rows:
        body += f"""<h4 style='font-size:12px;margin:0 0 6px'>Untagged detectors ({len(untagged)})</h4>
    <table><thead><tr><th>Name</th><th>Last Updated</th></tr></thead><tbody>{untagged_rows}</tbody></table>"""
    border = "#22c55e" if pct >= 80 else "#eab308" if pct >= 40 else "#ef4444"
    return _card("Detector Tag Coverage", body, anchor="sec-det-tags", border_color=border)


def _html_silent_detectors_by_creator(creator_data):
    if not creator_data:
        return ""
    rows = ""
    for c in creator_data:
        pct  = round(c["silent_count"] / max(c["total_count"], 1) * 100)
        col  = "#ef4444" if pct == 100 else "#f97316" if pct >= 50 else "#eab308"
        det_names = ", ".join(d["name"] for d in c["detectors"][:3])
        if len(c["detectors"]) > 3:
            det_names += f" +{len(c['detectors'])-3} more"
        rows += f"""
        <tr>
          <td style="font-size:12px">{c['email']}</td>
          <td style="text-align:center"><span style="color:{col};font-weight:700">{c['silent_count']}</span> / {c['total_count']}</td>
          <td style="width:120px">
            <div style="background:#e2e8f0;border-radius:3px;height:8px">
              <div style="background:{col};width:{pct}%;height:100%;border-radius:3px"></div>
            </div>
          </td>
          <td style="font-size:11px;color:var(--muted)">{det_names}</td>
        </tr>"""
    body = f"""<p style="font-size:12px;color:var(--muted);margin-bottom:10px">
      Detectors with zero notification routing, grouped by creator — useful for targeted outreach.</p>
    <table>
      <thead><tr><th>Creator</th><th style="text-align:center">Silent / Total</th><th>%</th><th>Detectors</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>"""
    total_silent = sum(c["silent_count"] for c in creator_data)
    return _card("Silent Detectors by Creator", body, anchor="sec-silent-creators", border_color="#ef4444") \
           .replace('<details', f'<details data-silent-count="{total_silent}"', 1)


def _html_asset_age_distribution(age_data):
    if not age_data:
        return ""
    buckets   = age_data.get("buckets", [])
    det_dist  = age_data.get("detectors", {})
    dash_dist = age_data.get("dashboards", {})
    colors    = {"<30d": "#22c55e", "30–90d": "#84cc16", "90–180d": "#eab308", "180d–1yr": "#f97316", ">1yr": "#ef4444"}

    max_val = max([det_dist.get(b, 0) for b in buckets] + [dash_dist.get(b, 0) for b in buckets] + [1])

    rows = ""
    for b in buckets:
        dv = det_dist.get(b, 0)
        dav = dash_dist.get(b, 0)
        c  = colors.get(b, "#6366f1")
        dw  = min(round(dv  / max_val * 120), 120)
        daw = min(round(dav / max_val * 120), 120)
        rows += f"""
        <tr>
          <td style="font-size:12px;font-weight:600;color:{c}">{b}</td>
          <td>
            <div style="display:flex;align-items:center;gap:6px">
              <div style="background:#e2e8f0;border-radius:3px;height:8px;width:{dw}px"></div>
              <span style="font-size:12px;font-weight:700">{dv}</span>
            </div>
          </td>
          <td>
            <div style="display:flex;align-items:center;gap:6px">
              <div style="background:#e2e8f0;border-radius:3px;height:8px;width:{daw}px"></div>
              <span style="font-size:12px;font-weight:700">{dav}</span>
            </div>
          </td>
        </tr>"""

    body = f"""<table>
      <thead><tr><th>Age</th><th>Detectors</th><th>Dashboards</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>"""
    return _card("Asset Age Distribution", body, anchor="sec-asset-age")


def _html_executive_summary(org_health, recommended_actions, org_trends, users, assets, days):
    """Top-of-page TL;DR: grade, key signals, top actions."""
    total   = org_health["total"]
    grade   = "A" if total >= 80 else "B" if total >= 65 else "C" if total >= 50 else "D" if total >= 35 else "F"
    grade_color = {"A": "#22c55e", "B": "#84cc16", "C": "#eab308", "D": "#f97316", "F": "#ef4444"}[grade]

    # Key signals
    active  = sum(1 for u in users if u["active"])
    total_u = len(users)
    champions = sum(1 for u in users if u.get("user_tag") == "Champion")
    churning  = sum(1 for u in users if u.get("user_tag") == "Churning")

    # Trend arrows
    trend_html = ""
    for t in (org_trends or []):
        arrow = "▲" if t["direction"] == "up" else "▼" if t["direction"] == "down" else "→"
        c     = "#22c55e" if t["direction"] == "up" else "#ef4444" if t["direction"] == "down" else "#94a3b8"
        pct_str = f" ({t['pct']:+}%)" if t["pct"] is not None else ""
        anom  = ' <span style="background:#ef4444;color:#fff;padding:1px 5px;border-radius:6px;font-size:10px">ANOMALY</span>' if t["anomaly"] else ""
        trend_html += (f'<div style="display:inline-block;margin-right:24px">'
                       f'<span style="font-size:13px;color:var(--muted)">{t["metric"]}</span> '
                       f'<span style="font-weight:700;color:{c}">{arrow} {t["current"]}{pct_str}</span>'
                       f'{anom}</div>')

    # Top 3 actions
    top_actions = (recommended_actions or [])[:3]
    action_items = ""
    priority_colors = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#22c55e"}
    for a in top_actions:
        c = priority_colors.get(a["priority"], "#94a3b8")
        action_items += (f'<li style="margin-bottom:6px">'
                         f'<span style="background:{c};color:#fff;padding:1px 7px;border-radius:8px;font-size:10px;margin-right:6px">{a["priority"]}</span>'
                         f'<strong>{a["action"]}</strong>'
                         f'{"<br><span style=\'font-size:11px;color:var(--muted);margin-left:52px\'>" + a["detail"] + "</span>" if a["detail"] else ""}'
                         f'</li>')

    return f"""
  <div class="card" style="border-left:6px solid {grade_color};background:linear-gradient(135deg,var(--hover) 0%,var(--surface) 100%);color:var(--text)">
    <div style="display:flex;align-items:center;gap:24px;flex-wrap:wrap">
      <div style="text-align:center;min-width:80px">
        <div style="font-size:56px;font-weight:900;line-height:1;color:{grade_color}">{grade}</div>
        <div style="font-size:12px;color:var(--muted);margin-top:2px">Health Score</div>
        <div style="font-size:22px;font-weight:700;color:{grade_color}">{total}/100</div>
      </div>
      <div style="flex:1;min-width:200px;color:var(--text)">
        <div style="font-size:13px;color:var(--muted);margin-bottom:6px">
          <strong>{active}/{total_u}</strong> active users &nbsp;·&nbsp;
          <strong>{champions}</strong> Champions &nbsp;·&nbsp;
          <strong style="color:#ef4444">{churning}</strong> Churning
        </div>
        <div style="margin-bottom:10px">{trend_html}</div>
        {"<ul style='margin:0;padding-left:0;list-style:none;color:var(--text)'>" + action_items + "</ul>" if action_items else ""}
      </div>
    </div>
  </div>"""


def _html_recommended_actions(actions):
    if not actions:
        return ""
    priority_colors = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#22c55e"}
    rows = ""
    for a in actions:
        c = priority_colors.get(a["priority"], "#94a3b8")
        rows += f"""
        <tr>
          <td style="text-align:center"><span style="background:{c};color:#fff;padding:2px 8px;border-radius:9px;font-size:11px">{a['priority']}</span></td>
          <td style="font-size:12px;color:var(--muted)">{a['category']}</td>
          <td style="font-size:13px;font-weight:600">{a['action']}</td>
          <td style="font-size:11px;color:var(--muted)">{a.get('detail','')}</td>
        </tr>"""
    return f"""
  <div class="card">
    <h2>Recommended Actions</h2>
    <table>
      <thead><tr><th style="text-align:center">Priority</th><th>Category</th><th>Action</th><th>Detail</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>"""


def _html_user_funnel(funnel_stages):
    if not funnel_stages:
        return ""
    max_count = funnel_stages[0][1] if funnel_stages else 1
    bars = ""
    stage_colors = ["#3b82f6", "#6366f1", "#8b5cf6", "#a855f7", "#22c55e"]
    for i, (stage, count, pct) in enumerate(funnel_stages):
        w = round(count / max_count * 300) if max_count else 0
        c = stage_colors[i % len(stage_colors)]
        bars += f"""
        <tr>
          <td style="font-size:12px;width:130px">{stage}</td>
          <td>
            <div style="background:#e2e8f0;border-radius:4px;height:18px;width:300px;display:inline-block;vertical-align:middle;overflow:hidden">
              <div style="background:{c};width:{w}px;height:100%;border-radius:4px;display:flex;align-items:center;padding-left:6px">
                <span style="font-size:11px;color:#fff;font-weight:700;white-space:nowrap">{count}</span>
              </div>
            </div>
          </td>
          <td style="text-align:center;font-weight:700;color:{c}">{pct}%</td>
        </tr>"""
    return f"""
  <div class="card">
    <h2>User Journey Funnel</h2>
    <table style="border:none">
      <tbody>{bars}</tbody>
    </table>
  </div>"""


def _html_org_trends(org_trends):
    if not org_trends:
        return ""
    rows = ""
    for t in org_trends:
        arrow = "▲" if t["direction"] == "up" else "▼" if t["direction"] == "down" else "→"
        c     = "#22c55e" if t["direction"] == "up" else "#ef4444" if t["direction"] == "down" else "#94a3b8"
        pct_str = f"{t['pct']:+}%" if t["pct"] is not None else "—"
        anom  = (' <span style="background:#ef4444;color:#fff;padding:1px 6px;border-radius:8px;font-size:10px">ANOMALY</span>'
                 if t.get("anomaly") else "")
        rows += f"""
        <tr>
          <td style="font-size:13px">{t['metric']}</td>
          <td style="text-align:center;font-weight:700">{t['prior']}</td>
          <td style="text-align:center;font-weight:700">{t['current']}</td>
          <td style="text-align:center;font-weight:700;color:{c}">{arrow} {pct_str}{anom}</td>
        </tr>"""
    return f"""
  <div class="card">
    <h2>Trend Comparison <span style="font-size:12px;color:var(--muted);font-weight:400">— last 30d vs prior 30d</span></h2>
    <table>
      <thead><tr><th>Metric</th><th style="text-align:center">Prev 30d</th><th style="text-align:center">Last 30d</th><th style="text-align:center">Change</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>"""


def _html_detector_last_fired(det_fired):
    if not det_fired:
        return ""
    never = [d for d in det_fired if d["never_fired"]]
    stale = [d for d in det_fired if not d["never_fired"] and d["days_since"] and d["days_since"] > 90]
    rows = ""
    for d in det_fired[:30]:
        if d["never_fired"]:
            status, color = "never fired", "#ef4444"
        elif d["days_since"] and d["days_since"] > 90:
            status, color = f"{d['days_since']}d ago", "#eab308"
        else:
            status, color = f"{d['days_since']}d ago" if d["days_since"] else "recent", "#22c55e"
        rows += f"""
        <tr>
          <td style="font-size:12px">{d['name'][:65]}</td>
          <td style="text-align:center;font-weight:700;color:{color}">{status}</td>
        </tr>"""
    return f"""
  <div class="card">
    <h2>Detector Last Fired <span style="font-size:12px;color:var(--muted);font-weight:400">— {len(never)} never fired, {len(stale)} silent &gt;90d</span></h2>
    <table>
      <thead><tr><th>Detector</th><th style="text-align:center">Last Incident</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>"""


def _html_token_usage(tok_usage):
    if not tok_usage:
        return ""
    dormant  = tok_usage.get("dormant", [])
    never    = tok_usage.get("never_used", [])
    if not dormant and not never:
        return ""
    rows = ""
    for t in (dormant + never)[:20]:
        status = "dormant" if t in dormant else "never used"
        c = "#eab308" if status == "dormant" else "#ef4444"
        age_str = f"{t['age_days']}d" if t["age_days"] is not None else "—"
        rows += f"""
        <tr>
          <td style="font-size:12px">{t['name']}</td>
          <td style="text-align:center">{age_str}</td>
          <td style="font-size:11px;color:var(--muted)">{t['scopes']}</td>
          <td style="text-align:center"><span style="color:{c};font-weight:700">{status}</span></td>
        </tr>"""
    active_count = len(tok_usage.get("active", []))
    return f"""
  <div class="card">
    <h2>Token Usage Activity <span style="font-size:12px;color:var(--muted);font-weight:400">— {active_count} active, {len(dormant)} dormant, {len(never)} never used</span></h2>
    <table>
      <thead><tr><th>Token</th><th style="text-align:center">Age</th><th>Scopes</th><th style="text-align:center">Status</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>"""


def _html_apm_dependency_graph(graph_data):
    """Render APM dependency graph with optional trace fingerprint overlay."""
    if not graph_data or not graph_data["nodes"]:
        return ""
    nodes        = graph_data["nodes"]
    edges        = graph_data["edges"]
    fp_entries   = graph_data.get("fingerprints", [])
    baseline_env = graph_data.get("baseline_env")
    if len(nodes) < 2:
        return ""

    import math as _math
    n  = len(nodes)
    cx, cy, r = 360, 260, 190
    positions = {}
    for i, node in enumerate(nodes):
        angle = 2 * _math.pi * i / n - _math.pi / 2
        x = cx + r * _math.cos(angle)
        y = cy + r * _math.sin(angle)
        positions[node["id"]] = (round(x), round(y))

    has_weights = any(e.get("weight", 0) > 0 for e in edges)
    max_weight  = max((e.get("weight", 0) for e in edges), default=1) or 1

    # SVG edges — width and colour scaled by weight if available
    edge_svgs = []
    for e in edges:
        src, dst = e["from"], e["to"]
        if src not in positions or dst not in positions:
            continue
        x1, y1 = positions[src]
        x2, y2 = positions[dst]
        w   = e.get("weight", 0)
        pct = w / max_weight if has_weights and max_weight else 0
        stroke_w = round(1 + pct * 4, 1)  # 1px..5px
        # green→amber→red by relative weight
        if not has_weights or w == 0:
            stroke_c = "#cbd5e1"
        elif pct >= 0.6:
            stroke_c = "#22c55e"
        elif pct >= 0.2:
            stroke_c = "#f59e0b"
        else:
            stroke_c = "#94a3b8"
        edge_svgs.append(
            f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" '
            f'stroke="{stroke_c}" stroke-width="{stroke_w}" '
            f'marker-end="url(#arrow)" opacity="0.85">'
            f'<title>{src} → {dst}{"  (" + str(w) + " occurrences)" if w else ""}</title>'
            f'</line>'
        )

    # SVG nodes — size by fp_count if available
    node_svgs = []
    max_fp = max((nd.get("fp_count", 0) for nd in nodes), default=1) or 1
    for node in nodes:
        if node["id"] not in positions:
            continue
        x, y = positions[node["id"]]
        fp_c = node.get("fp_count", 0)
        base_r = 16 if node["hub"] else 12
        r_node = base_r + round(fp_c / max_fp * 8) if fp_entries else base_r

        if node["hub"]:
            color = "#3b82f6"
        elif node["inferred"]:
            color = "#94a3b8"
        elif fp_c > 0:
            color = "#6366f1"
        else:
            color = "#a5b4fc"

        label = node["label"][:16]
        fp_badge = f'<text x="{x}" y="{y+4}" text-anchor="middle" font-size="8" fill="#fff" font-weight="700">{fp_c}</text>' if fp_c > 0 else ""
        node_svgs.append(
            f'<circle cx="{x}" cy="{y}" r="{r_node}" fill="{color}" stroke="#fff" stroke-width="2" opacity="0.93">'
            f'<title>{node["id"]}{"  (" + str(fp_c) + " fingerprints)" if fp_c else ""}</title>'
            f'</circle>'
            f'{fp_badge}'
            f'<text x="{x}" y="{y + r_node + 13}" text-anchor="middle" font-size="9" fill="#475569">{label}</text>'
        )

    svg = f"""<svg width="720" height="520" style="max-width:100%;display:block">
      <defs>
        <marker id="arrow" viewBox="0 0 10 10" refX="26" refY="5"
                markerWidth="5" markerHeight="5" orient="auto-start-reverse">
          <path d="M 0 0 L 10 5 L 0 10 z" fill="#94a3b8"/>
        </marker>
      </defs>
      {''.join(edge_svgs)}
      {''.join(node_svgs)}
    </svg>"""

    real_count = sum(1 for nd in nodes if not nd["inferred"])
    inf_count  = sum(1 for nd in nodes if nd["inferred"])
    legend_parts = [
        f'<span style="color:#6366f1">●</span> Service ({real_count})',
        f'<span style="color:#3b82f6">●</span> Hub (high in-degree)',
    ]
    if inf_count:
        legend_parts.append(f'<span style="color:#94a3b8">●</span> Inferred / baseline-only ({inf_count})')
    if fp_entries:
        legend_parts.append(f'<span style="color:#6366f1"><strong>N</strong></span> = fingerprint count per node')
        legend_parts.append(f'<span style="color:#22c55e">━</span> high-traffic edge &nbsp;<span style="color:#f59e0b">━</span> medium &nbsp;<span style="color:#94a3b8">━</span> low')
    legend = f'<div style="font-size:11px;color:var(--muted);margin-top:6px">' + ' &nbsp;·&nbsp; '.join(legend_parts) + '</div>'

    # Fingerprint table
    fp_html = ""
    if fp_entries:
        env_badge = (f'<span style="background:#6366f122;color:#6366f1;border-radius:6px;padding:2px 8px;'
                     f'font-size:11px;margin-left:8px">{baseline_env}</span>') if baseline_env else ""
        fp_rows = ""
        for fp in fp_entries[:25]:
            svcs_str = " → ".join(dict.fromkeys(fp["services"]))  # dedupe consecutive
            promo_badge = ('<span style="background:#22c55e22;color:#22c55e;border-radius:4px;padding:1px 6px;font-size:10px">promoted</span>'
                           if fp["auto_promoted"] else
                           '<span style="background:#fff7ed;color:#f97316;border-radius:4px;padding:1px 6px;font-size:10px">watching</span>')
            hits = fp.get("watch_hits", 0)
            hits_str = f'<span style="color:#ef4444;font-weight:700">{hits} drift hits</span>' if hits else "—"
            fp_rows += f"""
            <tr>
              <td style="font-family:monospace;font-size:11px;color:var(--muted)">{fp['hash']}</td>
              <td style="font-size:11px">{fp['root_op']}</td>
              <td style="font-size:11px;color:var(--muted);max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{svcs_str}">{svcs_str}</td>
              <td style="text-align:right;font-size:12px">{fp['occurrences']:,}</td>
              <td style="text-align:center">{promo_badge}</td>
              <td style="text-align:center">{hits_str}</td>
            </tr>"""
        fp_html = f"""
        <h4 style="font-size:12px;margin:16px 0 6px">Trace Fingerprint Baseline {env_badge}
          <span style="font-size:11px;font-weight:400;color:#94a3b8">— {len(fp_entries)} known paths</span>
        </h4>
        <table>
          <thead><tr>
            <th>Hash</th><th>Root Operation</th><th>Service Path</th>
            <th style="text-align:right">Occurrences</th><th style="text-align:center">Status</th>
            <th style="text-align:center">Drift Hits</th>
          </tr></thead>
          <tbody>{fp_rows}</tbody>
        </table>"""

    baseline_note = ""
    if not fp_entries:
        baseline_note = ('<p style="font-size:12px;color:#94a3b8;margin-top:8px">'
                         'No trace fingerprint baseline loaded. Pass <code>--baseline path/to/baseline.json</code> '
                         'to overlay fingerprint data on this graph.</p>')

    return f"""
  <div class="card" id="sec-apm-graph" style="scroll-margin-top:52px">
    <h2>APM Service Dependency Graph</h2>
    {svg}
    {legend}
    {baseline_note}
    {fp_html}
  </div>"""


def _html_team_health(team_health):
    if not team_health:
        return ""
    rows = ""
    for t in team_health:
        hs = t["health_score"]
        c  = "#22c55e" if hs >= 70 else "#eab308" if hs >= 40 else "#ef4444"
        w  = min(hs, 100)
        rows += f"""
        <tr>
          <td style="font-size:12px;font-weight:600">{t['name']}</td>
          <td style="text-align:center">{t['member_count']}</td>
          <td style="text-align:center">{t['active_rate']}%</td>
          <td style="text-align:center">{t['avg_score']}</td>
          <td style="text-align:center">{t['detectors']}</td>
          <td style="text-align:center">{t['dashboards']}</td>
          <td>
            <div style="background:#e2e8f0;border-radius:3px;height:8px;width:{w}px;display:inline-block;vertical-align:middle">
              <div style="background:{c};width:100%;height:100%;border-radius:3px"></div>
            </div>
            <span style="font-size:12px;font-weight:700;color:{c};margin-left:6px">{hs}</span>
          </td>
        </tr>"""
    return f"""
  <div class="card">
    <h2>Team Health Scores</h2>
    <table>
      <thead><tr><th>Team</th><th style="text-align:center">Members</th><th style="text-align:center">Active%</th><th style="text-align:center">Avg Score</th><th style="text-align:center">Det</th><th style="text-align:center">Dash</th><th>Health Score</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>"""


def save_html(users, assets, otel, ownership, org_health, team_data,
              det_issues, tok_attr, detectors, dashboards, tokens,
              days, stale_days, realm, path=None, app_insights=None,
              cohort_data=None, feature_heatmap=None, muting_data=None,
              collab_data=None, product_adoption=None, integ_data=None,
              org_capacity=None, det_history=None, ingestion_trend=None,
              dash_complexity=None, det_svc_coverage=None, tok_scope_issues=None,
              incident_mtta=None, alert_fatigue=None, notif_routing=None,
              alert_routing_svc=None, data_volume=None, inactive_admin_risk=None,
              token_rotation=None, signalflow_usage=None, dash_sharing=None,
              detector_velocity=None, new_vs_returning=None, priv_escalation=None,
              slo_detectors=None, instrumentation=None, cardinality=None,
              recommended_actions=None, org_trends=None, user_funnel=None,
              det_last_fired=None, tok_usage=None, apm_graph=None,
              team_health=None,
              det_complexity=None, user_last_touched=None, dash_groups=None,
              notif_health=None, svc_error_rates=None, report_diff=None,
              orphaned_assets=None, sev_dist=None, onboarding_vel=None,
              role_dist=None, env_inventory=None, token_expiry_pipeline=None,
              det_tag_coverage=None, silent_by_creator=None, asset_age=None):
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
        utag_val   = u.get("user_tag", "")
        utag_colors = {"Champion": "#8b5cf6", "Automator": "#f59e0b", "Power Builder": "#3b82f6",
                       "Viewer": "#64748b", "Churning": "#ef4444", "Growing": "#22c55e",
                       "Inactive": "#94a3b8", "Active": "#10b981"}
        utag_html  = (f'<span style="background:{utag_colors.get(utag_val,"#64748b")};color:#fff;'
                      f'padding:1px 6px;border-radius:8px;font-size:10px">{utag_val}</span>'
                      if utag_val else "")
        tag  = " <small style='color:#94a3b8'>[admin]</small>" if u["admin"] else ""
        own  = ownership.get(u["email"], {})
        n_det  = len(own.get("detectors",  []))
        n_dash = len(own.get("dashboards", []))
        n_ch   = len(own.get("charts",     []))
        avg_dur = u.get("avg_session_min")
        dur_str = (f"{avg_dur:.0f}m" if avg_dur and avg_dur < 60
                   else f"{avg_dur/60:.1f}h" if avg_dur else "—")
        api_pct = u.get("api_pct")
        api_str = f"{api_pct}%" if api_pct is not None else "—"
        top_feat   = ", ".join(f[0] for f in u.get("top_features", [])[:3]) or "—"
        ttfv       = u.get("ttfv_days")
        ttfv_str   = f"{ttfv}d" if ttfv is not None else "—"
        ttfv_color = ("#22c55e" if ttfv is not None and ttfv <= 3
                      else "#eab308" if ttfv is not None and ttfv <= 14
                      else "#ef4444" if ttfv is not None else "#94a3b8")
        delta     = u.get("activity_delta", 0)
        delta_str = (f'<span style="color:#22c55e">▲{delta}</span>' if delta > 0
                     else f'<span style="color:#ef4444">▼{abs(delta)}</span>' if delta < 0
                     else "—")
        user_rows += f"""
        <tr>
          <td>{u['email']}{tag}<br>{utag_html}</td>
          <td style="text-align:center">
            <span style="font-weight:700;color:{sc_c}">{sc}</span><small>/100</small><br>
            {bar(sc, color=sc_c, height=4)}<br>
            <small style="color:#94a3b8">{delta_str} 30d</small>
          </td>
          <td>{ll}</td>
          <td>{la}</td>
          <td style="text-align:center">{u['login_count']}</td>
          <td style="text-align:center">{u.get('read_ops', 0)}</td>
          <td style="text-align:center">{u['write_ops']}</td>
          <td style="text-align:center">{dur_str}</td>
          <td style="text-align:center">{api_str}</td>
          <td style="text-align:center;color:{ttfv_color};font-weight:600">{ttfv_str}</td>
          <td style="text-align:center">{n_det}</td>
          <td style="text-align:center">{n_dash}</td>
          <td style="text-align:center">{n_ch}</td>
          <td style="font-size:11px;color:var(--muted)">{top_feat}</td>
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
        age_days = int((now_ms - (dd.get("lastUpdated") or 0)) / 86400000)
        age_str  = f'<span style="color:#ef4444;font-size:11px">{age_days}d ago</span>'
        stale_det_rows += f"<tr><td>{dd['name']}</td><td>{ts_to_str(dd.get('lastUpdated'))}</td><td>{age_str}</td><td>{dd.get('lastUpdatedBy','—')}</td></tr>"
    stale_dash_rows = ""
    for dd in sorted([d for d in dashboards if (now_ms - (d.get("lastUpdated") or 0)) > stale_ms],
                     key=lambda x: x.get("lastUpdated", 0))[:20]:
        age_days = int((now_ms - (dd.get("lastUpdated") or 0)) / 86400000)
        age_str  = f'<span style="color:#ef4444;font-size:11px">{age_days}d ago</span>'
        stale_dash_rows += f"<tr><td>{dd['name']}</td><td>{ts_to_str(dd.get('lastUpdated'))}</td><td>{age_str}</td><td>{dd.get('lastUpdatedBy','—')}</td></tr>"

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
        <div style="background:var(--hover);border:1px solid #e2e8f0;border-radius:8px;padding:16px;flex:1;min-width:180px">
          <div style="font-size:12px;color:var(--muted);margin-bottom:4px">{label}</div>
          <div style="font-size:22px;font-weight:700;color:{color}">{val}<span style="font-size:13px;color:#94a3b8">/{maxv}</span></div>
          <div style="background:#e2e8f0;border-radius:4px;height:8px;margin:8px 0">
            <div style="background:{color};width:{p}%;height:100%;border-radius:4px"></div>
          </div>
          <div style="font-size:11px;color:var(--muted)">{detail}</div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Splunk O11y Adoption Report — {realm}</title>
  <style>
    :root {{
      --bg: #f1f5f9; --surface: #fff; --border: #e2e8f0; --text: #1e293b;
      --muted: #64748b; --subtle: #94a3b8; --hover: #f8fafc; --input-bg: #fff;
    }}
    [data-theme="dark"] {{
      --bg: #0f172a; --surface: #1e293b; --border: #334155; --text: #f1f5f9;
      --muted: #94a3b8; --subtle: #64748b; --hover: #273549; --input-bg: #1e293b;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: var(--bg); color: var(--text); font-size: 14px; transition: background .2s, color .2s; }}
    /* Layout: sidebar + main */
    .layout {{ display: flex; gap: 0; min-height: 100vh; }}
    .sidebar {{
      width: 220px; min-width: 220px; background: var(--surface); border-right: 1px solid var(--border);
      padding: 16px 12px; position: sticky; top: 0; height: 100vh; overflow-y: auto;
      font-size: 12px; flex-shrink: 0;
    }}
    .sidebar h3 {{ font-size: 10px; font-weight: 700; text-transform: uppercase;
                  letter-spacing: .08em; color: var(--subtle); margin: 12px 0 4px; }}
    .sidebar a {{ display: block; padding: 4px 8px; border-radius: 6px; color: var(--muted);
                  text-decoration: none; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
    .sidebar a:hover {{ background: var(--hover); color: var(--text); }}
    .page {{ flex: 1; max-width: 1100px; padding: 24px; padding-top: 52px; }}
    /* Header */
    header {{ background: linear-gradient(135deg,#0f172a,#1e3a5f);
              color: #fff; border-radius: 12px; padding: 24px 28px; margin-bottom: 20px;
              display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; }}
    header h1 {{ font-size: 20px; font-weight: 700; margin-bottom: 4px; }}
    header p  {{ font-size: 12px; color: #94a3b8; }}
    .header-controls {{ display: flex; gap: 8px; align-items: center; flex-shrink: 0; }}
    /* Cards — now use <details> for collapsibility */
    .card {{ background: var(--surface); border-radius: 12px; border: 1px solid var(--border);
             padding: 20px 24px; margin-bottom: 16px; }}
    .card summary {{ outline: none; }}
    .card summary::-webkit-details-marker {{ display: none; }}
    .card[open] .toggle-icon::before {{ content: "▲"; }}
    .card:not([open]) .toggle-icon::before {{ content: "▼"; }}
    .card-title {{ font-size: 13px; font-weight: 700; text-transform: uppercase;
                   letter-spacing: .05em; color: var(--muted); }}
    /* Legacy .card h2 for non-collapsible cards */
    .card h2 {{ font-size: 13px; font-weight: 700; text-transform: uppercase;
                letter-spacing: .05em; color: var(--muted); margin-bottom: 14px;
                padding-bottom: 8px; border-bottom: 1px solid var(--border); }}
    .stat-grid {{ display: flex; gap: 14px; flex-wrap: wrap; margin-bottom: 4px; }}
    .stat {{ background: var(--hover); border: 1px solid var(--border); border-radius: 8px;
             padding: 12px 18px; text-align: center; min-width: 110px; }}
    .stat .val {{ font-size: 26px; font-weight: 800; color: var(--text); }}
    .stat .lbl {{ font-size: 10px; color: var(--subtle); margin-top: 2px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th {{ background: var(--hover); color: var(--muted); font-size: 10px; font-weight: 600;
          text-transform: uppercase; letter-spacing: .05em;
          padding: 7px 10px; text-align: left; border-bottom: 2px solid var(--border); }}
    td {{ padding: 8px 10px; border-bottom: 1px solid var(--border); vertical-align: middle;
          color: var(--text); }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: var(--hover); }}
    .big-score {{ font-size: 52px; font-weight: 900; color: {grade_color}; line-height: 1; }}
    .grade {{ display: inline-block; background: {grade_color}; color: #fff;
              font-size: 24px; font-weight: 900; width: 48px; height: 48px;
              border-radius: 50%; text-align: center; line-height: 48px; margin-left: 12px; }}
    .dim-row {{ display: flex; gap: 12px; flex-wrap: wrap; }}
    .section-note {{ font-size: 11px; color: var(--subtle); margin-top: 12px; font-style: italic; }}
    /* Offset anchor targets so sticky bar doesn't cover the section header */
    details[id], div[id^="sec-"], .card[id] {{ scroll-margin-top: 52px; }}
    /* Search box */
    #search-box {{
      width: 100%; padding: 6px 10px; border: 1px solid var(--border); border-radius: 8px;
      font-size: 12px; background: var(--input-bg); color: var(--text); margin-bottom: 8px;
    }}
    .search-hide {{ display: none !important; }}
    /* Dark mode toggle button */
    .btn-toggle {{
      background: rgba(255,255,255,.15); border: 1px solid rgba(255,255,255,.3);
      color: #fff; border-radius: 8px; padding: 5px 12px; font-size: 12px;
      cursor: pointer; white-space: nowrap;
    }}
    .btn-toggle:hover {{ background: rgba(255,255,255,.25); }}
    /* Print styles */
    @media print {{
      body {{ background: #fff; color: #000; font-size: 11px; }}
      .sidebar, .header-controls, #search-box, #sticky-bar {{ display: none !important; }}
      .layout {{ display: block; }}
      .page {{ max-width: 100%; padding: 0; }}
      .card {{ break-inside: avoid; border: 1px solid #ccc; margin-bottom: 10px;
               box-shadow: none; }}
      header {{ background: #0f172a; -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
      details[class="card"] {{ display: block; }}
      details summary {{ display: none; }}
      details .card-body {{ display: block !important; margin-top: 0; }}
      .card h2, .card-title {{ color: #333; }}
      th {{ background: #eee; }}
      tr:hover td {{ background: transparent; }}
    }}
    /* Sticky summary bar */
    #sticky-bar {{
      position: fixed; top: 0; left: 0; right: 0; z-index: 999;
      background: #0f172a; color: #fff; padding: 6px 20px;
      display: flex; align-items: center; gap: 20px; font-size: 12px;
      box-shadow: 0 2px 8px rgba(0,0,0,.3); transition: transform .2s;
    }}
    #sticky-bar.hidden {{ transform: translateY(-100%); }}
    #sticky-bar .sb-grade {{ font-size:18px; font-weight:900; }}
    #sticky-bar .sb-sep   {{ color: #475569; }}
    #sticky-bar .sb-risk  {{ background:#ef4444; border-radius:6px; padding:2px 8px; font-size:11px; font-weight:700; }}
    #sticky-bar .sb-warn  {{ background:#f97316; border-radius:6px; padding:2px 8px; font-size:11px; font-weight:700; }}
    #sticky-bar .sb-close {{ margin-left:auto; cursor:pointer; color:#94a3b8; font-size:16px; line-height:1; }}
    @media (max-width: 768px) {{
      .sidebar {{ display: none; }}
      .layout {{ display: block; }}
      #sticky-bar {{ display: none; }}
    }}
    @media print {{
      #sticky-bar {{ display: none !important; }}
    }}
  </style>
</head>
<body>

  <!-- STICKY SUMMARY BAR -->
  <div id="sticky-bar">
    <span class="sb-grade" style="color:{grade_color}">{grade}</span>
    <span style="color:#94a3b8">{total}/100</span>
    <span class="sb-sep">|</span>
    <span>{sum(1 for u in users if u.get('active', False))}/{len(users)} active users</span>
    <span class="sb-sep">|</span>
    <span>{assets['detectors']['stale']} stale detectors</span>
    <span class="sb-sep">|</span>
    <span id="sb-flags"></span>
    <span class="sb-close" onclick="document.getElementById('sticky-bar').classList.add('hidden')" title="Dismiss">✕</span>
  </div>

<div class="layout">

  <!-- NAVIGATION SIDEBAR — populated by JS after render -->
  <nav class="sidebar" id="sidebar">
    <div style="font-size:13px;font-weight:700;color:var(--text);margin-bottom:12px">Sections</div>
    <input id="search-box" type="text" placeholder="Search report..." oninput="filterReport(this.value)">
    <div id="nav-links"></div>
  </nav>

  <div class="page">
  <header>
    <div>
      <h1>Splunk Observability Cloud — Adoption Report</h1>
      <p>realm={realm} &nbsp;|&nbsp; generated {now_str} &nbsp;|&nbsp; activity window: last {days} days</p>
    </div>
    <div class="header-controls">
      <button class="btn-toggle" onclick="toggleDark()">🌙 Dark mode</button>
      <button class="btn-toggle" onclick="window.print()">🖨 Print</button>
    </div>
  </header>

  <!-- EXECUTIVE SUMMARY -->
  {_html_executive_summary(org_health, recommended_actions, org_trends, users, assets, days) if recommended_actions is not None else ''}

  <!-- RECOMMENDED ACTIONS -->
  {_html_recommended_actions(recommended_actions) if recommended_actions else ''}

  <!-- ORG HEALTH SCORE -->
  <div class="card" id="sec-health">
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
  <div class="card" id="sec-platform">
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
  <div class="card" id="sec-otel">
    <h2>OTel &amp; Signal Adoption</h2>
    <div class="stat-grid" style="margin-bottom:20px">
      <div class="stat"><div class="val">{otel['apm_count']}</div><div class="lbl">APM Services</div></div>
      <div class="stat"><div class="val">{otel['sdk_count']}</div><div class="lbl">Instrumented Services</div></div>
      <div class="stat"><div class="val">{'1' if otel['collector'] else '0'}</div><div class="lbl">OTel Collector</div></div>
    </div>
    <div style="margin-top:12px;font-size:13px;color:var(--muted)">
      <b>Languages:</b> {', '.join(otel['languages']) if otel['languages'] else 'none detected'}
      &nbsp;&nbsp; <b>SDK names:</b> {', '.join(otel['sdk_names']) if otel['sdk_names'] else 'none detected'}
    </div>
  </div>

  <!-- APPLICATION INSIGHTS -->
  {_html_app_insights(app_insights) if app_insights and app_insights.get('service_count', 0) > 0 else ''}

  <!-- USER ACTIVITY -->
  <div class="card" id="sec-activity">
    <h2>User Activity</h2>
    <div style="overflow-x:auto">
    <table>
      <thead><tr>
        <th>User / Tag</th><th>Score / Δ30d</th><th>Last Login</th><th>Last Activity</th>
        <th style="text-align:center">Logins</th>
        <th style="text-align:center">Reads</th>
        <th style="text-align:center">Writes</th>
        <th style="text-align:center">Avg Session</th>
        <th style="text-align:center">API%</th>
        <th style="text-align:center">TTFV</th>
        <th style="text-align:center">Det</th><th style="text-align:center">Dash</th><th style="text-align:center">Charts</th>
        <th>Top Features</th>
      </tr></thead>
      <tbody>{user_rows}</tbody>
    </table>
    </div>
  </div>

  {'<!-- TEAM ROLLUP --><div class="card"><h2>Team Rollup</h2><table><thead><tr><th>Team</th><th style="text-align:center">Members</th><th style="text-align:center">Active</th><th style="text-align:center">Avg Score</th><th style="text-align:center">Logins</th><th style="text-align:center">Writes</th><th style="text-align:center">Det</th><th style="text-align:center">Dash</th><th style="text-align:center">Charts</th></tr></thead><tbody>' + team_rows + '</tbody></table></div>' if team_rows else ''}

  <!-- DETECTOR HEALTH -->
  {'<div class="card"><h2>Detector Health Issues</h2><table><thead><tr><th>Detector</th><th>Last Updated</th><th>Flags</th></tr></thead><tbody>' + det_rows + '</tbody></table></div>' if det_rows else ''}

  <!-- TOKEN ATTRIBUTION -->
  {'<div class="card"><h2>Token Attribution</h2><table><thead><tr><th>Token</th><th>Scopes</th><th style="text-align:center">Users</th><th>Attributed To</th></tr></thead><tbody>' + tok_rows + '</tbody></table></div>' if tok_rows else ''}

  <!-- TOKEN ALERTS -->
  {'<div class="card"><h2>Token Alerts</h2><table><thead><tr><th>Token</th><th>Status</th><th>Expiry</th></tr></thead><tbody>' + tok_alert_rows + '</tbody></table></div>' if tok_alert_rows else ''}

  <!-- STALE DETECTORS -->
  {'<div class="card"><h2>Stale Detectors (not updated in >' + str(stale_days) + 'd)</h2><table><thead><tr><th>Name</th><th>Last Updated</th><th>Age</th><th>Last Modified By</th></tr></thead><tbody>' + stale_det_rows + '</tbody></table></div>' if stale_det_rows else ''}

  <!-- STALE DASHBOARDS -->
  {'<div class="card"><h2>Stale Dashboards (not updated in >' + str(stale_days) + 'd)</h2><table><thead><tr><th>Name</th><th>Last Updated</th><th>Age</th><th>Last Modified By</th></tr></thead><tbody>' + stale_dash_rows + '</tbody></table></div>' if stale_dash_rows else ''}

  <!-- PRODUCT ADOPTION -->
  <div id="sec-product">{_html_product_adoption(product_adoption) if product_adoption else ''}</div>

  <!-- INTEGRATION COVERAGE -->
  <div id="sec-integ">{_html_integration_coverage(integ_data) if integ_data else ''}</div>

  <!-- ORG CAPACITY -->
  <div id="sec-capacity">{_html_org_capacity(org_capacity) if org_capacity else ''}</div>

  <!-- DETECTOR ALERT HISTORY -->
  <div id="sec-det-history">{_html_detector_alert_history(det_history) if det_history else ''}</div>

  <!-- DETECTOR SERVICE COVERAGE -->
  <div id="sec-det-svc">{_html_detector_service_coverage(det_svc_coverage) if det_svc_coverage else ''}</div>

  <!-- DATA INGESTION TREND -->
  {_html_ingestion_trend(ingestion_trend) if ingestion_trend else ''}

  <!-- DASHBOARD COMPLEXITY -->
  <div id="sec-dash-complexity">{_html_dashboard_complexity(dash_complexity) if dash_complexity else ''}</div>

  <!-- TOKEN SCOPE HYGIENE -->
  <div id="sec-tok-hygiene">{_html_token_scope_hygiene(tok_scope_issues) if tok_scope_issues else ''}</div>

  <!-- FEATURE HEATMAP -->
  <div id="sec-heatmap">{_html_feature_heatmap(feature_heatmap, users) if feature_heatmap else ''}</div>

  <!-- COHORT RETENTION -->
  <div id="sec-cohort">{_html_cohort_table(cohort_data) if cohort_data else ''}</div>

  <!-- TIME TO FIRST VALUE -->
  <div id="sec-ttfv">{_html_ttfv(users)}</div>

  <!-- ENGAGEMENT TREND -->
  <div id="sec-engagement">{_html_engagement_trend(users)}</div>

  <!-- SESSION DURATION -->
  {_html_session_duration(users)}

  <!-- API VS UI -->
  {_html_api_vs_ui(users)}

  <!-- MUTING ACTIVITY -->
  {_html_muting_activity(muting_data) if muting_data else ''}

  <!-- COLLABORATION -->
  <div id="sec-collab">{_html_collaboration(collab_data) if collab_data else ''}</div>

  <!-- ACTIVITY TREND -->
  {_html_activity_trend(users)}

  <!-- USER FUNNEL -->
  <div id="sec-funnel">{_html_user_funnel(user_funnel) if user_funnel else ''}</div>

  <!-- ORG TRENDS -->
  <div id="sec-trends">{_html_org_trends(org_trends) if org_trends else ''}</div>

  <!-- APM DEPENDENCY GRAPH -->
  <div id="sec-apm-graph">{_html_apm_dependency_graph(apm_graph) if apm_graph and apm_graph.get('nodes') else ''}</div>

  <!-- TEAM HEALTH -->
  <div id="sec-team-health">{_html_team_health(team_health) if team_health else ''}</div>

  <!-- DETECTOR LAST FIRED -->
  <div id="sec-last-fired">{_html_detector_last_fired(det_last_fired) if det_last_fired else ''}</div>

  <!-- TOKEN USAGE -->
  <div id="sec-tok-usage">{_html_token_usage(tok_usage) if tok_usage else ''}</div>

  <!-- NEW VS RETURNING -->
  <div id="sec-new-returning">{_html_new_vs_returning(new_vs_returning) if new_vs_returning else ''}</div>

  <!-- INCIDENT MTTA -->
  <div id="sec-mtta">{_html_incident_mtta(incident_mtta) if incident_mtta else ''}</div>

  <!-- ALERT FATIGUE -->
  <div id="sec-fatigue">{_html_alert_fatigue(alert_fatigue) if alert_fatigue else ''}</div>

  <!-- DETECTOR NOTIFICATION ROUTING -->
  <div id="sec-notif-routing">{_html_detector_notification_routing(notif_routing) if notif_routing else ''}</div>

  <!-- ALERT ROUTING BY SERVICE -->
  <div id="sec-routing-svc">{_html_alert_routing_by_service(alert_routing_svc) if alert_routing_svc else ''}</div>

  <!-- SLO DETECTORS -->
  <div id="sec-slo">{_html_slo_detectors(slo_detectors) if slo_detectors else ''}</div>

  <!-- DETECTOR CREATION VELOCITY -->
  <div id="sec-det-vel">{_html_detector_creation_velocity(detector_velocity) if detector_velocity else ''}</div>

  <!-- SIGNALFLOW USAGE -->
  <div id="sec-sf-usage">{_html_signalflow_usage(signalflow_usage) if signalflow_usage else ''}</div>

  <!-- DASHBOARD SHARING -->
  <div id="sec-dash-sharing">{_html_dashboard_sharing(dash_sharing) if dash_sharing else ''}</div>

  <!-- DATA VOLUME BY PRODUCT -->
  <div id="sec-data-volume">{_html_data_volume_by_product(data_volume) if data_volume else ''}</div>

  <!-- CARDINALITY HOTSPOTS -->
  <div id="sec-cardinality">{_html_cardinality_hotspots(cardinality) if cardinality else ''}</div>

  <!-- INSTRUMENTATION COMPLETENESS -->
  <div id="sec-instrumentation">{_html_instrumentation_completeness(instrumentation) if instrumentation else ''}</div>

  <!-- TOKEN ROTATION -->
  <div id="sec-tok-rotation">{_html_token_rotation(token_rotation) if token_rotation else ''}</div>

  <!-- INACTIVE ADMIN RISK -->
  <div id="sec-inactive-admin">{_html_inactive_admin_risk(inactive_admin_risk) if inactive_admin_risk else ''}</div>

  <!-- PRIVILEGE ESCALATION -->
  <div id="sec-priv-esc">{_html_privilege_escalation(priv_escalation) if priv_escalation else ''}</div>

  <!-- REPORT DIFF / CHANGELOG -->
  {_html_report_diff(report_diff) if report_diff else ''}

  <!-- ORPHANED ASSETS -->
  {_html_orphaned_assets(orphaned_assets) if orphaned_assets else ''}

  <!-- ALERT SEVERITY DISTRIBUTION -->
  {_html_alert_severity_dist(sev_dist) if sev_dist else ''}

  <!-- ONBOARDING VELOCITY -->
  {_html_onboarding_velocity(onboarding_vel) if onboarding_vel else ''}

  <!-- DETECTOR COMPLEXITY -->
  {_html_detector_complexity(det_complexity) if det_complexity else ''}

  <!-- USER LAST TOUCHED -->
  {_html_user_last_touched(user_last_touched, users) if user_last_touched else ''}

  <!-- DASHBOARD GROUPS -->
  {_html_dashboard_groups(dash_groups) if dash_groups else ''}

  <!-- NOTIFICATION HEALTH -->
  {_html_notification_health(notif_health) if notif_health and notif_health.get('broken_integrations') else ''}

  <!-- SERVICE ERROR RATES -->
  {_html_service_error_rates(svc_error_rates) if svc_error_rates else ''}

  <!-- ROLE DISTRIBUTION -->
  {_html_role_distribution(role_dist) if role_dist else ''}

  <!-- ENVIRONMENT INVENTORY -->
  {_html_environment_inventory(env_inventory) if env_inventory else ''}

  <!-- TOKEN EXPIRY PIPELINE -->
  {_html_token_expiry_pipeline(token_expiry_pipeline) if token_expiry_pipeline else ''}

  <!-- DETECTOR TAG COVERAGE -->
  {_html_detector_tag_coverage(det_tag_coverage) if det_tag_coverage else ''}

  <!-- SILENT DETECTORS BY CREATOR -->
  {_html_silent_detectors_by_creator(silent_by_creator) if silent_by_creator else ''}

  <!-- ASSET AGE DISTRIBUTION -->
  {_html_asset_age_distribution(asset_age) if asset_age else ''}

  <p class="section-note">Generated by o11y-adoption &nbsp;|&nbsp; Write activity tracked via HttpRequest audit events. Session duration from session created/deleted pairs.</p>
  </div><!-- end .page -->
</div><!-- end .layout -->

<script>
// Sticky bar: populate risk flags from page content
(function() {{
  const flags = document.getElementById('sb-flags');
  if (!flags) return;
  const chips = [];
  // Silent detectors
  const silentEl = document.querySelector('[data-silent-count]');
  if (silentEl) chips.push(`<span class="sb-risk">${{silentEl.dataset.silentCount}} silent detectors</span>`);
  // Admin risk
  const adminEl = document.querySelector('[data-admin-risk]');
  if (adminEl) chips.push(`<span class="sb-warn">admin-heavy org</span>`);
  flags.innerHTML = chips.join(' ');
}})();

// Dark mode toggle
function toggleDark() {{
  const html = document.documentElement;
  const dark = html.getAttribute('data-theme') !== 'dark';
  html.setAttribute('data-theme', dark ? 'dark' : 'light');
  document.querySelectorAll('.btn-toggle').forEach(b => {{
    if (b.textContent.includes('Dark') || b.textContent.includes('Light'))
      b.textContent = dark ? '☀ Light mode' : '🌙 Dark mode';
  }});
}}

// Search / filter: hide table rows not matching query
function filterReport(query) {{
  const q = query.toLowerCase().trim();
  document.querySelectorAll('tbody tr').forEach(row => {{
    row.classList.toggle('search-hide', q && !row.textContent.toLowerCase().includes(q));
  }});
}}

// Build sidebar dynamically — only show links for sections that have visible content
document.addEventListener('DOMContentLoaded', function() {{
  // Section metadata: id -> [group, label]
  const sections = [
    ['sec-health',         'Overview',            'Org Health'],
    ['sec-platform',       'Overview',            'Platform Overview'],
    ['sec-diff',           'Overview',            'Changelog'],
    ['sec-trends',         'Overview',            'Org Trends'],
    ['sec-actions',        'Overview',            'Recommended Actions'],
    ['sec-funnel',         'Users',               'User Funnel'],
    ['sec-activity',       'Users',               'User Activity'],
    ['sec-last-touched',   'Users',               'Last Asset Touched'],
    ['sec-ttfv',           'Users',               'Time to First Value'],
    ['sec-onboarding-vel', 'Users',               'Onboarding Velocity'],
    ['sec-cohort',         'Users',               'Cohort Retention'],
    ['sec-new-returning',  'Users',               'New vs Returning'],
    ['sec-heatmap',        'Users',               'Feature Heatmap'],
    ['sec-engagement',     'Users',               'Engagement Trend'],
    ['sec-mtta',           'Alerting',            'Incident MTTA'],
    ['sec-fatigue',        'Alerting',            'Alert Fatigue'],
    ['sec-severity',       'Alerting',            'Alert Severity Distribution'],
    ['sec-notif-routing',  'Alerting',            'Notification Routing'],
    ['sec-notif-health',   'Alerting',            'Notification Health'],
    ['sec-routing-svc',    'Alerting',            'Routing by Service'],
    ['sec-det-history',    'Alerting',            'Detector Alert History'],
    ['sec-last-fired',     'Alerting',            'Detector Last Fired'],
    ['sec-det-complexity', 'Alerting',            'Detector Complexity'],
    ['sec-det-vel',        'Alerting',            'Detector Velocity'],
    ['sec-slo',            'Alerting',            'SLO Detectors'],
    ['sec-otel',           'APM & Signals',       'OTel & Signal Adoption'],
    ['sec-app-insights',   'APM & Signals',       'Application Insights'],
    ['sec-product',        'APM & Signals',       'Product Adoption'],
    ['sec-svc-errors',     'APM & Signals',       'Service Error Rates'],
    ['sec-det-svc',        'APM & Signals',       'Detector Service Coverage'],
    ['sec-instrumentation','APM & Signals',       'Instrumentation'],
    ['sec-apm-graph',      'APM & Signals',       'APM Dependency Graph'],
    ['sec-cardinality',    'APM & Signals',       'Cardinality Hotspots'],
    ['sec-data-volume',    'APM & Signals',       'Data Volume'],
    ['sec-orphaned',       'Assets',              'Orphaned Assets'],
    ['sec-dash-groups',    'Assets',              'Dashboard Groups'],
    ['sec-dash-sharing',   'Assets',              'Dashboard Sharing'],
    ['sec-dash-complexity','Assets',              'Dashboard Complexity'],
    ['sec-collab',         'Assets',              'Collaboration'],
    ['sec-priv-esc',       'Security',            'Privilege Escalation'],
    ['sec-inactive-admin', 'Security',            'Inactive Admins'],
    ['sec-tok-rotation',   'Security',            'Token Rotation'],
    ['sec-tok-usage',      'Security',            'Token Usage'],
    ['sec-tok-hygiene',    'Security',            'Token Hygiene'],
    ['sec-roles',          'Security',            'Role Distribution'],
    ['sec-token-expiry',   'Security',            'Token Expiry & Scope'],
    ['sec-team-health',    'Teams & Integrations','Team Health'],
    ['sec-integ',          'Teams & Integrations','Integrations'],
    ['sec-capacity',       'Teams & Integrations','Org Capacity'],
    ['sec-sf-usage',       'Teams & Integrations','SignalFlow Usage'],
    ['sec-environments',   'Platform',            'Environment Inventory'],
    ['sec-det-tags',       'Platform',            'Detector Tag Coverage'],
    ['sec-silent-creators','Platform',            'Silent Detectors by Creator'],
    ['sec-asset-age',      'Platform',            'Asset Age Distribution'],
  ];

  const nav = document.getElementById('nav-links');
  let currentGroup = '';
  sections.forEach(([id, group, label]) => {{
    const el = document.getElementById(id);
    if (!el) return;
    // Check the element has meaningful content (not just whitespace/empty wrappers)
    const text = el.innerText.replace(/\\s/g, '');
    if (!text) return;
    if (group !== currentGroup) {{
      const h = document.createElement('h3');
      h.textContent = group;
      nav.appendChild(h);
      currentGroup = group;
    }}
    const a = document.createElement('a');
    a.href = '#' + id;
    a.textContent = label;
    nav.appendChild(a);
  }});

  // Highlight active section on scroll
  const allAnchors = nav.querySelectorAll('a[href^="#"]');
  const observer = new IntersectionObserver(entries => {{
    entries.forEach(e => {{
      if (e.isIntersecting) {{
        allAnchors.forEach(a => a.style.fontWeight = '');
        const active = nav.querySelector('a[href="#' + e.target.id + '"]');
        if (active) active.style.fontWeight = '700';
      }}
    }});
  }}, {{ threshold: 0.3 }});
  sections.forEach(([id]) => {{
    const el = document.getElementById(id);
    if (el && el.innerText.replace(/\\s/g, '')) observer.observe(el);
  }});

  // Collapsible toggle icons
  document.querySelectorAll('details.card').forEach(det => {{
    det.addEventListener('toggle', () => {{
      const icon = det.querySelector('.toggle-icon');
      if (icon) icon.textContent = det.open ? '▲' : '▼';
    }});
  }});
}});
</script>
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
                 apm_nodes=None, apm_edges=None, environments=None, svc_lang_map=None,
                 svc_envs=None, muting_rules=None, incidents=None, integrations=None,
                 org_data=None, chart_counts=None, ingestion_raw=None,
                 incidents_enriched=None, top_mts=None, data_volume_raw=None,
                 baseline_path=None):

    users           = analyze_users(members, session_events, http_events, days)
    assets          = analyze_assets(detectors, dashboards, charts, tokens, stale_days)
    otel            = analyze_otel(otel_services, apm_services)
    ownership       = analyze_asset_ownership(detectors, dashboards, charts, members)
    org_health      = compute_org_health(users, assets, otel, days)
    det_issues      = analyze_detector_health(detectors, tokens, muting_rules=muting_rules)
    tok_attr        = analyze_token_attribution(session_events, members, tokens)
    app_insights    = analyze_app_insights(
        apm_nodes or apm_services, apm_edges or [], otel_services,
        svc_lang_map or {}, environments or [], svc_envs=svc_envs or {}
    )
    # Engagement scores + tags
    for u in users:
        u["engagement_score"] = score_user_engagement(u, ownership, days)
        u["user_tag"]         = tag_user(u, ownership, u["engagement_score"])

    cohort_data      = analyze_cohorts(users, days)
    feature_heatmap  = analyze_feature_heatmap(users)
    muting_data      = analyze_muting_activity(users, muting_rules or [])
    collab_data      = analyze_collaboration(users, detectors, dashboards, charts, members)
    det_history      = analyze_detector_alert_history(detectors, incidents or [])
    product_adoption = analyze_product_adoption(otel_services, integrations or [], http_events, apm_services=apm_services)
    integ_data       = analyze_integration_coverage(integrations or [])
    org_capacity     = analyze_org_capacity(org_data or {})
    dash_complexity  = analyze_dashboard_complexity(dashboards, chart_counts or {})
    det_svc_coverage = analyze_detector_service_coverage(detectors, apm_services, members)
    tok_scope_issues = analyze_token_scope_hygiene(tokens, users)
    ingestion_trend  = analyze_ingestion_trend(ingestion_raw or [])

    # New analysis batch
    incidents_enr    = incidents_enriched or []
    incident_mtta    = analyze_incident_mtta(incidents_enr, members) if incidents_enr else None
    alert_fatigue    = analyze_alert_fatigue(incidents_enr, users, days) if incidents_enr else None
    notif_routing    = analyze_detector_notification_routing(detectors)
    alert_routing_svc = analyze_alert_routing_by_service(detectors, apm_services, members)
    data_volume      = analyze_data_volume_by_product(data_volume_raw or {})
    inactive_admin_risk = analyze_inactive_admin_risk(users, tokens)
    token_rotation   = analyze_token_rotation(tokens)
    signalflow_usage = analyze_signalflow_usage(http_events, members)
    dash_sharing     = analyze_dashboard_sharing(http_events, dashboards, members)
    detector_velocity = analyze_detector_creation_velocity(detectors)
    new_vs_returning = analyze_new_vs_returning(users, days)
    priv_escalation  = analyze_privilege_escalation(members, http_events)
    slo_detectors    = analyze_slo_detectors(detectors)
    instrumentation  = analyze_instrumentation_completeness(apm_services, otel_services, integrations or [], http_events)
    cardinality      = analyze_cardinality_hotspots(top_mts or [])

    # Additional new analyses
    det_last_fired   = analyze_detector_last_fired(detectors, incidents_enr)
    tok_usage        = analyze_token_usage(tokens, http_events)
    apm_graph        = analyze_apm_dependency_graph(apm_nodes or [], apm_edges or [],
                                                   baseline_path=baseline_path)
    org_trends       = analyze_org_trends(users, assets, detectors)

    now_str      = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    width        = 110

    team_data    = analyze_teams(teams or [], members, users, ownership) if teams else []
    team_health  = analyze_team_health(team_data, det_svc_coverage, alert_routing_svc)
    user_funnel  = analyze_user_funnel(users, ownership)

    # New analyses — must run before recommended_actions
    role_dist             = analyze_role_distribution(members)
    env_inventory         = analyze_environment_inventory(environments or [], apm_nodes or [], apm_edges or [])
    token_expiry_pipeline = analyze_token_expiry_pipeline(tokens)
    det_tag_coverage      = analyze_detector_tag_coverage(detectors)
    silent_by_creator     = analyze_silent_detectors_by_creator(detectors, members)
    asset_age             = analyze_asset_age_distribution(detectors, dashboards)

    recommended_actions = analyze_recommended_actions(
        users, assets, det_issues, tok_scope_issues,
        inactive_admin_risk, token_rotation, notif_routing,
        det_svc_coverage, instrumentation, priv_escalation,
        slo_detectors, alert_fatigue,
        role_dist=role_dist,
        token_expiry_pipeline=token_expiry_pipeline,
        det_tag_coverage=det_tag_coverage,
    )

    # New batch of analyses (#6–#15)
    det_complexity    = analyze_detector_complexity(detectors)
    user_last_touched = analyze_user_last_touched(users, detectors, dashboards)
    dash_groups       = analyze_dashboard_groups(dashboards)
    notif_health      = analyze_notification_health(integrations or [], detectors)
    svc_error_rates   = []   # populated below if apm_services available — skip SignalFlow here (costly)
    report_diff       = analyze_report_diff(users, detectors, dashboards)
    orphaned_assets   = analyze_orphaned_assets(detectors, dashboards, charts, members)
    sev_dist          = analyze_alert_severity_distribution(incidents_enr)
    onboarding_vel    = analyze_onboarding_velocity(users)

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
        # Environment breakdown by category
        ec = ai["env_categories"]
        if ai["environments"]:
            print(f"  Environments ({len(ai['environments'])} total):")
            if ec["production"]:
                print(f"    Production:  {', '.join(ec['production'])}")
            if ec["staging"]:
                print(f"    Staging:     {', '.join(ec['staging'])}")
            if ec["dev"]:
                print(f"    Dev:         {', '.join(ec['dev'])}")
            if ec["other"]:
                print(f"    Other:       {', '.join(sorted(ec['other']))}")
            if ec["workshop"]:
                print(f"    Workshop:    {len(ec['workshop'])} envs  ({', '.join(sorted(ec['workshop'])[:4])}{'...' if len(ec['workshop']) > 4 else ''})")
        # Stack types
        if ai["stack_types"]:
            print(f"\n  Stack types:     {', '.join(ai['stack_types'])}")
        # Language breakdown
        if ai["language_breakdown"]:
            lang_parts = [f"{lang}" for lang in sorted(ai["language_breakdown"].keys())]
            print(f"  Languages:       {', '.join(lang_parts)}  (org-wide)")
        # Service inventory with environments
        if ai["services"]:
            svc_envs_map = ai["svc_envs"]
            print(f"\n  Services ({ai['service_count']}):")
            print(f"    {'Name':<35}  Environments")
            print(f"    {'─'*80}")
            for s in sorted(ai["services"], key=lambda x: x["name"]):
                envs = svc_envs_map.get(s["name"], [])
                env_str = ", ".join(envs) if envs else "—"
                print(f"    {s['name']:<35}  {env_str}")
        # Inferred dependencies
        if ai["inferred_deps"]:
            dep_parts = []
            for dtype, cnt in sorted(ai["inferred_dep_types"].items()):
                label = "inferred HTTP endpoint(s)" if dtype == "service" else f"{dtype}(s)"
                dep_parts.append(f"{cnt} {label}")
            print(f"\n  Inferred dependencies:  {', '.join(dep_parts)}")
            for n in sorted(ai["inferred_deps"], key=lambda x: x.get("serviceName", "")):
                print(f"    {n.get('serviceName', '?'):<35}  [{n.get('type','unknown')}]")

    # ── Product adoption coverage ─────────────────────────────────────────
    if product_adoption:
        adopted = sum(1 for i in product_adoption.values() if i["adopted"])
        total_p = len(product_adoption)
        print(f"""
  PRODUCT ADOPTION COVERAGE  ({adopted}/{total_p} products active)
  {"─" * 70}""")
        for pname, info in product_adoption.items():
            status = "✓" if info["adopted"] else "✗"
            print(f"  {status}  {pname:<30}  {info['detail']}")

    # ── Org capacity ──────────────────────────────────────────────────────
    if org_capacity:
        print(f"""
  ORG CAPACITY & LIMITS
  {"─" * 60}
  {"Metric":<35} {"Used":>10} {"Limit":>10} {"Pct":>6}""")
        for c in org_capacity:
            bar_w = min(round(c["pct"] / 100 * 20), 20)
            bar_str = "█" * bar_w + "░" * (20 - bar_w)
            print(f"  {c['metric']:<35} {c['used']:>10,} {c['limit']:>10,} {c['pct']:>5.1f}%  {bar_str}")

    # ── Detector alert history summary ────────────────────────────────────
    if det_history:
        silent_d = [d for d in det_history if d["status"] == "silent"]
        noisy_d  = [d for d in det_history if d["status"] == "noisy"]
        if silent_d or noisy_d:
            print(f"""
  DETECTOR ALERT HISTORY  ({len(silent_d)} silent, {len(noisy_d)} noisy)
  {"─" * 70}""")
            for d in (noisy_d + silent_d)[:15]:
                print(f"  [{d['status']:>7}]  {d['incident_count']:>3} incidents  {d['name'][:55]}")

    # ── Detector → service coverage ───────────────────────────────────────
    if det_svc_coverage and det_svc_coverage["total"] > 0:
        pct = round(len(det_svc_coverage["covered"]) / det_svc_coverage["total"] * 100)
        print(f"""
  DETECTOR SERVICE COVERAGE  {len(det_svc_coverage['covered'])}/{det_svc_coverage['total']} services covered ({pct}%)
  {"─" * 60}""")
        if det_svc_coverage["uncovered"]:
            print(f"  Uncovered: {', '.join(det_svc_coverage['uncovered'])}")

    # ── Time to first value ───────────────────────────────────────────────
    u_ttfv = [(u["email"], u["ttfv_days"]) for u in users if u.get("ttfv_days") is not None]
    if u_ttfv:
        avg_ttfv = round(sum(d for _, d in u_ttfv) / len(u_ttfv), 1)
        print(f"""
  TIME TO FIRST VALUE  (days from join to first write op, avg={avg_ttfv}d)
  {"─" * 60}""")
        for email, d_val in sorted(u_ttfv, key=lambda x: x[1]):
            print(f"  {email:<40}  {d_val}d")

    # ── Engagement 30d trend ──────────────────────────────────────────────
    trend_users = [u for u in users if u.get("activity_last30", 0) + u.get("activity_prev30", 0) > 0]
    if trend_users:
        print(f"""
  ENGAGEMENT TREND  (last 30d vs prev 30d)
  {"─" * 70}
  {"User":<35} {"Tag":<15} {"Prev30":>7} {"Last30":>7} {"Delta":>7}""")
        print("  " + "-" * 70)
        for u in sorted(trend_users, key=lambda u: -abs(u.get("activity_delta", 0))):
            delta = u.get("activity_delta", 0)
            arrow = "▲" if delta > 0 else "▼" if delta < 0 else "→"
            print(f"  {u['email']:<35} {u.get('user_tag',''):<15} "
                  f"{u.get('activity_prev30',0):>7} {u.get('activity_last30',0):>7} "
                  f"{arrow}{abs(delta):>6}")

    # ── Integration coverage ──────────────────────────────────────────────
    if integ_data and integ_data["total"] > 0:
        print(f"""
  INTEGRATION COVERAGE  ({integ_data['enabled']} enabled, {integ_data['disabled']} disabled)
  {"─" * 60}""")
        for itype, names in list(integ_data["by_type"].items())[:10]:
            print(f"  [enabled]   {itype:<25}  {', '.join(names[:3])}{'...' if len(names) > 3 else ''}")
        for d in integ_data.get("disabled_list", []):
            print(f"  [disabled]  {d['type']:<25}  {d['name']}")

    # ── Feature area heatmap ──────────────────────────────────────────────
    if feature_heatmap and feature_heatmap["by_feature"]:
        print(f"""
  FEATURE AREA USAGE  (API resource types, org-wide)
  {"─" * width}""")
        for rtype, cnt in list(feature_heatmap["by_feature"].items())[:15]:
            bar_str = score_bar(min(cnt, 100), width=20)
            print(f"  {rtype:<30}  {bar_str}  {cnt:>6} requests")
        if feature_heatmap["unused_features"]:
            print(f"\n  Potentially unused features: {', '.join(feature_heatmap['unused_features'])}")

    # ── Cohort retention ──────────────────────────────────────────────────
    if cohort_data:
        print(f"""
  USER COHORT RETENTION  (grouped by join month)
  {"─" * 70}
  {"Cohort":<12} {"Size":>6} {"Active":>7} {"Retention":>10}""")
        print("  " + "-" * 40)
        for c in cohort_data:
            pct_str = f"{c['retention_pct']}%"
            print(f"  {c['month']:<12} {c['size']:>6} {c['active']:>7} {pct_str:>10}")

    # ── Activity trend ────────────────────────────────────────────────────
    combined_monthly = defaultdict(int)
    for u in users:
        for month, cnt in u.get("activity_by_month", {}).items():
            combined_monthly[month] += cnt
    if combined_monthly:
        print(f"""
  ORG ACTIVITY TREND  (combined logins + API events by month)
  {"─" * 70}""")
        months = sorted(combined_monthly.keys())[-12:]
        for m in months:
            cnt = combined_monthly[m]
            bar_str = score_bar(min(cnt, 500), width=30)
            print(f"  {m}  {bar_str}  {cnt}")

    # ── Muting activity ───────────────────────────────────────────────────
    if muting_data and muting_data["writers"]:
        print(f"""
  ALERT MUTING ACTIVITY  (potential alert fatigue)
  {"─" * 60}
  Active muting rules: {muting_data['active_rules']}""")
        for w in muting_data["writers"]:
            print(f"  {w['email']:<40}  {w['mute_writes']} muting rule write(s)")

    # ── Collaboration ─────────────────────────────────────────────────────
    if collab_data and collab_data["multi_editor_assets"]:
        print(f"""
  CROSS-USER COLLABORATION  (assets edited by multiple users)
  {"─" * width}
  {"Type":<12} {"Asset Name":<45} {"Creator":<30} {"Last Modified By"}""")
        print("  " + "-" * (width - 2))
        for a in collab_data["multi_editor_assets"][:15]:
            print(f"  {a['type']:<12} {a['name'][:44]:<45} {a['creator'][:29]:<30} {a['last_modified_by']}")

    # ── User activity table ───────────────────────────────────────────────
    print(f"""
  USER ACTIVITY  (last {days} days)
  {"─" * width}
  {"User":<35} {"Score":>6}  {"Last Login":<22} {"Last Activity":<22} {"Logins":>7} {"Reads":>7} {"Writes":>7}  {"Avg Ses":>7}  {"API%":>5}  {"Resources Used"}""")
    print("  " + "-" * (width - 2))

    for u in users:
        last_login    = ts_to_str(u["last_login"])    if u["last_login"]    else "never"
        last_activity = ts_to_str(u["last_activity"]) if u["last_activity"] else "never"
        resources     = ", ".join(u["resources_used"][:3]) + ("..." if len(u["resources_used"]) > 3 else "")
        admin_tag     = " [admin]" if u["admin"] else ""
        name          = f"{u['email']}{admin_tag}"
        sc            = u["engagement_score"]
        score_str     = f"{sc:>3}/100"
        avg_dur       = u.get("avg_session_min")
        dur_str       = (f"{avg_dur:.0f}m" if avg_dur and avg_dur < 60
                         else f"{avg_dur/60:.1f}h" if avg_dur else "—")
        api_pct       = u.get("api_pct")
        api_str       = f"{api_pct}%" if api_pct is not None else "—"
        print(f"  {name:<35} {score_str}  {last_login:<22} {last_activity:<22} "
              f"{u['login_count']:>7} {u.get('read_ops',0):>7} {u['write_ops']:>7}  "
              f"{dur_str:>7}  {api_str:>5}  {resources or '—'}")

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

    # ── New vs returning users ────────────────────────────────────────────
    if new_vs_returning:
        n = new_vs_returning["new"]
        e = new_vs_returning["established"]
        print(f"""
  NEW VS RETURNING USERS
  {"─" * 60}
  New (<30d):    {n['count']:>4}  active={n.get('active', 0)}  avg_score={n.get('avg_score', 0)}
  Established:   {e['count']:>4}  active={e.get('active', 0)}  avg_score={e.get('avg_score', 0)}""")

    # ── Incident MTTA ────────────────────────────────────────────────────
    if incident_mtta and incident_mtta["total_incidents"] > 0:
        print(f"""
  INCIDENT ACKNOWLEDGEMENT & MTTA  ({incident_mtta['acked']}/{incident_mtta['total_incidents']} ack'd, {incident_mtta['unacked_pct']}% never ack'd)
  {"─" * 70}
  {"User":<40} {"Incidents":>10} {"Ack'd":>7} {"Ack Rate":>9} {"Avg MTTA":>9}""")
        for u in incident_mtta["per_user"][:10]:
            ack_pct = round(u["acked"] / u["total"] * 100) if u["total"] else 0
            mtta = f"{u['avg_mtta_min']}m" if u["avg_mtta_min"] is not None else "—"
            print(f"  {u['email']:<40} {u['total']:>10} {u['acked']:>7} {ack_pct:>8}% {mtta:>9}")

    # ── Alert fatigue ─────────────────────────────────────────────────────
    if alert_fatigue:
        ok_str = "OK" if alert_fatigue["benchmark_ok"] else "HIGH"
        print(f"""
  ALERT FATIGUE INDEX  ({alert_fatigue['alerts_per_user_per_day']} alerts/user/day — {ok_str})
  {"─" * 70}""")
        noisy = [d for d in alert_fatigue["detector_quality"] if d["quality"] == "noisy"]
        if noisy:
            print(f"  Noisy detectors ({len(noisy)}, >50% short-lived incidents):")
            for d in noisy[:8]:
                print(f"    {d['noise_pct']:>3}% noise  {d['name'][:60]}")

    # ── Detector notification routing ────────────────────────────────────
    if notif_routing:
        cc = notif_routing.get("channel_counts", {})
        if cc:
            print(f"""
  DETECTOR NOTIFICATION ROUTING
  {"─" * 60}""")
            for ch, cnt in list(cc.items())[:8]:
                print(f"  {ch:<20}  {cnt} detector(s)")
            nr = notif_routing.get("no_routing", [])
            if nr:
                print(f"  ⚠ {len(nr)} detector(s) have no routing")

    # ── Alert routing by service ──────────────────────────────────────────
    if alert_routing_svc:
        covered   = sum(1 for r in alert_routing_svc if r["tier"] == "covered")
        uncovered = sum(1 for r in alert_routing_svc if r["tier"] == "uncovered")
        if alert_routing_svc:
            print(f"""
  ALERT ROUTING COVERAGE BY SERVICE  ({covered}/{len(alert_routing_svc)} covered, {uncovered} uncovered)
  {"─" * 70}""")
            for r in sorted(alert_routing_svc, key=lambda x: {"covered": 0, "detector-only": 1, "uncovered": 2}[x["tier"]])[:15]:
                print(f"  [{r['tier']:<13}]  {r['service']}")

    # ── SLO detectors ─────────────────────────────────────────────────────
    if slo_detectors:
        print(f"""
  SLO DETECTOR COVERAGE  ({slo_detectors['slo_count']} SLO, {slo_detectors['generic_count']} generic — maturity: {slo_detectors['maturity']})
  {"─" * 60}""")
        for d in slo_detectors.get("slo_detectors", [])[:10]:
            print(f"  {d['name'][:70]}")

    # ── Detector creation velocity ────────────────────────────────────────
    if detector_velocity:
        print(f"""
  DETECTOR CREATION VELOCITY  (last 12 months)
  {"─" * 60}""")
        for item in detector_velocity[-12:]:
            bar_str = score_bar(min(item["count"] * 5, 100), width=20)
            print(f"  {item['month']}  {bar_str}  {item['count']}")

    # ── SignalFlow usage ──────────────────────────────────────────────────
    if signalflow_usage:
        print(f"""
  SIGNALFLOW & DATA SEARCH USAGE
  {"─" * 70}
  {"User":<40} {"SignalFlow":>12} {"Searches":>10}""")
        for u in signalflow_usage[:10]:
            print(f"  {u['email']:<40} {u['signalflow']:>12} {u['data_searches']:>10}")

    # ── Dashboard sharing ─────────────────────────────────────────────────
    if dash_sharing and dash_sharing["top_read_dashboards"]:
        print(f"""
  DASHBOARD SHARING & VIEW FREQUENCY  (total views: {dash_sharing['total_dash_reads']})
  {"─" * 70}""")
        for d in dash_sharing["top_read_dashboards"][:8]:
            print(f"  {d['reads']:>5} views  {d['name'][:60]}")

    # ── Data volume by product ────────────────────────────────────────────
    if data_volume:
        print(f"""
  DATA VOLUME BY TELEMETRY TYPE
  {"─" * 60}""")
        for item in data_volume:
            bar_str = score_bar(item["pct"], width=20)
            print(f"  {item['product']:<20}  {bar_str}  {item['pct']:>5.1f}%  {item['total']:,.0f}")

    # ── Cardinality hotspots ──────────────────────────────────────────────
    if cardinality:
        print(f"""
  CARDINALITY HOTSPOTS  (top metrics by MTS count)
  {"─" * 70}""")
        for h in cardinality[:10]:
            print(f"  {h['mts_count']:>10,} MTS  ({h['pct']:>5.1f}%)  {h.get('metric', h.get('name', '?'))}")

    # ── Instrumentation completeness ──────────────────────────────────────
    if instrumentation:
        full = sum(1 for s in instrumentation if s["tier"] == "full")
        partial = sum(1 for s in instrumentation if s["tier"] == "partial")
        traces_only = sum(1 for s in instrumentation if s["tier"] == "traces-only")
        print(f"""
  INSTRUMENTATION COMPLETENESS  (full={full}, partial={partial}, traces-only={traces_only})
  {"─" * 70}
  {"Service":<40} {"Traces":>7} {"Metrics":>8} {"Logs":>6} {"Tier"}""")
        for s in instrumentation[:15]:
            print(f"  {s['service']:<40} {'✓' if s['traces'] else '✗':>7} {'✓' if s['metrics'] else '✗':>8} {'✓' if s['logs'] else '✗':>6} {s['tier']}")

    # ── Token rotation ────────────────────────────────────────────────────
    if token_rotation:
        print(f"""
  TOKEN ROTATION CADENCE  ({len(token_rotation)} tokens older than 1 year)
  {"─" * 70}""")
        for t in token_rotation[:10]:
            exp_str = " [EXPIRED]" if t["expired"] else ""
            print(f"  {t['age_days']:>5}d  {t['scopes']:<25}  {t['name']}{exp_str}")

    # ── Inactive admin risk ───────────────────────────────────────────────
    if inactive_admin_risk and inactive_admin_risk.get("inactive_admins"):
        risks = inactive_admin_risk["inactive_admins"]
        print(f"""
  INACTIVE ADMIN RISK  ({len(risks)} inactive admin(s), {inactive_admin_risk['active_token_count']} active token(s))
  {"─" * 60}""")
        for r in risks:
            inactive_str = f"{r['days_inactive']}d ago" if r["days_inactive"] is not None else "never active"
            print(f"  {r['email']:<45}  last activity: {inactive_str}")

    # ── Privilege escalation ──────────────────────────────────────────────
    if priv_escalation:
        elevated = priv_escalation.get("recently_elevated", [])
        role_changes = priv_escalation.get("role_changes", [])
        if elevated or role_changes:
            print(f"""
  PRIVILEGE ESCALATION DETECTION  ({len(elevated)} new admin(s), {len(role_changes)} role change(s))
  {"─" * 70}""")
            for r in elevated:
                print(f"  [new admin]     {r['email']:<45}  {r['days_ago']}d ago")
            for rc in role_changes[:5]:
                print(f"  [role change]   {rc['actor']:<45}  {ts_to_str(rc['ts'])}")

    # ── Recommended actions ───────────────────────────────────────────────
    if recommended_actions:
        print(f"""
  RECOMMENDED ACTIONS  ({len(recommended_actions)} actions)
  {"─" * width}
  {"Priority":<10} {"Category":<20} {"Action"}""")
        print("  " + "-" * (width - 2))
        for a in recommended_actions:
            print(f"  {a['priority']:<10} {a['category']:<20} {a['action']}")
            if a.get("detail"):
                print(f"  {'':>30} {a['detail']}")

    # ── User journey funnel ───────────────────────────────────────────────
    if user_funnel:
        print(f"""
  USER JOURNEY FUNNEL
  {"─" * 60}""")
        for stage, count, pct in user_funnel:
            bar_str = score_bar(pct, width=20)
            print(f"  {stage:<20}  {bar_str}  {count:>4} ({pct}%)")

    # ── Org trends ────────────────────────────────────────────────────────
    if org_trends:
        print(f"""
  ORG TRENDS  (last 30d vs prior 30d)
  {"─" * 70}
  {"Metric":<25} {"Prev 30d":>10} {"Last 30d":>10} {"Change":>10}""")
        for t in org_trends:
            arrow = "▲" if t["direction"] == "up" else "▼" if t["direction"] == "down" else "→"
            pct_str = f"({t['pct']:+}%)" if t["pct"] is not None else ""
            anom = "  ⚠ ANOMALY" if t.get("anomaly") else ""
            print(f"  {t['metric']:<25} {t['prior']:>10} {t['current']:>10} "
                  f"  {arrow} {pct_str}{anom}")

    # ── Detector last fired ───────────────────────────────────────────────
    if det_last_fired:
        never = [d for d in det_last_fired if d["never_fired"]]
        if never:
            print(f"""
  DETECTOR LAST FIRED  ({len(never)} detectors never fired)
  {"─" * 60}""")
            for d in never[:8]:
                print(f"  [never fired]  {d['name'][:65]}")

    # ── Token usage ───────────────────────────────────────────────────────
    if tok_usage:
        dormant = tok_usage.get("dormant", [])
        never   = tok_usage.get("never_used", [])
        if dormant or never:
            print(f"""
  TOKEN USAGE ACTIVITY  ({len(tok_usage.get('active',[]))} active, {len(dormant)} dormant, {len(never)} never used)
  {"─" * 70}""")
            for t in (dormant + never)[:8]:
                status = "dormant" if t in dormant else "never used"
                print(f"  [{status:<10}]  {t['name']:<35}  {t['age_days'] or '?'}d old")

    # ── Team health ───────────────────────────────────────────────────────
    if team_health:
        print(f"""
  TEAM HEALTH SCORES
  {"─" * width}
  {"Team":<30} {"Members":>8} {"Active%":>8} {"Avg Score":>10} {"Health":>7}""")
        print("  " + "-" * (width - 2))
        for t in team_health:
            print(f"  {t['name']:<30} {t['member_count']:>8} {t['active_rate']:>7}% "
                  f"{t['avg_score']:>10} {t['health_score']:>7}")

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
            cohort_data=cohort_data,
            feature_heatmap=feature_heatmap,
            muting_data=muting_data,
            collab_data=collab_data,
            product_adoption=product_adoption,
            integ_data=integ_data,
            org_capacity=org_capacity,
            det_history=det_history,
            ingestion_trend=ingestion_trend,
            dash_complexity=dash_complexity,
            det_svc_coverage=det_svc_coverage,
            tok_scope_issues=tok_scope_issues,
            incident_mtta=incident_mtta,
            alert_fatigue=alert_fatigue,
            notif_routing=notif_routing,
            alert_routing_svc=alert_routing_svc,
            data_volume=data_volume,
            inactive_admin_risk=inactive_admin_risk,
            token_rotation=token_rotation,
            signalflow_usage=signalflow_usage,
            dash_sharing=dash_sharing,
            detector_velocity=detector_velocity,
            new_vs_returning=new_vs_returning,
            priv_escalation=priv_escalation,
            slo_detectors=slo_detectors,
            instrumentation=instrumentation,
            cardinality=cardinality,
            recommended_actions=recommended_actions,
            org_trends=org_trends,
            user_funnel=user_funnel,
            det_last_fired=det_last_fired,
            tok_usage=tok_usage,
            apm_graph=apm_graph,
            team_health=team_health,
            det_complexity=det_complexity,
            user_last_touched=user_last_touched,
            dash_groups=dash_groups,
            notif_health=notif_health,
            svc_error_rates=svc_error_rates,
            report_diff=report_diff,
            orphaned_assets=orphaned_assets,
            sev_dist=sev_dist,
            onboarding_vel=onboarding_vel,
            role_dist=role_dist,
            env_inventory=env_inventory,
            token_expiry_pipeline=token_expiry_pipeline,
            det_tag_coverage=det_tag_coverage,
            silent_by_creator=silent_by_creator,
            asset_age=asset_age,
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
    p_report.add_argument("--no-cache",   action="store_true",
                          help="Bypass disk cache and force fresh API fetches")
    p_report.add_argument("--baseline",   default=None,
                          help="Path to a trace fingerprint baseline.json to overlay on the APM dependency graph")

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
        use_cache = not getattr(args, "no_cache", False)
        cache_ttl = 300  # 5 minutes

        t0 = time.time()
        print(f"Fetching data from realm={REALM} ({window_desc})...")

        # ── Phase 1: parallel fetch of all independent data sources ──────────
        fetch_results = {}

        def _fetch(name, fn, *a, cache_key=None, **kw):
            if use_cache and cache_key:
                hit = cache_load(cache_key, cache_ttl)
                if hit is not None:
                    return name, hit, True
            result = fn(*a, **kw)
            if use_cache and cache_key:
                cache_save(cache_key, result)
            return name, result, False

        tasks = {
            "members":       (fetch_members,       (),                             {"cache_key": f"members_{REALM}"}),
            "session_events":(fetch_session_events,(eff_days, since_ms, until_ms), {"cache_key": f"sess_{REALM}_{eff_days}"}),
            "http_events":   (fetch_http_events,   (eff_days, since_ms, until_ms), {"cache_key": f"http_{REALM}_{eff_days}"}),
            "assets":        (fetch_assets,         (),                             {"cache_key": f"assets_{REALM}"}),
            "muting_rules":  (fetch_muting_rules,   (),                             {"cache_key": f"muting_{REALM}"}),
            "incidents":     (fetch_incidents,      (eff_days,),                    {"cache_key": f"incidents_{REALM}_{eff_days}"}),
            "integrations":  (fetch_integrations,   (),                             {"cache_key": f"integrations_{REALM}"}),
            "org_data":      (fetch_organization,   (),                             {"cache_key": f"org_{REALM}"}),
            "top_mts":       (fetch_top_mts,        (20,),                          {"cache_key": f"topmts_{REALM}"}),
        }
        if not args.no_teams:
            tasks["teams"] = (fetch_teams, (), {"cache_key": f"teams_{REALM}"})
        if not args.no_otel:
            tasks["otel_services"]  = (fetch_otel_signals,           (), {"cache_key": f"otel_{REALM}"})
            tasks["apm_topology"]   = (fetch_apm_topology,           (), {"cache_key": f"apmtopo_{REALM}"})
            tasks["environments"]   = (fetch_deployment_environments,(), {"cache_key": f"envs_{REALM}"})

        completed = set()
        with ThreadPoolExecutor(max_workers=8) as ex:
            futures = {
                ex.submit(_fetch, name, fn, *a, **kw): name
                for name, (fn, a, kw) in tasks.items()
            }
            for fut in as_completed(futures):
                name, result, cached = fut.result()
                fetch_results[name] = result
                cached_str = " (cached)" if cached else ""
                completed.add(name)
                print(f"  {name}...done{cached_str}")

        # Unpack results
        members        = fetch_results["members"]
        session_events = fetch_results["session_events"]
        http_events    = fetch_results["http_events"]
        detectors, dashboards, charts, tokens = fetch_results["assets"]
        muting_rules   = fetch_results.get("muting_rules", [])
        incidents      = fetch_results.get("incidents", [])
        integrations   = fetch_results.get("integrations", [])
        org_data       = fetch_results.get("org_data", {})
        top_mts        = fetch_results.get("top_mts", [])
        teams          = fetch_results.get("teams", [])

        otel_services  = fetch_results.get("otel_services", {})
        apm_nodes, apm_edges = fetch_results.get("apm_topology", ([], []))
        apm_services   = [n for n in apm_nodes if not n.get("inferred")]
        environments   = fetch_results.get("environments", [])
        svc_lang_map   = {}
        svc_envs       = {}

        # ── Phase 2: dependent fetches (need results from phase 1) ────────────
        print("  dashboard chart counts (sample)...")
        chart_counts = fetch_dashboard_chart_counts(dashboards)

        if not args.no_otel and environments:
            print("  services per environment...")
            svc_envs = fetch_services_per_environment(environments)

        # ── Phase 3: parallel SignalFlow + incident enrichment ────────────────
        print("  SignalFlow & enrichment (parallel)...")
        _vol_programs = {
            "Infrastructure": "data('sf.org.numDatapointsReceived').sum().publish()",
            "APM":            "data('sf.org.apm.numSpansReceived').sum().publish()",
            "Logs":           "data('sf.org.numLogsReceived').sum().publish()",
        }
        sf_tasks = {
            "ingestion_raw": ("data('sf.org.numDatapointsReceived').sum().publish()", eff_days),
            **{f"vol_{k}": (v, min(eff_days, 30)) for k, v in _vol_programs.items()},
        }
        sf_results = {}
        with ThreadPoolExecutor(max_workers=5) as ex:
            sf_futures = {
                ex.submit(fetch_signalflow_metric, prog, days): key
                for key, (prog, days) in sf_tasks.items()
            }
            inc_future = ex.submit(fetch_incident_details, incidents)
            for fut in as_completed({**sf_futures, inc_future: "incidents_enriched"}):
                if fut is inc_future:
                    incidents_enriched = fut.result()
                else:
                    key = sf_futures[fut]
                    sf_results[key] = fut.result()

        ingestion_raw  = sf_results.get("ingestion_raw", [])
        data_volume_raw = {k: sf_results.get(f"vol_{k}", []) for k in _vol_programs}

        t1 = time.time()
        print(f"  ✓ all data fetched in {t1 - t0:.1f}s")

        print_report(members, session_events, http_events,
                     detectors, dashboards, charts, tokens,
                     otel_services, apm_services, teams=teams,
                     days=eff_days, stale_days=args.stale_days,
                     csv_path=True if args.csv else None,
                     html_path=True if args.html else None,
                     apm_nodes=apm_nodes, apm_edges=apm_edges,
                     environments=environments, svc_lang_map=svc_lang_map,
                     svc_envs=svc_envs, muting_rules=muting_rules,
                     incidents=incidents, integrations=integrations,
                     org_data=org_data, chart_counts=chart_counts,
                     ingestion_raw=ingestion_raw,
                     incidents_enriched=incidents_enriched,
                     top_mts=top_mts,
                     data_volume_raw=data_volume_raw,
                     baseline_path=getattr(args, "baseline", None))

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
