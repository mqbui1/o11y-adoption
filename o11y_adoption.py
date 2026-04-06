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


def fetch_session_events(days=90):
    start_ms = int((datetime.now() - timedelta(days=days)).timestamp() * 1000)
    return event_find("sf_eventType:SessionLog", start_ms)


def fetch_http_events(days=90):
    start_ms = int((datetime.now() - timedelta(days=days)).timestamp() * 1000)
    return event_find("sf_eventType:HttpRequest", start_ms)


def fetch_assets():
    detectors  = api_get("/v2/detector",  {"limit": 1000}).get("results", [])
    dashboards = api_get("/v2/dashboard", {"limit": 1000}).get("results", [])
    charts     = api_get("/v2/chart",     {"limit": 1000}).get("results", [])
    tokens     = api_get("/v2/token",     {"limit": 1000}).get("results", [])
    return detectors, dashboards, charts, tokens


def fetch_otel_signals():
    """
    Detect OTel adoption by sampling MTS dimensions across known OTel metrics.
    Returns dict of service -> {sdk, language, collector, version}
    """
    otel_metrics = [
        "otelcol_receiver_accepted_metric_points",
        "otelcol_exporter_sent_metric_points",
        "http.server.request.duration_count",
        "jvm.memory.used",
        "db.client.connections.usage",
    ]
    services = defaultdict(lambda: {
        "sdk": False, "collector": False,
        "language": set(), "sdk_version": set(), "collector_version": set(),
        "metrics": set(),
    })

    for metric in otel_metrics:
        try:
            result = api_get("/v2/metrictimeseries", {
                "query": f"sf_metric:{metric}", "limit": 500
            })
            mts_list = result.get("results", [])
            for mts in mts_list:
                dims = mts.get("dimensions", {})
                svc  = (dims.get("service.name") or dims.get("service") or
                        dims.get("sf_service") or "unknown")
                services[svc]["metrics"].add(metric)

                if "otelcol" in metric:
                    services[svc]["collector"] = True
                    if "receiver" in dims or "exporter" in dims:
                        pass
                else:
                    services[svc]["sdk"] = True

                lang = (dims.get("telemetry.sdk.language") or
                        dims.get("process.runtime.name", ""))
                if lang:
                    services[svc]["language"].add(lang)

                ver = dims.get("telemetry.sdk.version", "")
                if ver:
                    services[svc]["sdk_version"].add(ver)

        except Exception:
            continue

    return dict(services)


def fetch_apm_services():
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    week_ago = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 604800))
    try:
        r = requests.post(f"{API_BASE}/v2/apm/topology",
                          headers=HDR, json={"timeRange": f"{week_ago}/{now}"}, timeout=30)
        nodes = (r.json().get("data") or {}).get("nodes", [])
        return [n for n in nodes if not n.get("inferred")]
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


def analyze_otel(otel_services, apm_services):
    apm_names   = {s["serviceName"] for s in apm_services}
    sdk_svcs    = {s for s, info in otel_services.items() if info["sdk"]}
    coll_svcs   = {s for s, info in otel_services.items() if info["collector"]}
    languages   = defaultdict(set)
    for svc, info in otel_services.items():
        for lang in info["language"]:
            languages[lang].add(svc)

    return {
        "apm_services":        sorted(apm_names),
        "sdk_instrumented":    sorted(sdk_svcs),
        "collector_present":   sorted(coll_svcs),
        "languages":           {lang: sorted(svcs) for lang, svcs in languages.items()},
        "apm_count":           len(apm_names),
        "sdk_count":           len(sdk_svcs),
        "collector_count":     len(coll_svcs),
    }


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def print_report(members, session_events, http_events,
                 detectors, dashboards, charts, tokens,
                 otel_services, apm_services,
                 days=90, stale_days=90):

    users        = analyze_users(members, session_events, http_events, days)
    assets       = analyze_assets(detectors, dashboards, charts, tokens, stale_days)
    otel         = analyze_otel(otel_services, apm_services)
    ownership    = analyze_asset_ownership(detectors, dashboards, charts, members)
    now_str      = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    width        = 110

    print()
    print("=" * width)
    print(f"  Splunk Observability Adoption Report  |  realm={REALM}  |  {now_str}")
    print(f"  Activity window: last {days} days  |  Stale threshold: >{stale_days} days since last update")
    print("=" * width)

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
    print(f"""
  OTEL & SIGNAL ADOPTION
  {"─" * 50}
  APM services (traces):        {otel['apm_count']:>4}  {', '.join(otel['apm_services'][:6]) + ('...' if otel['apm_count'] > 6 else '')}
  OTel SDK instrumented:        {otel['sdk_count']:>4}  {', '.join(otel['sdk_instrumented'][:4]) + ('...' if otel['sdk_count'] > 4 else '')}
  OTel Collector deployments:   {otel['collector_count']:>4}""")
    if otel["languages"]:
        for lang, svcs in sorted(otel["languages"].items()):
            print(f"  Language — {lang:<12}          {len(svcs):>4}  {', '.join(svcs[:4])}")
    else:
        print("  Languages:                     no telemetry.sdk.language dimension detected")

    # ── User activity table ───────────────────────────────────────────────
    print(f"""
  USER ACTIVITY  (last {days} days)
  {"─" * width}
  {"User":<35} {"Last Login":<22} {"Last Activity":<22} {"Logins":>7} {"API Calls":>10} {"Writes":>7}  {"Auth Method":<20} {"Resources Used"}""")
    print("  " + "-" * (width - 2))

    for u in users:
        last_login    = ts_to_str(u["last_login"])    if u["last_login"]    else "never"
        last_activity = ts_to_str(u["last_activity"]) if u["last_activity"] else "never"
        auth          = ", ".join(u["auth_methods"][:2]) or "—"
        resources     = ", ".join(u["resources_used"][:4]) + ("..." if len(u["resources_used"]) > 4 else "")
        admin_tag     = " [admin]" if u["admin"] else ""
        name          = f"{u['email']}{admin_tag}"
        print(f"  {name:<35} {last_login:<22} {last_activity:<22} "
              f"{u['login_count']:>7} {u['http_count']:>10} {u['write_ops']:>7}  "
              f"{auth:<20} {resources or '—'}")

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
    p_report.add_argument("--stale-days", type=int, default=90,
                          help="Mark assets stale if not updated in N days (default: 90)")
    p_report.add_argument("--json",       action="store_true",
                          help="Also save full data as JSON to reports/")
    p_report.add_argument("--no-otel",    action="store_true",
                          help="Skip OTel MTS dimension scan (faster)")

    p_users = sub.add_parser("users", help="User activity summary only")
    p_users.add_argument("--days", type=int, default=90)
    p_users.add_argument("--inactive-only", action="store_true",
                         help="Show only users with no activity in the window")

    p_tokens = sub.add_parser("tokens", help="Token health — expiring and expired tokens")

    args = parser.parse_args()

    if not TOKEN:
        print("Error: SPLUNK_ACCESS_TOKEN not set")
        sys.exit(1)

    if args.command == "report":
        print(f"Fetching data from realm={REALM}...")
        print("  members...")
        members = fetch_members()
        print(f"  session events (last {args.days}d)...")
        session_events = fetch_session_events(args.days)
        print(f"  HTTP audit events (last {args.days}d)...")
        http_events = fetch_http_events(args.days)
        print("  assets (detectors, dashboards, charts, tokens)...")
        detectors, dashboards, charts, tokens = fetch_assets()

        otel_services = {}
        apm_services  = []
        if not args.no_otel:
            print("  OTel MTS dimensions...")
            otel_services = fetch_otel_signals()
            print("  APM topology...")
            apm_services  = fetch_apm_services()

        print_report(members, session_events, http_events,
                     detectors, dashboards, charts, tokens,
                     otel_services, apm_services,
                     days=args.days, stale_days=args.stale_days)

        if args.json:
            path = save_json({
                "members": members,
                "session_events": session_events,
                "http_events": http_events,
                "detectors": detectors,
                "dashboards": dashboards,
                "tokens": tokens,
                "otel_services": {k: {**v, "language": list(v["language"]),
                                       "sdk_version": list(v["sdk_version"]),
                                       "collector_version": list(v["collector_version"]),
                                       "metrics": list(v["metrics"])}
                                   for k, v in otel_services.items()},
                "apm_services": apm_services,
            })
            print(f"  JSON saved: {path}")

    elif args.command == "users":
        print(f"Fetching user activity (last {args.days}d)...")
        members        = fetch_members()
        session_events = fetch_session_events(args.days)
        http_events    = fetch_http_events(args.days)
        users          = analyze_users(members, session_events, http_events, args.days)

        if args.inactive_only:
            users = [u for u in users if not u["active"]]
            print(f"\nInactive users (no activity in last {args.days}d): {len(users)}\n")
        else:
            print(f"\nUser activity (last {args.days}d):\n")

        print(f"  {'User':<35} {'Last Login':<22} {'Logins':>7} {'API Calls':>10}  {'Auth'}")
        print("  " + "-" * 85)
        for u in users:
            ll   = ts_to_str(u["last_login"]) if u["last_login"] else "never"
            auth = ", ".join(u["auth_methods"][:1]) or "—"
            tag  = " [admin]" if u["admin"] else ""
            print(f"  {u['email']+tag:<35} {ll:<22} {u['login_count']:>7} {u['http_count']:>10}  {auth}")

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

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
