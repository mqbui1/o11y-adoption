# o11y-adoption

Audit tool for Splunk Observability Cloud adoption. Answers:
- **Who** is using the platform and how actively?
- **How much** OpenTelemetry instrumentation has been adopted?
- **What** assets (detectors, dashboards, tokens) are stale or unhealthy?

> **Note on data availability:** The Splunk Observability audit API logs write operations (POST/PUT/DELETE) only — dashboard views and chart reads are not recorded. Time-on-page and view counts are not derivable from any available API. The tool maximizes what can be inferred from login events, write activity, and asset metadata.

## Data sources

| Source | What it provides |
|--------|-----------------|
| `GET /v2/organization/member` | Full user roster, roles, join date |
| `GET /v2/event/find?query=sf_eventType:SessionLog` | Login/logout events — email, auth method, timestamps |
| `GET /v2/event/find?query=sf_eventType:HttpRequest` | Write-only audit events — resource type, method, URI, timestamp |
| `GET /v2/detector`, `/v2/dashboard`, `/v2/chart` | Asset inventory, staleness, last-modified-by |
| `GET /v2/token` | Token expiry / health |
| MTS dimension search (`telemetry.sdk.*`) | OTel SDK instrumentation signals |
| `POST /v2/apm/topology` | APM-instrumented service list |

## Setup

```bash
git clone https://github.com/mqbui1/o11y-adoption
cd o11y-adoption
pip install -r requirements.txt

export SPLUNK_REALM=us1
export SPLUNK_ACCESS_TOKEN=<your-api-token>
```

## Commands

### `report` — full adoption report

```bash
python3 o11y_adoption.py report [--days 90] [--stale-days 90] [--no-otel] [--json]
```

Prints a full report with the following sections:

| Section | What it shows |
|---------|---------------|
| **Org health score** | Single 0–100 score with progress bars across four dimensions: user adoption, OTel coverage, asset hygiene, token health |
| **Platform overview** | User counts, detector/dashboard/chart totals, token health summary |
| **OTel & signal adoption** | APM service count, SDK-instrumented services, Collector deployments, language breakdown |
| **User activity table** | All users with engagement score (0–100), last login, last activity, login count, write ops, resource types |
| **Login frequency timeline** | Logins per calendar week per user — shows engagement trends over time |
| **Login heatmap** | Org-wide logins by day-of-week × hour-of-day (UTC) — reveals usage patterns and timezone concentration |
| **Write activity detail** | Per-user breakdown of API mutations: grouped by method+resource type, plus 5 most recent individual operations with timestamps and URIs |
| **Asset ownership** | Detectors, dashboards, and charts attributed to each user by `lastUpdatedBy` field |
| **Inactive users** | Users with no login or write activity in the lookback window |
| **Token alerts** | Expired and soon-to-expire tokens |
| **Stale detectors** | Detectors not updated in `--stale-days` |
| **Stale dashboards** | Dashboards not updated in `--stale-days` |

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--days N` | 90 | Activity lookback window in days |
| `--stale-days N` | 90 | Mark assets stale if not updated in N days |
| `--no-otel` | off | Skip OTel MTS dimension scan (faster) |
| `--json` | off | Save full raw data to `reports/` as JSON |

### `users` — user activity only

```bash
python3 o11y_adoption.py users [--days 90] [--inactive-only]
```

Lightweight fetch — skips assets and OTel signals. Prints user activity table only.

| Flag | Description |
|------|-------------|
| `--inactive-only` | Show only users with no activity in the window |

### `tokens` — token health only

```bash
python3 o11y_adoption.py tokens
```

Lists all tokens with expiry status and auth scopes. Flags expired and expiring-soon tokens.

## Example output

```
  ORG HEALTH SCORE
  ──────────────────────────────────────────────────
  Overall:  ██████████░░░░░░░░░░  49/100  (D)

  User adoption    ████████░░    19/25   7 of 9 users active in last 90d
  OTel coverage    ░░░░░░░░░░     0/25   0 of 8 APM services OTel-instrumented
  Asset hygiene    ███░░░░░░░     7/25   51 of 182 detectors+dashboards not stale
  Token health     █████████░    23/25   20 of 22 tokens healthy

  USER ACTIVITY  (last 90 days)
  ──────────────────────────────────────────────────────────────────────────
  User                                 Score  Last Login           Logins  Writes
  ──────────────────────────────────────────────────────────────────────────
  mbui@splunk.com [admin]              92/100  2026-03-25 03:37          9      46
  gravi@splunk.com                     32/100  2026-03-11 18:20          3       0
  agrover@splunk.com [admin]            5/100  never                     0       0

  LOGIN FREQUENCY  (logins per calendar week)
  ─────────────────────────────────────────────────────────────────
  User                                 W01  W02  W08  W09  W10  W11  W12
  ─────────────────────────────────────────────────────────────────
  mbui@splunk.com [admin]                .    .    1    2    .    2    3
  gravi@splunk.com                       .    2    .    .    1    .    .
  douglask@splunk.com [admin]            .    .    .    .    .    .    .

  LOGIN HEATMAP  (org-wide logins by day/hour UTC)
  ───────────────────────────────────────────────────────────────────
  Day   00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19
  ───────────────────────────────────────────────────────────────────
  Mon    .  .  .  .  1  .  .  .  .  .  .  .  .  .  .  .  1  .  2  .
  Tue    .  .  .  .  .  1  .  .  .  .  .  .  .  .  .  .  1  1  .  .
  Fri    .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  2  .  .  1  .

  WRITE ACTIVITY DETAIL  (API mutations per user, last 90 days)

  mbui@splunk.com [admin]  —  46 write op(s)
      18x  DELETE token
      13x  POST token
       7x  DELETE team
       4x  PUT token
    Recent:
      2026-04-06 05:38 UTC  PUT     /v2/token/_RLITHH7C8nIXRJOG4KYuQ
      2026-04-06 05:37 UTC  PUT     /v2/token/mqbtesting-INGEST

  ASSET OWNERSHIP  (detectors / dashboards / charts by last modifier)
  ─────────────────────────────────────────────────────────────────────
  User                                      Detectors  Dashboards  Charts
  ─────────────────────────────────────────────────────────────────────
  mbui@splunk.com                                   4          35     222
  adiaz@splunk.com                                  0           1       0
```

## Scoring

### Org health score (0–100)

| Dimension | Weight | Formula |
|-----------|--------|---------|
| User adoption | 25 pts | `active users / total users` |
| OTel coverage | 25 pts | `SDK-instrumented services / total APM services` |
| Asset hygiene | 25 pts | `non-stale assets / total detectors+dashboards` |
| Token health  | 25 pts | `healthy tokens / total tokens` (penalises expired + expiring <7d) |

Grade: A ≥80, B ≥65, C ≥50, D ≥35, F <35

### User engagement score (0–100)

| Component | Weight | Formula |
|-----------|--------|---------|
| Recency | 30 pts | Linear decay from last activity date to window start |
| Login cadence | 25 pts | Actual logins vs target of 1/week over the window |
| Write activity | 25 pts | Log scale — 50 write ops = full score |
| Asset footprint | 20 pts | Log scale — 20 owned assets = full score |

## What counts as "active"

| Signal | Source | Notes |
|--------|--------|-------|
| Login | `SessionLog` event with `action=session created` | Includes SSO and password auth |
| API write activity | `HttpRequest` event with method POST/PUT/DELETE | Only mutations are logged; GET requests are not audited |
| Asset ownership | `lastUpdatedBy` on detector/dashboard/chart objects | Reflects who last saved the asset, not who created it |
| Login frequency | Count of `SessionLog` events grouped by calendar week | |

## OTel detection logic

The tool scans MTS dimensions to infer OTel instrumentation coverage:

- `telemetry.sdk.language` — OTel SDK present on that service
- `telemetry.sdk.version` — OTel SDK version in use
- `otelcol_*` metric prefix — OTel Collector deployment detected
- Semantic convention metrics (`http.server.request.duration`, `jvm.memory.used`, etc.) — further OTel SDK signal

## Known limitations

- **No read/view tracking** — the audit API only records write operations. Dashboard views, chart views, and SignalFlow executions are not logged and cannot be derived from any available API.
- **Asset ownership = last modifier** — `lastUpdatedBy` reflects who last saved an asset, which may differ from the original creator.
- **System assets** — assets created by Splunk's built-in content system appear under a system user ID (e.g. `AAAAAAAAAAA`) rather than an email.
- **HttpRequest events** — only user-initiated API calls are captured; automated token/integration calls appear under their token's associated user if resolvable.
