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
| `GET /v2/team` | Team membership |
| `GET /v2/event/find?query=sf_eventType:SessionLog` | Login/logout events — email, auth method, tokenId, timestamps |
| `GET /v2/event/find?query=sf_eventType:HttpRequest` | Write-only audit events — resource type, method, URI, timestamp |
| `GET /v2/detector`, `/v2/dashboard`, `/v2/chart` | Asset inventory, staleness, last-modified-by |
| `GET /v2/token` | Token expiry / health |
| `GET /v2/dimension?query=key:telemetry.sdk.*` | OTel SDK language and version signals |
| `GET /v2/dimension?query=key:telemetry.sdk.name` | OTel SDK name (opentelemetry, beyla, etc.) |
| `GET /v2/dimension?query=key:otelcol*` | OTel Collector presence |
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
python3 o11y_adoption.py report [options]
```

Prints a full report with the following sections (in order):

| Section | What it shows |
|---------|---------------|
| **Org health score** | 0–100 score with progress bars: user adoption, OTel coverage, asset hygiene, token health |
| **Platform overview** | User counts, detector/dashboard/chart totals, token health summary |
| **OTel & signal adoption** | APM service count, SDK-instrumented services, Collector deployments, language breakdown |
| **User activity table** | All users with engagement score (0–100), last login, last activity, login count, write ops |
| **Login frequency timeline** | Logins per calendar week per user |
| **Login heatmap** | Org-wide logins by day-of-week × hour-of-day (UTC) |
| **Write activity detail** | Per-user API mutations grouped by method+resource, plus 5 most recent ops |
| **Asset ownership** | Detectors, dashboards, charts attributed to each user by `lastUpdatedBy` |
| **Team rollup** | Members, active count, avg engagement score, asset counts per team |
| **Detector health issues** | Detectors flagged for: no notifications configured, disabled |
| **Token attribution** | Tokens seen in login events — identifies shared tokens (used by multiple users) |
| **Inactive users** | Users with no login or write activity in the lookback window |
| **Token alerts** | Expired and soon-to-expire tokens |
| **Stale detectors** | Detectors not updated in `--stale-days` |
| **Stale dashboards** | Dashboards not updated in `--stale-days` |

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--days N` | 90 | Activity lookback window in days |
| `--since YYYY-MM-DD` | — | Start date (overrides `--days`) |
| `--until YYYY-MM-DD` | now | End date (use with `--since`) |
| `--stale-days N` | 90 | Mark assets stale if not updated in N days |
| `--no-otel` | off | Skip OTel Dimension API scan (faster) |
| `--no-teams` | off | Skip team rollup section |
| `--csv` | off | Save user activity table to `reports/adoption_users_<ts>.csv` |
| `--html` | off | Save full report as HTML to `reports/adoption_report_<ts>.html` |
| `--json` | off | Save full raw data to `reports/adoption_report_<ts>.json` |

### `users` — user activity only

```bash
python3 o11y_adoption.py users [options]
```

Lightweight fetch — skips assets, OTel signals, and teams. Prints user activity table with engagement scores.

| Flag | Default | Description |
|------|---------|-------------|
| `--days N` | 90 | Activity lookback window |
| `--since YYYY-MM-DD` | — | Start date (overrides `--days`) |
| `--until YYYY-MM-DD` | now | End date |
| `--inactive-only` | off | Show only users with no activity in the window |
| `--csv` | off | Save results to `reports/adoption_users_<ts>.csv` |

### `tokens` — token health only

```bash
python3 o11y_adoption.py tokens
```

Lists all tokens with expiry status and auth scopes. Flags expired and expiring-soon tokens.

### `activity-timeline` — per-user event log

```bash
python3 o11y_adoption.py activity-timeline --user <email> [options]
```

Prints a chronological timeline of all logins and write operations for a specific user.

| Flag | Default | Description |
|------|---------|-------------|
| `--user EMAIL` | required | User email to show timeline for |
| `--days N` | 90 | Lookback window |
| `--since YYYY-MM-DD` | — | Start date (overrides `--days`) |
| `--until YYYY-MM-DD` | now | End date |

Example output:
```
  Activity timeline for mbui@splunk.com  (8 events)

  Timestamp              Action   Resource/Detail
  ----------------------------------------------------------------------
  2026-04-01 15:54 UTC   LOGIN    SSO_PROVIDER
  2026-04-01 15:54 UTC   POST     /v2/team
  2026-04-01 15:54 UTC   POST     /v2/token
  2026-04-06 05:37 UTC   PUT      /v2/token/mqbtesting-INGEST
  2026-04-06 05:38 UTC   PUT      /v2/token/_RLITHH7C8nIXRJOG4KYuQ
```

## HTML report

```bash
python3 o11y_adoption.py report --html
# → reports/adoption_report_<timestamp>.html
```

Generates a self-contained single-file HTML report (no external dependencies, works offline) with:
- Org health score with letter grade, full-width progress bar, and dimension cards
- Platform overview stat cards
- User activity table with inline per-user score bars (color-coded green/yellow/red)
- OTel adoption — instrumented service count, collector status, language and SDK breakdown
- Team rollup, detector health issues, token attribution, token alerts
- Stale detector and dashboard tables

## Example terminal output

```
  ORG HEALTH SCORE
  ──────────────────────────────────────────────────
  Overall:  ██████████░░░░░░░░░░  49/100  (D)

  User adoption    ████████░░    19/25   7 of 9 users active in last 90d
  OTel coverage    ██████████    25/25   8 of 8 APM services OTel-instrumented
  Asset hygiene    ███░░░░░░░     7/25   51 of 182 detectors+dashboards not stale
  Token health     █████████░    23/25   20 of 22 tokens healthy

  USER ACTIVITY  (last 90 days)
  ──────────────────────────────────────────────────────────────────────────
  User                                 Score  Last Login             Logins  Writes
  ──────────────────────────────────────────────────────────────────────────
  mbui@splunk.com [admin]              92/100  2026-03-25 03:37 UTC       9      46
  gravi@splunk.com                     32/100  2026-03-11 18:20 UTC       3       0
  agrover@splunk.com [admin]            5/100  never                      0       0

  TEAM ROLLUP
  ──────────────────────────────────────────────────────────────────────────
  Team                            Members  Active  Avg Score  Logins  Writes   Det   Dash  Charts
  ──────────────────────────────────────────────────────────────────────────
  platform-engineering                  4       3         58      14      46     4     35     222
  sre-team                              2       1         32       3       0     0      1       0

  DETECTOR HEALTH ISSUES  — 27 detector(s) flagged
  ──────────────────────────────────────────────────────────────────────────
  Name                                               Last Updated           Flags
  K8s nodes are not ready                            2025-03-24 21:45 UTC   no-notifications
  AWS EC2: CPU utilization expected to reach limit   2025-03-21 17:30 UTC   no-notifications

  TOKEN ATTRIBUTION  (tokens seen in login events)
  ──────────────────────────────────────────────────────────────────────
  Token                               Scopes       Users  Users
  ──────────────────────────────────────────────────────────────────────
  default-session-token               API              3  alice@co.com, bob@co.com, carol@co.com  [SHARED]
  mbui-personal                       API, INGEST      1  mbui@splunk.com
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
| Token sharing | `tokenId` in `SessionLog` cross-referenced with token objects | Identifies shared vs personal tokens |

## OTel detection logic

OTel signals are detected via the **Dimension API** (`GET /v2/dimension`), not via MTS queries. The Splunk Java agent and OTel SDKs store instrumentation metadata as dimension-level properties, not as metric time series dimensions.

| Signal | API query | What it means |
|--------|-----------|---------------|
| SDK languages in use | `key:telemetry.sdk.language` | Values: `java`, `python`, `go`, `nodejs`, etc. |
| SDK names | `key:telemetry.sdk.name` | Values: `opentelemetry`, `beyla`, `opentelemetry-ebpf-instrumentation` |
| OTel Collector present | `key:otelcol*` | Any result = Collector deployed |
| Instrumented service count | APM topology node count | Services sending traces = instrumented |

> **Why not MTS dimensions?** The Splunk Java agent and OTel SDKs attach `telemetry.sdk.*` as resource attributes on spans, not as dimensions on metric time series. Querying `/v2/metrictimeseries` for these keys returns zero results even in fully instrumented environments.

## Known limitations

- **No read/view tracking** — the audit API only records write operations. Dashboard views, chart views, and SignalFlow executions are not logged and cannot be derived from any available API.
- **Asset ownership = last modifier** — `lastUpdatedBy` reflects who last saved an asset, which may differ from the original creator.
- **System assets** — assets created by Splunk's built-in content system appear under a system user ID (e.g. `AAAAAAAAAAA`) rather than an email.
- **Team members** — team membership is fetched from `GET /v2/team` but member IDs are only resolved to emails for users present in the org member list.
- **HttpRequest events** — only user-initiated API calls are captured; automated token/integration calls appear under their token's associated user if resolvable.
