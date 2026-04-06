# o11y-adoption

Audit tool for Splunk Observability Cloud adoption. Answers:
- **Who** is using the platform and how actively?
- **How much** OpenTelemetry instrumentation has been adopted?
- **What** assets (detectors, dashboards, tokens) are stale or unhealthy?

## Data sources

| Source | What it provides |
|--------|-----------------|
| `GET /v2/organization/member` | Full user roster, roles, join date |
| `GET /v2/event/find?query=sf_eventType:SessionLog` | Login/logout events — email, auth method, timestamps |
| `GET /v2/event/find?query=sf_eventType:HttpRequest` | Per-user API/UI actions — resources touched, write ops |
| `GET /v2/detector`, `/v2/dashboard`, `/v2/chart` | Asset inventory + staleness |
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
python3 o11y_adoption.py report [--days 90] [--stale-days 90]
```

Prints a full report with sections:

- **Platform overview** — user counts, detector/dashboard/chart totals, token health
- **OTel & signal adoption** — APM service count, SDK-instrumented services, OTel Collector deployments, language breakdown
- **User activity table** — all users sorted by recency: last login, last activity, login count, API calls, write ops, auth method, resource types accessed
- **Inactive users** — users with no activity in the window
- **Token alerts** — expired and soon-to-expire tokens
- **Stale detectors** — not updated in `--stale-days`
- **Stale dashboards** — not updated in `--stale-days`

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--days N` | 90 | Activity lookback window |
| `--stale-days N` | 90 | Days without update = stale |
| `--top-n N` | 25 | Max users in activity table |

### `users` — user activity only

```bash
python3 o11y_adoption.py users [--days 90] [--top-n 25]
```

Prints just the user activity table and inactive users list — lighter fetch (skips assets and OTel signals).

### `tokens` — token health only

```bash
python3 o11y_adoption.py tokens
```

Lists all tokens with expiry status, disabled state, and DPM/APM limits. Flags expired and expiring-soon tokens.

## Example output

```
==============================================================================================================
  Splunk Observability Adoption Report  |  realm=us1  |  2026-04-06 19:25 UTC
  Activity window: last 90 days  |  Stale threshold: >90 days since last update
==============================================================================================================

  PLATFORM OVERVIEW
  ──────────────────────────────────────────────────
  Users (total):          9
  Users (active 90d):     7
  Users (inactive):       2

  Detectors:     30  (10 active, 20 stale >90d)
  Dashboards:   152  (41 active, 111 stale >90d)
  Charts:      1000
  Tokens:        22  (0 expiring <7d, 4 expiring <30d, 2 expired)

  OTEL & SIGNAL ADOPTION
  ──────────────────────────────────────────────────
  APM services (traces):    8  api-gateway, customers-service, ...
  OTel SDK instrumented:    6  api-gateway, vets-service, ...
  OTel Collector:           2
  Language — java           4  api-gateway, customers-service, ...

  USER ACTIVITY  (last 90 days)
  ──────────────────────────────────────────────────
  User                      Last Login           Last Activity        Logins  API Calls  Writes  Auth
  ──────────────────────────────────────────────────────────────────────────────────────────────────
  mbui@splunk.com [admin]   2026-03-25 03:37     2026-04-06 05:38          9         46      46  SSO
  gravi@splunk.com          2026-03-11 18:20     2026-03-11 18:20          3          0       0  SSO
  ...

  TOKEN ALERTS
  ────────────────────────────────────────────────────────────
  [EXPIRED]       pythozeroconfig-RUM    expired 2025-06-08 14:51 UTC
  [EXPIRING <30d] o11ymcp-API           expires in 22d
```

## What counts as "active"

- **Login**: a `SessionLog` event with `action=session created`
- **API activity**: an `HttpRequest` audit event attributed to the user's email
- **Write op**: an `HttpRequest` with method `POST`, `PUT`, `PATCH`, or `DELETE`

## OTel detection logic

The tool looks for MTS with these dimensions to infer OTel instrumentation:

- `telemetry.sdk.language` — presence indicates OTel SDK on that service
- `telemetry.sdk.version` — OTel SDK version
- `otelcol_*` metric name prefix — indicates OTel Collector deployment
