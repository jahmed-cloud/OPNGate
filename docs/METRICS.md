# Metrics and performance

## Time and aggregation

Rendered timestamps and historical chart axes follow the browser time-zone cookie (PORTAL_TZ, then UTC as fallback); WAF daily counts remain UTC calendar days. CSV timestamps stay UTC. Telemetry is timestamped on receipt by the services host. Hover graph points for timestamps and values. The flow diagram is a timestamped snapshot, not a historical traffic graph.

Ranges are `1h`, `24h` (default), `7d` and `30d`. Unknown range values fall back to `24h`. SQLite selects the exact requested window and aggregates into epoch-aligned buckets. Python receives at most 240 rows rather than all raw samples. Each chart point is a bucket average; peak summary values come from raw sample maxima. The first and last buckets may be partial. This reduces application memory and response work, but range queries still scan the relevant SQLite samples.

Missing metric values and empty buckets stay null. Lines break across missing values. WAN states with no known observation remain unknown. Availability is up samples divided by known up/down samples. Coverage is the percentage of chart buckets containing any telemetry. Neither metric is an SLA or a duration-weighted uptime calculation; one sample can fill a large bucket. A bucket containing any known down sample is colored as down in the availability strip.

## Endpoints

All endpoints require the same signed-in session as the dashboard. Never expose session cookies in scripts, screenshots or shared requests.

| GET endpoint | Result |
| --- | --- |
| `/api/live` | Small current WAN/interface snapshot with revision, report timestamp, source and stale state; no historical queries |
| `/api/metrics?range=24h` | JSON with range_key, start/end Unix times, bucket_seconds, points and summary |
| `/exports/metrics.csv?range=24h` | Download with UTC bucket start, width, sample count, WAN state, latency, loss, download and upload |

`end` is exclusive. CSV exports the same bounded bucket data as graphs, not raw logs. Loss is percent, latency milliseconds, throughput bits per second. Null CSV fields are empty; a missing sample is not zero traffic.

## Refresh and latency

Overview and Traffic poll the authenticated `/api/live` endpoint every two seconds while visible and unpaused. The firewall agent samples only interface counters on a dedicated two-second worker and pushes `/v1/live` through the existing mTLS listener. This feed replaces one current snapshot; it does not add historical rows. Device, DNS, VPN and security collection remains on the full-report interval (default 30 seconds); signed action polling remains 15 seconds.

Historical Overview/Traffic fragments refresh every 60 seconds. Recursive keyed reconciliation updates text, attributes and chart paths while retaining mounted elements, rather than replacing the entire dashboard. The Traffic live graph contains up to 90 real observations from the last three minutes of the current browser session. Missing values or gaps over ten seconds break the line. It is not persisted, reconstructed history or interpolated traffic.

Clients send `X-Live-Revision` with the last snapshot revision. An unchanged response returns 204 after checking the session; changing freshness also changes the revision. Each read is bounded to current snapshots and at most 64 interfaces. Requests use `X-Auto-Refresh: 1` so polling does not extend session idle expiry. Responses remain no-store. Legacy agents fall back to full-report rates and are labeled accordingly. Fast counters become stale at 20 seconds, full-report fallback at 120 seconds; report age remains visible.

Polling pauses while the tab is hidden, live updates are paused, or an input/menu/selection is active. Fetches time out after ten seconds; manual Refresh works while automatic updates are paused. Updates normally appear after a two-second sample plus a two-second browser check, with network/processing time on top. This is near-real-time monitoring, not a subsecond guarantee.

CrowdSec decisions refresh in a background worker every 30 seconds. Rendering never fetches CrowdSec synchronously. First load shows a loading state; errors retain the last known snapshot with freshness/error labels. A snapshot older than 60 seconds is marked stale. Reported ban durations count down from the cached observation.

Responses include `Server-Timing: app;dur=...` for application response preparation. This excludes internet round-trip time and is not a firewall ping measurement. Gateway latency comes from the agent's gateway observation. Dashboard optimization does not change ISP latency. No hardware performance gain is claimed without measurements on the target Pis.

## WAF counts

Only Coraza audit evidence contributes to new charts: `is_interrupted: true` is blocked; a non-interrupted transaction with rule messages is detected-only. These categories are disjoint and count transactions, not individual rule matches. Generic access-log 403s and audit records with no match are excluded. Old `blocked`/`detected` counters remain in storage but are identified as legacy and excluded from new totals.

The chart covers today and the preceding six UTC calendar days. A zero can mean no events or missing logs. Shipper contact confirms the reporting process contacted the portal, not that the WAF is active. New shippers persist pending batches and retry the same batch ID; receipt IDs prevent duplicate counting within the configured retention period. Deploy the updated portal before the shipper. Older shippers lack this guarantee.
