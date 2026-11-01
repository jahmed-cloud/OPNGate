# Metrics and performance

## Time and aggregation

Rendered timestamps and historical chart axes follow the browser time-zone cookie (PORTAL_TZ, then UTC as fallback); WAF daily counts remain UTC calendar days. CSV timestamps stay UTC. Telemetry is timestamped on receipt by the services host. Hover graph points for timestamps and values. The flow diagram combines one-second WAN/network and routed-device rates with names/policy/topology snapshots refreshed every 30 seconds; it is not a historical traffic graph.

Ranges are `1h`, `24h` (default), `7d` and `30d`. Unknown range values fall back to `24h`. SQLite selects the exact requested window and aggregates into epoch-aligned buckets. Python receives at most 240 rows rather than all raw samples. Each chart point is a bucket average; peak summary values come from raw sample maxima. The first and last buckets may be partial. This reduces application memory and response work, but range queries still scan the relevant SQLite samples.

Missing metric values and empty buckets stay null. Lines break across missing values. WAN states with no known observation remain unknown. Availability is up samples divided by known up/down samples. Coverage is the percentage of chart buckets containing any telemetry. Neither metric is an SLA or a duration-weighted uptime calculation; one sample can fill a large bucket. A bucket containing any known down sample is colored as down in the availability strip.

## Endpoints

All endpoints require the same signed-in session as the dashboard. Never expose session cookies in scripts, screenshots or shared requests.

| GET endpoint | Result |
| --- | --- |
| `/api/live` | Current WAN/interface/device frame with revision and separate freshness; one-second JSON fallback, no historical queries |
| `/api/live/stream` | Authenticated SSE fan-out of changed current frames; bounded latest-value queues and session rechecks |
| `/api/flow` | Map-only HTML fragment for expansion and 30-second device/topology refresh; no historical queries |
| `/api/metrics?range=24h` | JSON with range_key, start/end Unix times, bucket_seconds, points and summary |
| `/exports/metrics.csv?range=24h` | Download with UTC bucket start, width, sample count, WAN state, latency, loss, download and upload |

`end` is exclusive. CSV exports the same bounded bucket data as graphs, not raw logs. Loss is percent, latency milliseconds, throughput bits per second. Null CSV fields are empty; a missing sample is not zero traffic.

## Refresh and latency

Overview, Traffic and Clients receive authenticated server-sent events from `/api/live/stream`. Agent 1.5.0 samples interface and routed device counters every second, caching IP/MAC bindings for five seconds. Ingest replaces one bounded frame in a shared tmpfs volume instead of writing SQLite for each observation. Full inventory, DNS, VPN and security collection remains 30 seconds; action polling remains 15 seconds.

History refreshes every 60 seconds and map metadata every 30 seconds. Numeric device/network values and branch activity update in place, matched by MAC, IP and segment. Collapsed networks load counts only; expanded networks show up to eight devices in stable order. The Traffic live graph contains at most 180 real observations from three minutes of the current browser session. Missing values or gaps over ten seconds break the line. Device rates cover routed traffic, with sampling limitations; traffic switched entirely inside a subnet is not observable here.

The portal shares one producer per process. Each stream has one pending-frame slot, with four streams per session and 64 per process. Sessions are revalidated every five seconds without extending idle expiry. Hidden/paused tabs close streams. Stream failure activates one-second revision-based JSON fallback and automatic reconnect. Full HTML updates still avoid interrupting active inputs/menus; live numeric updates continue without replacing controls. Manual Refresh works while paused.

Fast interface/device rates become stale at five seconds, full-report fallback at 120 seconds, with visible age and stopped stale animations. Fresh fast counters take precedence over slow averages. One second is the nominal sampling cadence; collection, network transit and scheduling still add latency. See [LIVE_STREAM.md](LIVE_STREAM.md) for limits, RAM storage, authentication and deployment checks.

CrowdSec decisions refresh in a background worker every 30 seconds. Rendering never fetches CrowdSec synchronously. First load shows a loading state; errors retain the last known snapshot with freshness/error labels. A snapshot older than 60 seconds is marked stale. Reported ban durations count down from the cached observation.

Responses include `Server-Timing: app;dur=...` for application response preparation. This excludes internet round-trip time and is not a firewall ping measurement. Gateway latency comes from the agent's gateway observation. Dashboard optimization does not change ISP latency. No hardware performance gain is claimed without measurements on the target Pis.

## WAF counts

Only Coraza audit evidence contributes to new charts: `is_interrupted: true` is blocked; a non-interrupted transaction with rule messages is detected-only. These categories are disjoint and count transactions, not individual rule matches. Generic access-log 403s and audit records with no match are excluded. Old `blocked`/`detected` counters remain in storage but are identified as legacy and excluded from new totals.

The chart covers today and the preceding six UTC calendar days. A zero can mean no events or missing logs. Shipper contact confirms the reporting process contacted the portal, not that the WAF is active. New shippers persist pending batches and retry the same batch ID; receipt IDs prevent duplicate counting within the configured retention period. Deploy the updated portal before the shipper. Older shippers lack this guarantee.
