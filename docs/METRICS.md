# Metrics and performance

## Time and aggregation

All rendered timestamps and chart axes use UTC regardless of server/browser timezone. Telemetry is timestamped on receipt by the services host. Hover graph points for timestamps and values. The flow diagram is a timestamped snapshot, not a historical traffic graph.

Ranges are `1h`, `24h` (default), `7d` and `30d`. Unknown range values fall back to `24h`. SQLite selects the exact requested window and aggregates into epoch-aligned buckets. Python receives at most 240 rows rather than all raw samples. Each chart point is a bucket average; peak summary values come from raw sample maxima. The first and last buckets may be partial. This reduces application memory and response work, but range queries still scan the relevant SQLite samples.

Missing metric values and empty buckets stay null. Lines break across missing values. WAN states with no known observation remain unknown. Availability is up samples divided by known up/down samples. Coverage is the percentage of chart buckets containing any telemetry. Neither metric is an SLA or a duration-weighted uptime calculation; one sample can fill a large bucket. A bucket containing any known down sample is colored as down in the availability strip.

## Endpoints

Both endpoints require the same signed-in session as the dashboard. Never expose session cookies in scripts, screenshots or shared requests.

| GET endpoint | Result |
| --- | --- |
| `/api/metrics?range=24h` | JSON with range_key, start/end Unix times, bucket_seconds, points and summary |
| `/exports/metrics.csv?range=24h` | Download with UTC bucket start, width, sample count, WAN state, latency, loss, download and upload |

`end` is exclusive. CSV exports the same bounded bucket data as graphs, not raw logs. Loss is percent, latency milliseconds, throughput bits per second. Null CSV fields are empty; a missing sample is not zero traffic.

## Refresh and latency

Overview/traffic refresh every 15 seconds; other pages use their displayed intervals. Live requests return content fragments, preserve idle session expiry, and pause while a field, selection or open detail is being used. A 10-second fetch timeout allows retry after failure. The live toggle is remembered locally; Refresh works while automatic updates are paused. Hidden tabs do not poll.

Responses include `Server-Timing: app;dur=...` for application response preparation. This excludes internet round-trip time and is not a firewall ping measurement. Gateway latency comes from the agent's gateway observation. Dashboard optimization does not change ISP latency. No hardware performance gain is claimed without measurements on the target Pis.

## WAF counts

Only Coraza audit evidence contributes to new charts: `is_interrupted: true` is blocked; a non-interrupted transaction with rule messages is detected-only. These categories are disjoint and count transactions, not individual rule matches. Generic access-log 403s and audit records with no match are excluded. Old `blocked`/`detected` counters remain in storage but are identified as legacy and excluded from new totals.

The chart covers today and the preceding six UTC calendar days. A zero can mean no events or missing logs. Shipper contact confirms the reporting process contacted the portal, not that the WAF is active. New shippers persist pending batches and retry the same batch ID; receipt IDs prevent duplicate counting within the configured retention period. Deploy the updated portal before the shipper. Older shippers lack this guarantee.
