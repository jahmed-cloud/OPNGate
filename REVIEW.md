# Implementation review

## Current assessment

This repository contains a gateway management portal plus a separate deployable WAF. Caddy/Coraza/OWASP CRS performs HTTP inspection; the portal provides authentication, telemetry and signed control workflows. Default WAF mode is DetectionOnly. Actual enforcement must be validated at the edge.

The current Compose deployment uses Cloudflare-proxied DNS and WAN IPv4 forwarding to Caddy. Earlier design discussion of Cloudflare Tunnel and services ports 8000/8443 is historical; current external services ports are 9443/9444/9080. Follow [RUNBOOK.md](docs/RUNBOOK.md).

## Changes from the first implementation

- Replaced full raw-sample dashboard loads with bounded SQL aggregation and added authenticated metrics JSON/CSV.
- Added UTC axes/tooltips, missing-data gaps, coverage and sample-based availability, latency/loss summaries, throughput peaks and timestamped flow snapshots.
- Exposed device search and alert source/severity filters, with bounded result lists and parameterized queries.
- Added fragment refresh, manual refresh, pause controls, failure feedback and fetch timeouts.
- Corrected WAF attribution: generic HTTP 403s do not establish WAF blocking. New counters use Coraza interruption/match evidence and exclude ambiguous legacy counts.
- Added persisted retry batches and receipt deduplication to the new WAF shipper protocol; moved pruning from every 15 seconds to hourly.
- Fixed browser-normalized login redirect targets, guarded alert return locations, rejected non-finite telemetry values and preserved unknown WAN state.
- Limited Coraza audit parts to avoid full credential-bearing headers/bodies. Rule messages can still be sensitive.
- Disabled control actions in the supplied agent example until explicitly provisioned.

## Verification boundaries

The local automated suite exercises software-authenticator login and signed-action verification, including OpenSSL ES256/Ed25519 checks; agent collectors against captured command output; authenticated page rendering; bounded month-long metrics; missing/unknown data; filters, exports, redirect safety and WAF ingestion. JavaScript syntax is checked with Node. These checks do not establish browser layout quality, deployed performance or real network enforcement.

No production gateway configuration is changed by this review. Raspberry Pi ARM builds, real OPNsense command output, physical keys, live CrowdSec parsing, Cloudflare paths and host firewall rules must pass the runbook gates. See [SECURITY.md](docs/SECURITY.md) for remaining action delivery, DHCP/IP reassignment, log rotation and trust-display limitations. A compromised portal cannot forge an operator signature unattended, but could misrepresent the action an operator approves.

Performance changes reduce graph result size and Python memory work. They do not reduce ISP latency, and no target-hardware speedup is claimed without a benchmark.
