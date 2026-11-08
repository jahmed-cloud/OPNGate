# Implementation review

## OPNGate rebuild

The 2.0 application separates backend workspace routers and browser workspaces, adds a current-only Networks view and authenticated console inventory API, scopes passkeys and signatures to explicit portal identities, and introduces a guided Windows deployment launcher with a scoped existing-stack update path. Existing session, mTLS, collection, history and action protocols are retained. See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for feature parity and tradeoffs.

## Current assessment

This repository contains OPNGate, a gateway management console, plus a separate deployable WAF. Caddy/Coraza/OWASP CRS performs HTTP inspection; the portal provides authentication, telemetry and signed control workflows. Default WAF mode is DetectionOnly. Actual enforcement must be validated at the edge.

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


## One-second flow streaming follow-up

Device labels previously used 30-second inventory rates and their branches were static. Agent 1.5.0 adds dedicated one-second PF/interface counters, cached IP/MAC bindings, final-record parsing and duplicate/unknown-interface filtering. Ingest replaces a bounded RAM frame; the portal fans out SSE through one-slot queues and uses one-second JSON fallback. MAC/IP/segment matching avoids stale address attribution. Sessions retain idle expiry and are rechecked during streams. Full telemetry storage runs outside the ingest event loop. Validation: 108 Python tests and DOM/stream behavior harnesses; production evidence belongs in docs/STATUS.md. Settings initialization also has regression and real read-only-container coverage, preventing a live-directory default from breaking the WAF shipper that imports the shared settings module.

## Live-feed performance follow-up (original two-second release)

Current rates now use a dedicated two-second interface-counter worker and mTLS `/v1/live` snapshot ingestion, separate from 30-second historical/device/security telemetry. Authenticated revision-based JSON polling avoids sample aggregation and preserves idle expiry. Overview/Traffic history refreshes every 60 seconds using mounted DOM reconciliation. The Traffic rolling graph uses bounded real browser-session observations, with missing-data gaps. CrowdSec network I/O runs only in its background worker; pages display cached state and freshness.

The regression suite includes live API authorization/revisions/fallback/staleness, history isolation, slow CrowdSec refresh without page blocking, retention of stale bans, counter-baseline behavior, SVG identity and path updates, and live-series gap handling. Deployment verification is recorded in docs/STATUS.md. The live feed is near-real-time; collection plus polling and public-network transit still introduce delay.

## Network flow and adjacent UI review

Map rates/activity and Traffic bandwidth bars now follow the two-second feed. The map has its own authenticated, history-free fragment endpoint for 30-second device updates and expansion. History responses leave the mounted map untouched; superseded map requests are cancelled and discarded. Device lists are bounded to eight per expanded network in stable MAC order; collapsed networks load counts only. Device animation is removed, while trunk animation respects pause/hidden/stale state. Map timeout failures have local retry feedback. Validation: 94 Python tests and JavaScript syntax/DOM regression checks passed. Runtime observations and rollback locations are recorded in docs/STATUS.md.

## November 8 security follow-up

The revised [security assessment](docs/SECURITY_ASSESSMENT.md) records the 2.0.1 authentication hardening, local regression coverage and pending external checks. It supersedes the November 6 pentest draft’s backend, CSP and origin-bypass assumptions. Earlier test counts and runtime observations above describe their respective releases.

## November 8 deployment follow-up

The Windows launcher now defaults to one-command Deploy, with the same `deploy` entrypoint on POSIX systems. Existing updates stage and back up both hosts, build and verify all application images before activation, check exact running image IDs plus telemetry/public auth, and retain scoped rollback without restoring stale database contents. Incomplete/failed host detection cannot fall through to fresh installation. The final Windows command completed on production; private configuration fingerprints remained unchanged. Validation: 178 Python tests, including 31 deployment tests, plus existing browser harnesses and launcher syntax checks. See [INSTALL.md](docs/INSTALL.md) for recovery limits and [STATUS.md](docs/STATUS.md) for measured evidence. Fresh hardware installation remains a separate verification item.

## November 8 UI follow-up

The 2.0.2 cleanup preserves the layout and orange branding while reducing duplicated status text, grouping device controls and correcting mobile overflow/navigation/refresh access. Client rendering batches overlapping updates into animation frames and reuses mounted-node lookups; it preserves existing point/transport bounds and invalidates references after fragments change. Networks no longer marks fresh same-second live timestamps as stale. Validation: 180 Python tests, JavaScript syntax and the expanded DOM/stream harnesses; sample-data desktop/mobile and keyboard checks. See STATUS.md for rollout evidence and PERFORMANCE.md for the limits of the performance claim.
