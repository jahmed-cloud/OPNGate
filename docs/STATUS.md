# Project memory and pending work

Updated: 2026-11-01 (Asia/Calcutta).

## User preferences

- Preserve current sidebar/dashboard layout and orange-neutral branding.
- Git author/committer: Junaid Ahmed <jahmed.cloud@outlook.com>, no coauthor trailers.
- Deploy authorized changes to the existing stack over the saved SSH key, preserving credentials, PKI, configuration, database volumes and action trust.

## Current release

Gaming follow-up (2026-11-01): MGMT-to-WAN FQ-CoDel is active at 285/285 Mbit/s for the confirmed 300/300 Mbps service. Both kernel schedulers verified as FQ_CODEL with rising counters; only TrafficShaper and revision metadata changed. No Riot route override was added. Short before/after probes showed no loss and approximately 7 ms PC-to-Internet average; a loaded-latency comparison and actual Mumbai-match packet-loss validation remain pending. Other segments remain unshaped. See GAMING_NETWORK.md for scope, tuning and private rollback locations.

Agent 1.4.1 and matching shaper.php are deployed on OPNsense. Device-cap removal now deletes only pipe numbers explicitly removed by that device's tagged model operation, preserving manual gaming pipes. Regression validation: 97 Python tests passed; PHP helper lint and read-only model listing passed on the firewall. Agent credentials, state and operator trust preserved. Source rollback files end in `.gaming-backup`.

Network-flow follow-up is also live (2026-11-01): two-second WAN/network map rates, live Traffic bandwidth bars, separate 30-second map/device fragments, count-only collapsed segments, bounded stable device ordering, cancelled superseded expansion requests and reduced/paused animation. Validation: 94 Python tests plus JavaScript syntax/DOM/series/tooltip checks passed.

Portal rebuilt/restarted on Pi 4 and matching WAF shipper rebuilt/restarted on Pi 5. Ingest and firewall agent continue unchanged. Production browser verified CSS 34 / JS 20, fresh rates, WiFi collapse/expand and manual Refresh preserving expansion; no captured browser errors. Public unauthenticated `/api/flow` returns 401. A read-only map rendering diagnostic with all networks expanded measured 3.988 ms median over 20 renders (cold 148.308 ms; HTML 23,482 bytes). This excludes authentication middleware and public network latency. Portal resource sample: 1.71% CPU / 58.34 MiB, not a load-test guarantee.

Flow rollback copies: `/opt/gateway/releases/flow-before.tgz` on both Pis, `gw-services-portal:flow-rollback` and `gw-edge-waf-shipper:flow-rollback`. Temporary upload archives removed after verification; rollback archives retained.

All five performance changes are implemented. Local validation: 91 Python tests and the JavaScript DOM/series harness pass. Deployed to the existing stack and verified on 2026-11-01. All five requested changes are live.

## Deployment checklist

- Verified: portal and ingest rebuilt/restarted on Pi 4 (10.10.0.22).
- Verified: matching WAF shipper rebuilt/restarted on Pi 5 (10.10.0.21).
- Verified: agent 1.4.0 installed on OPNsense management address 10.99.99.1; agent.json, state and operator trust preserved.
- Verified: six observed snapshot timestamps advanced exactly 2 s apart, with 0 extra historical rows during the 12 s diagnostic.
- Verified: current snapshot reads measured 0.361 ms median across 20 reads; representative JSON size 822 bytes; unchanged revision returned 204 in the deployed handler diagnostic. Public unauthenticated request returned 401, login 200.
- Verified: cold diagnostic Threats rendering 160.84 ms and warm 30.35 ms with its CrowdSec refresh running separately; no synchronous CrowdSec wait in rendering.
- Verified in the signed-in production browser: fresh rate age, rolling real observations, graph retained through manual Refresh, and no browser error logs. Mounted SVG/path identity also covered by DOM regression harness.
- Resource sample: portal 1.72% CPU / 57.16 MiB, ingest 0.26% CPU / 39.16 MiB; these are point-in-time samples, not load-test guarantees.
- Rollback: source archives under /opt/gateway/releases/performance-before.tgz, Docker tags ending performance-rollback, and fw_agent.py.performance-backup on the firewall. Retain these until a full normal-use observation cycle passes.

## Remaining work outside this release

- Observe performance during an actual user-run speed test and sustained multi-viewer use; no speed test is run automatically.
- Audit log rotation/retention and action delivery/DHCP reassignment limitations described in SECURITY.md remain tracked.
- End-to-end counter/poll timing is approximate; subsecond streaming is not promised.
