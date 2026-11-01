# Performance architecture

The five requested improvements are implemented as follows:

| Requirement | Implementation |
| --- | --- |
| Keep page/charts mounted | Recursive keyed DOM reconciliation; update text/attributes/paths in place; browser-owned live chart is preserved |
| Frequent inexpensive collection | Dedicated agent worker reads netstat interface counters every 2 s; independent baselines and TLS client; full collection 30 s, actions 15 s |
| Background CrowdSec | 30 s background refresh, immediate cached reads, loading/last-success/error/stale display |
| Separate current/history | `/v1/live` overwrites a current snapshot; `/api/live` reads bounded snapshots; no sample aggregation; history/CSV stay separate |
| Revision-based browser updates | Authenticated 2 s polls with X-Live-Revision; 204 when unchanged; visible-tab/pause/edit guards; session idle expiry preserved |

The Traffic page adds a rolling three-minute live WAN graph based on real reports observed since opening the page. It keeps at most 90 points and does not connect missing values or gaps over ten seconds. Full history continues to use raw 30-second samples aggregated into at most 240 time buckets and refreshes every 60 seconds. Per-device rates, gateway latency, DNS and security details remain on the full telemetry cadence.

Do not confuse speed-test dashboard lag with actual gateway/ISP latency. This change improves the display pipeline; it does not configure queue management or solve link congestion/bufferbloat. Two-second collection plus two-second polling and network transit can still introduce several seconds of delay.

Before this release, a diagnostic on the actual Pi measured Threats at about 2160 ms on first rendering with synchronous CrowdSec access versus 3 ms cached. Other warm page renders were around 9–13 ms. On OPNsense, ten read-only netstat counter commands measured a 5.05 ms median and 5.26 ms maximum. These are short samples, not throughput or production-load guarantees. Post-deployment measurements belong in STATUS.md.

Validation commands:

```sh
python -m pytest -q portal/tests
node --check portal/app/static/portal.js
node portal/tests/test_refresh_dom.cjs
```

Use the configured virtual environment. Windows TestClient may need normal localhost-socket access outside the restricted executor sandbox. Tests use synthetic data and software authenticators.


Post-deployment verification (2026-11-01): current snapshot reads on the services Pi measured 0.361 ms median (20 reads), representative JSON 822 bytes. Six successive observed report timestamps advanced exactly 2 s apart and no extra historical rows were written in the 12 s diagnostic. A signed-in production browser plotted real live reports without console errors and retained its rolling chart across manual refresh. See STATUS.md for precise scope and remaining observation work.
