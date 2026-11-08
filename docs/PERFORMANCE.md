# Performance architecture

The five requested improvements are implemented as follows. The later [one-second live-flow release](LIVE_STREAM.md) supersedes the original two-second counter pipeline:

| Requirement | Implementation |
| --- | --- |
| Keep page/charts mounted | Recursive keyed DOM reconciliation; update text/attributes/paths in place; browser-owned live chart is preserved |
| Frequent inexpensive collection | Dedicated one-second interface/PF device counters; cached neighbors; independent baselines/TLS client; full collection 30 s, actions 15 s |
| Background CrowdSec | 30 s background refresh, immediate cached reads, loading/last-success/error/stale display |
| Separate current/history | `/v1/live` replaces one RAM frame; SSE fan-out shares bounded current reads; no per-frame SQLite writes; history/CSV stay separate |
| Revision-based browser updates | Authenticated SSE with one-second revision-based JSON fallback; bounded queues; hidden/pause cleanup; idle expiry and session revocation preserved |

The Traffic page adds a rolling three-minute live WAN graph based on real reports observed since opening the page. It keeps at most 180 points and does not connect missing values or gaps over ten seconds. Full history continues to use raw 30-second samples aggregated into at most 240 time buckets and refreshes every 60 seconds. Device rates now use the one-second worker; gateway latency, DNS and security details remain on the full telemetry cadence.

## Network flow follow-up

The Overview map stays mounted during history refreshes. WAN, network and device labels/activity levels use the one-second stream, and Traffic bandwidth bars follow the same feed. Device/topology refreshes use a separate authenticated `/api/flow` fragment every 30 seconds. Expanding a network requests only that fragment, with cancellation and expansion-state checks to discard superseded responses. No history aggregation runs for a map request.

Collapsed networks load counts only; expanded networks load at most eight online devices each, ordered by MAC so fluctuating traffic does not reorder cards. Device branches animate from fresh measured rates; stale/hidden/paused/off-screen and reduced-motion states suppress animation. Network trunk animations stop when paused, hidden or stale. Existing layout, interface icons and signed device controls remain in place. No database migration or firewall rule change is required.

Validation for this follow-up: 94 Python tests, JavaScript syntax and the DOM/series/tooltip harness pass. Regression coverage verifies map authorization, history isolation, collapsed count-only loading, stable order and preservation of the owned map during history reconciliation.

Do not confuse speed-test dashboard lag with actual gateway/ISP latency. This change improves the display pipeline; it does not configure queue management or solve link congestion/bufferbloat. One-second collection plus command time, stream delivery and scheduling still add display delay; no subsecond guarantee is made.

Before this release, a diagnostic on the actual Pi measured Threats at about 2160 ms on first rendering with synchronous CrowdSec access versus 3 ms cached. Other warm page renders were around 9–13 ms. On OPNsense, ten read-only netstat counter commands measured a 5.05 ms median and 5.26 ms maximum. These are short samples, not throughput or production-load guarantees. Post-deployment measurements belong in STATUS.md.

Validation commands:

```sh
python -m pytest -q portal/tests
node --check portal/app/static/portal.js
node portal/tests/test_refresh_dom.cjs
```

Use the configured virtual environment. Windows TestClient may need normal localhost-socket access outside the restricted executor sandbox. Tests use synthetic data and software authenticators.


Post-deployment verification (2026-11-01): current snapshot reads on the services Pi measured 0.361 ms median (20 reads), representative JSON 822 bytes. Six successive observed report timestamps advanced exactly 2 s apart and no extra historical rows were written in the 12 s diagnostic. A signed-in production browser plotted real live reports without console errors and retained its rolling chart across manual refresh. See STATUS.md for precise scope and remaining observation work.

## Browser painting and UI stability (2026-11-08)

The 2.0.2 follow-up batches live text/chart paints into one animation frame when SSE, timer or fragment work overlaps. Browser observations are still collected individually and retained within the existing 180-point history; coalescing rendering does not discard observations. Live element queries are cached for the mounted page and invalidated after main/map fragment reconciliation. One-second collection/transport and 30/60-second metadata/history work remain unchanged.

The stream harness verifies one paint for a burst of reports, retention of each observed point, reuse/invalidation of mounted node references, manual chart refresh while paused, and correct handling of hidden nested menu sections. These assertions establish reduced redundant work, not a measured production frame-rate gain. The full Python suite has 180 passing tests.

UI stability changes include fixed minimum rate-column widths, contained table scrolling, bounded dropdowns/tooltips, shorter status text and stable scrollbar space. Mobile keyboard/navigation and 320/390-pixel layouts were checked with sample data. The Networks freshness fix also removes false stale labels caused by comparing fractional received timestamps with integer time. Current production verification belongs in STATUS.md.
