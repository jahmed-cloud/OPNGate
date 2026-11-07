# Security assessment follow-up

Reviewed: 2026-11-08. Release: OPNGate 2.0.1.

This review corrects the earlier pentest assumptions and implements concrete authentication hardening. It includes source review, isolated regression tests and normal live requests. It is not an external penetration-test certification. The [revised test plan](../OPNGate%20Security%20Assessment%20%26%20Test%20Plan.md) records scope, evidence and remaining work.

## Implemented changes

| Finding | Impact before this change | Remediation and evidence |
| --- | --- | --- |
| Malformed authentication JSON | Invalid JSON or an unexpected top-level/credential type could produce a server error before normal credential validation | Shared typed envelope parser returns 400 for invalid JSON, UTF-8, excessive nesting and invalid field types across login, step-up, registration and signed approvals. Invalid envelopes leave challenges and pending approvals untouched. |
| No application-wide browser body budget | Form/JSON parsing could allocate for large control requests | ASGI middleware caps browser mutation bodies at 128 KiB, checks Content-Length and actual chunks, and rejects over-budget bodies with 413 before form/JSON parsing. GET/SSE and WebSockets pass through. The exact internal WAF endpoint keeps its authenticated two-MiB batch budget. |
| Unbounded authentication limiter dictionaries | Repeated identity churn could retain unbounded process-local records | At most 4,096 IP/account key records, periodic inactive-record expiry, bounded failure counters and no allocation for new usernames behind an already-blocked IP. At capacity, new identities wait rather than evicting active lockouts. |
| Concurrent monotonic passkey-counter writes | Simultaneous verifications could both use the same stored count and overwrite a newer result | Conditional counter update rejects a verification whose stored counter changed. Real signed concurrent assertions are tested. Zero-counter authenticators remain supported; this does not invent clone detection for counterless keys. |
| Old presented session survived relogin | A new random cookie was issued while the old session remained valid until expiry | Creating the replacement and deleting the presented old token now happen in one SQLite transaction. Other device sessions remain valid. |
| Credential RP missing from security-page query | Template could not show the stored credential identity | The credential query now includes its existing `rp_id` column; no schema migration. |

Source: `portal/app/requests.py`, `security.py`, `wa.py`, `auth.py`, `actions.py` and `main.py`. No browser asset changes, key rotation or database schema migration are required.

## Verification

- New suite: `portal/tests/test_security_assessment.py`, using synthetic users and a software authenticator. It checks malformed envelopes across all four finish/approval routes, body limits including chunked/exact-budget/disconnected requests, separate shipper budgets and source/token rejection, limiter churn/capacity/expiry, session replacement, real signature concurrency, zero-counter compatibility and production cookie attributes.
- Complete local validation: 153 Python tests pass across portal and installer suites, including 28 new assessment regressions. JavaScript syntax and existing DOM/stream harnesses pass. One pre-existing Starlette/httpx deprecation warning remains. No CI workflow is configured; these are local results.
- Normal November 8 public login request returned 200 through Cloudflare, with no-store, CSP, HSTS and nosniff. CSP allows self plus the configured HTTPS sibling domain for forward-auth; it is not `form-action *`.
- Read-only host checks confirmed the existing On WAF configuration and running services. The previously recorded November 5 blocked probe remains historical enforcement evidence; no new active production scan was run.
- Deployment of this follow-up: pending.

## Operational tradeoffs and remaining work

The limiter is process-local and resets on restart. Keep one portal process unless a shared limiter is introduced; CrowdSec is a separate control whose live parsing and decisions need operational verification. The capacity bound denies new identities when full until inactive state ages out. It does not establish resistance to a distributed denial-of-service attack.

A body byte limit does not set a network read deadline or bound every upstream buffer. Review edge/server timeouts and measure Argon2 verification under concurrent login attempts on staging. Password hashing still runs in the current login path; this release does not claim an auth-load performance improvement.

External origin rejection, IPv6/service isolation, real hardware action approval, physical passkeys, sustained multi-viewer performance and authenticated application compatibility remain pending. Serial Coraza log rotation/identity-aware offsets, interrupted action delivery and DHCP reassignment remain tracked in [STATUS.md](STATUS.md) and [SECURITY.md](SECURITY.md).

## Deployment and rollback

Build/recreate only portal and ingest on the services host and the matching WAF shipper on the edge host. Save the prior source and image tags first. Preserve private environment files, database/key volumes, certificates, Caddy policy and native firewall settings. No firewall-agent rollout is needed for these portal-only changes.

After deployment, verify normal login/read-only auth guards, live-frame freshness, shipper contact and container stability. Do not run real-account lockout or malformed-request experiments as a production smoke test. Roll back to the saved source/images if login availability, telemetry delivery or WAF shipping regresses; do not restore a stale database over newly recorded activity for this code-only change. Physical-key login and signed controls still need the owner’s normal-use check.
