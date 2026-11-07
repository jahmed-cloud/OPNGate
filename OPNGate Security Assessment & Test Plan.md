# OPNGate Security Assessment & Test Plan

Reviewed: 2026-11-08 (Asia/Calcutta). Supersedes the November 6 draft.

This is an owner-scoped assessment plan, not a completed penetration-test certificate. The November 8 work consists of source review, isolated automated tests and normal live requests. Active production scans, credential attacks and load testing have not been run. See [assessment results](docs/SECURITY_ASSESSMENT.md) and [security limitations](docs/SECURITY.md).

## Scope and safeguards

- Approved portal: `https://opngate.jahmed.cloud`. Other published applications, the firewall WebGUI, unrelated subdomains and ISP systems are outside this plan unless separately authorized.
- Origin verification covers only an owner-supplied address. Do not discover or scan unrelated addresses. A public external vantage is required; a successful request from the trusted LAN does not establish public exposure.
- Default execution is local: synthetic users, disposable test databases, software authenticators and a simulated firewall. No test should execute a real block, shaper or device pause.
- Before authenticated staging tests, save the credential database and configuration privately and confirm an independent recovery path. Use disposable test accounts. Keep real cookies, recovery codes, private keys and raw auth/WAF logs out of commands, reports and Git.
- Active testing remains owner-run in a separately agreed window. Start on staging; allowlist routes and test templates, use one worker and at most one request per second initially. This is a starting budget, not a guarantee of safety on a Pi. Stop on elevated errors, latency or telemetry delay.
- Exclude logout, authenticator changes, action creation/approval and other state changes from crawlers. No destructive payloads, brute-force volume, stress tests or automatic production remediations.

## Actual architecture and trust boundaries

| Boundary | Implementation | Assessment focus |
| --- | --- | --- |
| Internet to edge | Cloudflare proxy, then Caddy with Coraza/OWASP CRS and CrowdSec | Public origin restrictions, client-IP trust, WAF enforcement and legitimate application compatibility |
| Browser to portal | Python FastAPI, SQLite, passkeys or password plus TOTP/recovery code | Sessions, CSRF/origin validation, roles, bounded parsing and auth resource use |
| Firewall to ingest | Separate certificate-authenticated TLS listener | Listener isolation, CA/client-certificate enforcement and bounded telemetry |
| Telemetry to browser | Authenticated current-state JSON/SSE, separate historical queries | Expiry/revocation, connection limits, stale data and slow consumers |
| Portal to firewall controls | Allowlisted canonical action plus operator assertion; agent verifies independently | Role and CSRF checks, payload binding, expiry, replay, independent key trust and execution limits |
| Edge log shipper to portal | Internal endpoint with token and trusted source checks | Separate batch budget, public route rejection and receipt deduplication |

The portal is not a Go backend. Caddy/Coraza is the Go edge component. Browser flow queries read telemetry already collected by the agent; they do not accept arbitrary shell commands or proxy destinations. Signed mutations still deserve targeted review because they can change firewall state.

## Corrections to the earlier draft

| Earlier statement | Reviewed result |
| --- | --- |
| CSP is `form-action *`; replace with self only | Current source and November 8 login response use `'self' https://*.jahmed.cloud`. The configured sibling domain supports forward-auth redirects. A self-only change could break that workflow. An explicit sibling allowlist is a possible future tightening, after inventorying the required destinations. |
| Public console JavaScript is a vulnerability | Public client assets and endpoint names are expected. Audit them for secrets and enforce authorization on every server route; hiding the bundle is not an authorization control. |
| An unsupported POST returning 405 suggests auth bypass | 405 means that method is unavailable; it does not show protected content was returned. Test each implemented method and its effects. |
| A direct origin request bypasses every WAF and security header | It can bypass Cloudflare-specific controls. Caddy runs its own Coraza policy, and the portal sets its own headers. Verify these layers independently. |
| Add HSTS preload as routine hygiene | Preload affects a domain and its subdomains over time. Keep it a separate owner decision after auditing the full domain; no preload change is made here. |
| ZAP baseline performs light active attacks | Baseline spiders the site and applies passive analysis. Spidering still sends requests and needs scope and action exclusions. See [ZAP baseline documentation](https://www.zaproxy.org/docs/docker/baseline-scan/). |
| Every cross-origin login redirect is invalid | Configured HTTPS cookie-domain siblings are intentional. Reject unrelated origins, suffix tricks, userinfo, backslashes and control characters. |

A missing `security.txt` is an optional reporting-channel improvement, not proof of compromise. Publish one only with a real maintainer contact and expiry. No contact information is invented by this review.

## Evidence levels and current status

| Evidence | Result | Limits |
| --- | --- | --- |
| November 8 source review and local regressions | Authentication parser, body-budget, limiter-state, session-replacement and passkey-counter fixes implemented | Synthetic users and local services; not a complete external pentest |
| November 8 normal public login GET | 200 through Cloudflare; no-store, CSP, HSTS and nosniff present | Does not establish all routes, direct-origin rejection or authenticated behavior |
| November 8 read-only host inspection | Caddy configured with WAF mode On; portal, ingest and shipper running | Configuration and heartbeat alone do not prove a request was blocked |
| November 5 controlled WAF check, recorded previously | XSS test changed from 200 in DetectionOnly to 403 with Coraza interruption evidence in On mode | Historical point-in-time evidence; not rerun as an active scan in this review |
| External direct-origin and IPv6/service exposure | Pending | Requires an owner-controlled public test host and known origin address |
| Real physical-key controls and authenticated app compatibility | Pending normal-use verification | Software signatures and unauthenticated HTTP checks do not replace these workflows |

## Authentication and authorization matrix

Run the automated cases locally first. Production accounts must not be used for lockout, replay or malformed-request experiments.

| ID | Check | Existing local coverage / remaining work |
| --- | --- | --- |
| A1 | Generic failures and username enumeration | Generic login failure and dummy Argon2 hash are present. Statistically meaningful timing comparison remains a staging exercise, not a constant-time guarantee. |
| A2 | Password/TOTP throttling and memory growth | `test_e2e.py` covers throttling; `test_security_assessment.py` covers bounded key state, churn, capacity and retained active lockouts. Restart resets the in-process limiter; distributed limits are not claimed. |
| A3 | Required second factor and TOTP/recovery replay | `test_e2e.py` verifies password alone fails and TOTP/recovery codes cannot be reused. Keep these tests on disposable users. |
| A4 | WebAuthn origin, RP, challenge and user binding | `test_e2e.py` and `test_identity.py` cover signature/origin/RP failures and configured identity selection. Add browser/physical-authenticator verification after relevant identity changes. |
| A5 | Concurrent signature counter changes | `test_security_assessment.py` races real signed assertions and verifies a stale counter update fails. Authenticators with legitimate zero counters remain supported. Counterless keys rely on challenge/signature validation. |
| A6 | Challenge expiry and reuse | Existing challenge handling consumes stored challenges once. New malformed-envelope tests ensure invalid JSON does not consume an otherwise valid challenge. Check simultaneous challenge-cookie flows in staging if that workflow changes. |
| A7 | Session replacement, cookies and stream revocation | New tests revoke only the presented old session on login and verify production cookie attributes. `test_live_stream.py` checks revoked-session stream shutdown. Confirm idle/absolute expiry in a real browser. |
| A8 | Safe `next` redirects | `test_redirects.py` and `test_identity.py` cover configured identity behavior. Local paths and configured HTTPS siblings are allowed intentionally. |
| B1 | Implemented methods and viewer/operator authorization | `test_e2e.py` and `test_blocking.py` cover guards and control actions. Unsupported methods must not mutate state; 404/405 alone is not a finding. |
| B2 | CSRF and trusted client IP | Existing origin/CSRF and untrusted `X-Real-IP` tests. Validate immediate proxy peers on the actual deployment; never trust arbitrary forwarded headers. |
| B3 | Signed mutation integrity | Existing end-to-end portal/agent tests cover tampering, replay and expiry. Real hardware action verification remains a separate normal-use check. |
| B4 | JSON/form parsing and body budgets | New tests cover malformed UTF-8/JSON, non-object envelopes, invalid credential fields, excessive nesting, declared/chunked bodies, disconnects and shipper budget isolation. |
| B5 | Historical/current telemetry isolation | Existing dashboard, flow, performance and live-stream tests verify bounded queries, RAM current frames, slow-consumer coalescing and session-gated output. |
| B6 | Injection, SSRF and file access | Source review should follow actual route parameters into SQLite, file access and agent action validators. Do not assume an arbitrary URL proxy or shell exists. Revisit whenever a new mutation or import/export route is added. |
| B7 | Authenticated resource use | Per-key limits and body budgets are covered. Argon2 CPU/memory cost, concurrent authenticated sessions and sustained Pi workload still need staging measurements. |

## Origin, TLS and network verification

1. From an external host, send one normal request to the owner-supplied origin using the portal hostname/SNI. Verify certificate validation; if the origin intentionally uses a private or origin-only CA, supply that CA rather than silently disabling verification. A TLS failure alone does not prove the port is unreachable.
2. Check both relevant IPv4 and IPv6 routes and the actual exposed services ports. The services and ingest listeners must remain restricted; unknown origin/service exposure stays pending until externally verified.
3. Confirm Caddy's Cloudflare matcher evaluates the immediate peer address, not a spoofable client header. Review intentional private-network exceptions separately. See [Caddy request matchers](https://caddyserver.com/docs/caddyfile/matchers).
4. Verify Cloudflare restrictions, Caddy/Coraza enforcement, portal headers and ingest client-certificate checks as separate controls. An abort, TLS denial or firewall rejection may each be appropriate for its layer; not every policy produces a timeout.
5. Save only redacted status, certificate and policy evidence. Keep real origin addresses, firewall exports and keys in private operational records.

Example normal public request (no authentication or attack payload):

```sh
curl --fail --silent --show-error --max-time 15 --output /dev/null \
  --write-out 'status=%{http_code} total=%{time_total}s\n' \
  https://opngate.jahmed.cloud/login
```

## Automated tooling workflow

1. Use the checked-in local suite first. On Windows, follow the Python environment and OpenSSL prerequisites in the README:

   ```powershell
   ./portal/.venv/Scripts/python.exe -X utf8 -m pytest -q portal/tests deploy/tests
   node portal/tests/test_refresh_dom.cjs
   node portal/tests/test_live_stream.cjs
   ```

2. For a staging ZAP session, explicitly constrain the context to the test origin, use disposable credentials, exclude state-changing routes, limit crawl duration and review every enabled rule. Baseline is spidering plus passive analysis, not proof of authenticated coverage. A command without a login context is not an authenticated scan.
3. Review selected scanner templates and their actual requests before enabling them. The previous broad Nuclei categories and large FFUF wordlists are removed from the default plan: concurrency and a nominal request limit do not make arbitrary templates harmless.
4. Check the origin TLS path separately from Cloudflare TLS. Record tool/template versions and which hop was tested. An edge TLS score says nothing about ingest mTLS or internal upstream certificate verification.
5. Classify each result as confirmed, rejected with evidence, or pending. Redact request bodies, tokens, private addresses and user data before sharing. Record the exact tested commit and retain private evidence outside Git.

## Next priorities and completion criteria

1. Complete external origin/IPv6/services-listener checks; remediate only a confirmed deployment gap.
2. Measure auth concurrency and real one-second telemetry under controlled staging load; choose an explicit Argon2 concurrency budget if measurements require it.
3. Implement Coraza serial audit rotation with identity-aware shipper offsets and retention, then test rename, truncate, replacement and restart cases without double-counting or silent gaps.
4. Verify normal signed controls on real hardware and authenticated Vaultwarden edit/upload/sync under WAF On.
5. Continue action delivery/retry and DHCP address-reassignment review; these existing limitations are documented, not resolved by the parser fixes.

A phase is complete only when its evidence and limits are recorded. Local test success does not close external-network, physical-authenticator or sustained-load items.
