# WAF operations

OPNGate is the gateway console. Caddy with Coraza and OWASP CRS is the web application firewall on the edge. The edge configuration and actual interruption evidence establish enforcement; a dashboard label, shipper heartbeat or generic HTTP 403 alone does not.

## Modes

- `DetectionOnly`: inspect and record rule matches without disruptive actions.
- `On`: enforce disruptive rule decisions.
- `Off`: no WAF inspection.

New deployments start in DetectionOnly. Review legitimate logins, API methods, uploads and WebSockets before enabling blocking. The amount of representative application traffic and unresolved false positives matters more than a fixed number of elapsed days.

## Vaultwarden method policy

The Caddy rules set `tx.allowed_methods` to include PUT, PATCH and DELETE only for the Vaultwarden hostname's `/api/` paths. Method restrictions remain enabled elsewhere, and other CRS checks continue to inspect all those API requests. This addresses the method-policy match observed on legitimate vault item updates without removing rule 911100 globally or raising anomaly thresholds.

## Apply and verify

Back up the private edge environment and Caddyfile, validate Caddy with the intended environment, set `WAF_MODE=On` in `deploy/edge/.env`, then recreate only Caddy with `docker compose up -d --no-deps caddy`. An environment-only mode change needs container recreation; validating a file does not change the running process.

Use harmless requests against sites you own. Compare the same probe before/after activation and correlate it with the Coraza audit record: `producer.rule_engine=On`, `is_interrupted=true`, and matching rule IDs. Direct-origin tests from an allowed private network establish that Coraza caused the interruption; also check the public Cloudflare path separately.

A valid unauthenticated Vaultwarden API update should reach its ordinary authentication check, rather than be rejected merely for using PUT. This is a limited compatibility check; it does not replace a real user login, vault edit, attachment upload and sync test. Never replay secret vault bodies or authentication traces as public test data.

Shipper updates normally arrive every 30 seconds. Confirm the latest engine timestamp and block events on Threats after deployment. Keep watching legitimate use; a fresh heartbeat does not establish that all application workflows have been tested.

## Rollback and remaining operations

If legitimate traffic is blocked, restore DetectionOnly and recreate Caddy, then tune narrowly by site/path/parameter. Keep the prior file and environment for rollback. Coraza serial audit-log rotation and shipper offset handling remain an operational task documented in SECURITY.md; Caddy's access-log rotation is separate.

References: [Coraza directives](https://www.coraza.io/docs/seclang/directives/), [CRS configuration](https://github.com/coreruleset/coreruleset/blob/main/crs-setup.conf.example).
