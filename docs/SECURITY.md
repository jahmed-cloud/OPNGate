# Security model and limitations

## Trust boundaries

The browser-facing portal requires passkey/FIDO2 user verification or password plus TOTP/recovery code. Operators can request allowlisted actions; the agent independently verifies the assertion and trusted key before execution. Public keys are copied from the admin workstation to the firewall, never automatically pushed by the portal. Example agent actions start disabled.

A signature prevents unattended forgery by a portal without a trusted private key. It does not provide a trusted display of transaction details: a compromised portal could misrepresent the action an operator is asked to approve. Keep management access separate, protect admin workstations and inspect action parameters.

Agent ingest is a separate TLS listener requiring a certificate from the private CA. Its application routes rely on that TLS listener and network isolation; do not expose the ingest ASGI app through an ordinary public reverse proxy. The WAF shipper uses a shared token and a trusted source address; `/internal/*` is refused at the public edge.

## WAF configuration

Caddy imports Coraza and OWASP CRS for published sites. `WAF_MODE=DetectionOnly` records matches; `On` enables disruptive rules; `Off` disables inspection. Tune exclusions narrowly and validate each application before enabling blocking. Dashboard counts cannot verify engine mode, coverage or successful enforcement. CrowdSec bans and OPNsense/Suricata protection are separate controls.

Coraza audit parts are limited to AHZ to omit full headers and bodies. Rule messages, URLs and matched fragments may still contain sensitive data. Audit files currently need to be readable by the separate shipper; restrict access to the host and Docker volumes. Configure operational rotation and retention for the serial Coraza audit log; unlike the Caddy access log, it has no supplied automatic rotation. Avoid posting raw audit logs or authentication traces publicly.

## Deployment limits

- Flat-LAN host firewall rules are interim protection; a rooted host can remove them. Use routed VLANs for real network boundaries. The supplied host firewall is IPv4-oriented; audit IPv6 separately before exposing it.
- CrowdSec LAPI uses HTTP on the restricted services link. Add TLS or an appropriately isolated network before using it across untrusted links.
- The optional HTTPS upstream template disables upstream certificate verification. Provision and trust internal certificates before relying on that hop.
- Coraza serial-log reading handles truncation but byte offsets alone cannot reliably detect every rename/replace rotation. Reconcile logs/counts after rotation; counts are operational indicators, not billing or forensic evidence.
- An interrupted action-fetch response may leave an action marked fetched. Inspect the action status and actual firewall state before retrying. Paused-device IP reassignment needs care; stale table entries may affect another device after DHCP changes.
- Container certificate access currently uses a host-readable services key. Keep its directory private, limit host users and rotate credentials after suspected exposure.
- Real OPNsense versions, physical authenticators, Raspberry Pi ARM builds, CrowdSec live parsing and your Cloudflare/network rules require deployment gate tests.

## Secrets and reporting

Never publish `.env`, `deploy/pki/out/`, private keys, operator recovery codes, databases or network backups. Ignore rules do not remove secrets already committed to history. If a secret is exposed, revoke/rotate it and assess history removal separately.

For a suspected vulnerability, use GitHub private vulnerability reporting if enabled or contact the maintainer through an established private channel. Do not put credentials or exploitable deployment details in a public issue. Stop both stacks and the agent if compromise is suspected; restore from known-good backups and rotate affected keys.


## Current-state feed

`/v1/live` is available only on the existing mTLS ingest listener. `/api/live` requires a valid portal session even for unchanged revisions, and only returns display telemetry. Polling does not extend the idle timeout; the live transport has no action or privilege-changing capability. No dashboard/API responses are publicly cacheable. Browser graphs retain at most 90 live observations in memory and expose their freshness. Background CrowdSec cache errors never imply that bans are absent; last-known snapshots are explicitly labeled.
