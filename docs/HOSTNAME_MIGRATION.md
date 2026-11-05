# Moving the console hostname

WebAuthn passkeys are bound to an RP ID. A key enrolled for `waf.example.com` is not a key for `opngate.example.com`. Display-name changes alone do not affect passkeys.

1. Back up the portal database, private environments, Caddy configuration, agent configuration and operator public-key trust store.
2. Create proxied DNS for the new hostname. Add it to edge `PORTAL_HOSTS`, validate Caddy and recreate Caddy to obtain the matching certificate. A Cloudflare 525 indicates the origin TLS handshake needs investigation; changing DNS alone does not add a Caddy site.
3. Set services `PORTAL_SUBDOMAIN=opngate` and `PORTAL_RP_NAME=OPNGate`. Compose derives the RP ID and origin from the selected subdomain. Recreate portal and ingest together with the new release.
4. Choose a transition policy. To keep old sign-in temporarily, retain its DNS record, list both full hostnames in `PORTAL_HOSTS`, and set `PORTAL_LEGACY_ORIGIN=https://waf.example.com` in services. Old and new origin checks remain separate. To retire the old address immediately, leave the legacy setting empty and use password plus TOTP/recovery at the new address.
5. Existing credentials are tagged with their prior RP ID during the database upgrade. During a staged move, set the legacy origin before starting the upgraded application so existing untagged credentials are assigned correctly. Keep the database backup for rollback. For immediate retirement, record/backfill old credentials against the old RP ID before removing the legacy setting.
6. At the new address, enroll a new passkey. Confirm new-address sign-in and retain a separate recovery method.
7. From the trusted admin workstation, export operator public keys with `python -m app.cli export-keys`, inspect the RP ID/origin and expected operators, and manually transfer them to the firewall trust store. Update the agent action RP ID/origin to the new pair. Keep private keys, configuration and telemetry out of Git.
8. After verification, remove old DNS/Caddy hosts and the legacy origin setting. Retire obsolete credentials through Account security. Preserve backups and replay-protection state.

The agent supports an optional `actions.migration_portals` list of at most two explicit `{rp_id, origin}` pairs for a staged transition. It verifies the payload, browser origin, RP hash and signature against the same pair. It does not trust arbitrary sibling origins or automatically enroll portal keys. Leave this list absent after retirement.

See [installation](INSTALL.md), [security](SECURITY.md) and [the runbook](RUNBOOK.md).
