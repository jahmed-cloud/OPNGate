# OPNGate community announcement

Updated and published as jahmed on 2026-11-05: [OPNGate: a self-hosted OPNsense gateway console](https://forum.opnsense.org/index.php?topic=53268.0).

The existing first post was rewritten rather than creating another topic. It links [jahmed-cloud/OPNGate](https://github.com/jahmed-cloud/OPNGate), describes the console as the OPNsense visibility/management layer, and keeps Caddy/Coraza web protection separate.

The post now describes nominal one-second RAM-backed streaming, mounted chart updates, device/network flow, local-time graphs, DNS/VPN/security visibility, signed actions and the scope of firewall-observed device traffic. It labels the application rebuild and guided deployment work as in progress at the time of publication.

Two reference screenshots are embedded from the public repository: `docs/screenshots/overview-dark.png` and `docs/screenshots/clients.png`. They use sample devices and addresses, and the post explicitly identifies them as an earlier-release interface under the former name. No live telemetry, personal tuning details, credentials or private screenshots were published.

The source screenshot files remain unchanged so the post's historical-reference caption stays accurate. Current implementation and validation are recorded in [STATUS.md](STATUS.md), [ARCHITECTURE.md](ARCHITECTURE.md), [INSTALL.md](INSTALL.md) and [WAF.md](WAF.md).
