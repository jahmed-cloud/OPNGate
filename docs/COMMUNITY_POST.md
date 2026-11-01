# Community post draft

**Title: My OPNsense home-lab gateway dashboard with a separate Coraza WAF edge**

I've been building a self-hosted gateway portal for my OPNsense home lab and have published the code:

https://github.com/jahmed-cloud/WAF-OPNSense

The portal brings connectivity, clients, traffic, DNS, VPNs and security alerts into one place. The dashboard includes UTC time axes and timestamp tooltips, latency/loss and bandwidth graphs, availability with visible telemetry gaps, device search, alert filters and CSV exports. Longer time ranges aggregate in SQLite to keep the graph data bounded. A separate two-second current-counter feed drives a rolling WAN graph, while historical charts refresh every minute without replacing the page. CrowdSec data refreshes in the background.

The actual web application firewall runs separately at the edge: Caddy + Coraza + OWASP CRS, alongside CrowdSec. It starts in detection mode for tuning. The portal reports confirmed Coraza matches and interruptions, and avoids treating every application 403 as a WAF block.

For access, it supports passkeys/security keys or password + TOTP. Optional firewall actions require an operator signature that the OPNsense agent verifies independently. The example starts with actions disabled.

This is a home-lab project under active development. Automated tests cover authentication, signed actions, metrics, filters and exports; live OPNsense/Pi deployment checks and rule tuning still matter. I'd welcome feedback on the dashboard, deployment documentation, false-positive tuning and how others separate their edge and management networks.

What would make a gateway dashboard more useful in your own lab?
