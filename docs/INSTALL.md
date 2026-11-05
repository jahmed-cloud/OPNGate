# OPNGate installation

## Before launching

Use an OPNsense firewall, a services Linux host and an edge Linux host. Current Compose files target the existing two-Pi architecture. Install Docker with its Compose plugin on both Linux hosts. Prepare root SSH key login and verify host fingerprints from a trusted source before the launcher uses strict host-key checking.

Create a proxied DNS record for `opngate.<domain>`, configure Cloudflare Full (strict), and forward WAN IPv4 TCP 80/443 to the edge. Keep services 9443/9444/9080 private. Identify the admin workstation address seen by SSH, the Linux LAN interface and OPNsense logical interfaces. Keep console access available when applying host-firewall rules.

## Windows: one launcher

Clone or download [OPNGate](https://github.com/jahmed-cloud/OPNGate), install Git for Windows, and double-click `Deploy.cmd`. Its PowerShell launcher uses Git Bash to run the same deployment implementation as Linux/macOS.

1. **Configure** collects settings into `deploy/deploy.conf`; no remote changes.
2. **Check** verifies tools, key access, both Docker installations and OPNsense access.
3. **Install** provisions a new stack in order, with interactive first-user setup.
4. **Update** rebuilds portal, ingest and the matching shipper on an existing stack.
5. **Status** checks public login, running core services and the agent; failures return a nonzero exit code.

The PowerShell process launched by `Deploy.cmd` uses a process-scoped execution policy; it does not change the workstation's persistent policy.

```powershell
.\Deploy.ps1 -Action Configure
.\Deploy.ps1 -Action Check
.\Deploy.ps1 -Action Install
.\Deploy.ps1 -Action Update
.\Deploy.ps1 -Action Status -NonInteractive -NoPause
```

Use `-ConfigPath` for a separate private configuration and `-BashPath` for a nonstandard Git for Windows installation. Non-interactive mode requires an existing configuration. Existing configuration files are retained; edit that file to change saved settings.

## Linux/macOS or Git Bash

```sh
cp deploy/deploy.conf.example deploy/deploy.conf
# Edit the private file.
sh deploy/deploy.sh check
sh deploy/deploy.sh all
# Later application updates:
sh deploy/deploy.sh update
```

`deploy.conf` is trusted shell configuration: do not source a configuration received from an untrusted party. The repository supplies examples only. The wizard writes quoted values and LF line endings, including SSH key paths with spaces.

## New installation behavior

The install path creates missing secrets and a complete private PKI. An incomplete local certificate set stops deployment rather than replacing part of it. Existing remote certificates must match before deployment. Services start before the edge. The firewall agent starts with actions disabled; configure its actual physical interfaces and segments before relying on telemetry, and manually export registered operator keys before enabling signed controls.

`INSTALL_HOSTFW=yes` applies the supplied Linux host-firewall policy only after confirming the remote SSH source matches `ADMIN_IP`. List application upstreams explicitly. The launcher does not configure your upstream applications or import arbitrary existing proxy sites.

## Existing installations

Use Update for routine application releases. It backs up existing portal source on both Pis and updates application code without replacing live Compose files, Caddy routes, certificates, credentials, volumes, agent code/configuration, operator trust or host firewall policy. This path requires an already compatible stack; releases that change Compose or agent protocols need the release-specific runbook first. An interrupted update must be checked before retrying.

A hostname move changes WebAuthn identity and signed-action configuration. Follow [HOSTNAME_MIGRATION.md](HOSTNAME_MIGRATION.md) separately. WAF enforcement stays as configured; the generic fresh-install example starts in DetectionOnly.

## Verification and recovery

Sign in, check Networks/Devices/Traffic, verify one-second freshness and independent historical charts, and confirm ordinary application authentication still works. Inspect action results on the firewall before repeating failed requests. Keep configuration/PKI/database backups and the prior images until a normal use cycle passes. The installer tests simulate hosts and failure paths; a new hardware installation still needs these deployment checks.
