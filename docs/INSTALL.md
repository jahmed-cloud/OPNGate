# OPNGate installation and updates

## One command

Keep the existing OPNsense plus services/edge Linux architecture. From a checkout on Windows, double-click `Deploy.cmd` or run:

```powershell
.\Deploy.ps1
```

On Linux, macOS or Git Bash, copy/edit the private configuration once, then use the same deployment entrypoint for installation and updates:

```sh
cp deploy/deploy.conf.example deploy/deploy.conf
# Edit domain, hosts, SSH key, interface names and admin access.
sh deploy/deploy.sh deploy
```

The launcher checks prerequisites, then probes both hosts. Two existing compatible stacks select an application update; two empty hosts select installation. Mixed/partial installations and failed probes stop. Explicit Install also refuses an existing stack. The installer does not fetch or execute an unpinned remote bootstrap script: run the checked-out version you reviewed.

## Prerequisites

Use an OPNsense firewall and two distinct Linux hosts. Install Docker with Compose and Python 3.9+ on both Linux hosts; application Python runs in the supplied containers. Prepare root SSH key login and verify each host fingerprint from a trusted source. Windows also needs Git for Windows; the PowerShell launcher uses its Bash/OpenSSL/SSH tools. macOS/Linux needs the local tools listed by Check.

Create proxied DNS for `opngate.<domain>`, configure Cloudflare Full (strict), and forward WAN IPv4 TCP 80/443 to the edge. Keep services 9443/9444/9080 private. Identify the admin address seen by SSH, Linux LAN interfaces and OPNsense logical interfaces. Keep console access available when initially applying host-firewall rules.

First Windows launch collects settings into ignored `deploy/deploy.conf`, then deploys. Use `-Action Configure` to collect settings without remote changes. Existing configuration is retained; edit it to change saved values. Configuration is trusted shell code: use your own private file. SSH key paths with spaces are supported. `Deploy.cmd` forwards command-line options and uses a process-scoped PowerShell execution policy.

## Individual operations

```powershell
.\Deploy.ps1 -Action Menu
.\Deploy.ps1 -Action Configure
.\Deploy.ps1 -Action Check -NonInteractive -NoPause
.\Deploy.ps1 -Action Deploy -NonInteractive -NoPause
.\Deploy.ps1 -Action Update -NonInteractive -NoPause
.\Deploy.ps1 -Action Status -NonInteractive -NoPause
.\Deploy.ps1 -Action Rollback -ReleaseId <release-id>
```

`-ConfigPath` selects a private configuration; `-BashPath` selects a nonstandard Git Bash installation. Non-interactive mode requires an existing configuration. Shell equivalents are `check`, `deploy`, `update`, `status`, `rollback <release-id>` and `all` for an explicit fresh install.

## Existing-stack update

1. Inspect both compatible stacks and create a unique release directory on each host. Verify the uploaded archive SHA-256 before installing it. Host locks prevent two releases from modifying the same deployment; operation locks prevent recovery racing a still-running stage.
2. Retain the previous selected source files and exact running image IDs/tags on both hosts. Take a private SQLite backup through the running portal. The backup is mode 0600 and stays in the services data volume.
3. Copy only public application, documentation and deployment files. Never ship `.env`, PKI, databases, live Compose files, Caddy routes, agent source/configuration, operator trust or host-firewall policy as part of Update. Unexpected/private archive paths and links are rejected.
4. Build portal/ingest on services and the matching shipper on edge before activating either host. Import each built image with a read-only filesystem and no network; compare its application files against the staged source hashes.
5. Recreate only portal, ingest and shipper as needed. Check running image IDs and restart counts, fresh current telemetry, ingest listener availability and recent shipper contact. Retry readiness up to 30 times with two seconds between attempts. Public GET checks require login/health 200 and unauthenticated live JSON/SSE 401, with normal TLS certificate validation.
6. Mark the release complete and release host locks. Retain source archives, state, private logs and image tags for recovery; no automatic pruning runs.

This is a coordinated update with recovery, not an atomic distributed transaction or a zero-downtime promise. A short reconnect can occur during recreation. It requires an already compatible Compose/agent protocol and healthy telemetry sources. A release with schema/protocol/identity changes needs a specific migration procedure.

## Failure recovery

A failed build leaves the previous containers running. A failure during activation/readiness attempts to restore source and image tags on both reachable hosts, recreating only the application services that may have switched. It never restores a stale database over new events or user changes.

An update prints a release ID such as `opngate-20261108T010203Z-1234abcd`. After an SSH/workstation interruption, reconnect and use that exact ID:

```powershell
.\Deploy.ps1 -Action Rollback -ReleaseId opngate-20261108T010203Z-1234abcd
# After recovery, retry the normal deployment with a new release ID:
.\Deploy.ps1
```

```sh
sh deploy/deploy.sh rollback opngate-20261108T010203Z-1234abcd
```

Recovery refuses another deployment's host lock and refuses an old completed release over a newer one. If a remote stage is still running, wait for it to finish before retrying recovery. If a host cannot be reached, automatic recovery may be incomplete: the command reports it and retains the state. Inspect private `releases/<release-id>/state.json`, `build.log`, `import.log` and the lock owner on both hosts; do not blindly delete locks or prune backup images. A kill between lock-directory creation and owner recording can need manual inspection.

The release controller retained on each host performs recovery, so rollback remains available after the live installer source is restored. Keep the admin checkout containing the new Rollback command until a normal-use cycle passes. Database snapshots are manual recovery material; schema downgrades and full host failures are outside automatic rollback.

## New installation

The installation branch creates missing secrets and a complete private PKI. Partial certificate sets stop rather than being regenerated. Matching remote certificates are required. Services start before edge; firewall setup and first-user creation run interactively. The fresh agent starts with actions disabled: configure actual physical interfaces/segments, register a passkey, and explicitly export/trust its public key before enabling signed controls.

`INSTALL_HOSTFW=yes` applies Linux host-firewall policy after checking the remote SSH source matches `ADMIN_IP`. List permitted application upstreams explicitly. The launcher does not configure unrelated applications, migrate arbitrary proxy routes or upgrade operator-owned firewall-agent extensions. New WAF examples start in DetectionOnly; existing updates preserve the live mode.

## Verification boundaries

Check a physical-key login, Networks/Devices/Traffic freshness, historical charts and a normal signed control after deployment. Inspect actual firewall state before retrying a failed action. HTTP availability and software-authenticator tests do not prove real hardware approval or application upload/sync compatibility.

Automated tests exercise real archive/state/restore logic in disposable directories and orchestrate simulated hosts for failure ordering. A successful production update validates the existing-stack path, not a clean hardware installation or every possible recovery fault. Keep source, PKI/configuration/database backups and prior images until normal use passes. See [STATUS.md](STATUS.md) for the latest measured deployment evidence.
