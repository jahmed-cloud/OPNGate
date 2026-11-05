# Blocking and undo in OPNGate

The same instructions are available inside the authenticated console at **Help & guides** (`/help`), with contextual links on Devices, Networks and Actions.

| Goal | Path | Choice |
| --- | --- | --- |
| Pause one device | Devices → Manage | Pause internet, then choose a duration |
| Block domains/categories for one device | Devices → Manage | Block websites |
| Block domains/categories for a subnet | Networks → network card | Block sites |
| Block an external IP/CIDR | Actions | Block an IP or CIDR |
| Limit a device | Devices → Manage | Speed limit |

Choose the target and duration, prepare the request and select **Approve with security key**. Wait for **done** and verify the effect on the device. The firewall fetches approved actions about every 15 seconds; website DNS policies can take about a minute. Pending/approved/fetched does not mean a policy is active.

Controls require an operator account and an enrolled passkey whose public key has been manually trusted by the firewall. Password/TOTP authenticates sign-in; it does not replace the control signature. After changing hostname, register a passkey for the new hostname and update the firewall's public-key trust and action identity.

Use Resume internet, Allow all sites again, Remove speed limit or the active action's Undo button to reverse a policy. Reversals need approval too. Timed policies expire; indefinite policies remain until removed. Removing an OPNGate website policy leaves independent network-wide DNS blocklists in force.

For websites enter domain names, without scheme/path. Subdomains are included. DNS caches, app-specific secure DNS and VPNs can affect DNS-policy results. For a local device use Pause internet; the external-IP control rejects private/local and protected addresses.

WAF enforcement is separate: Caddy/Coraza automatically inspects published websites, while Threats reports audit evidence. See [WAF.md](WAF.md). If a control fails, read its firewall result and check actual state before retrying. See [SECURITY.md](SECURITY.md) for delivery and DHCP limitations.
