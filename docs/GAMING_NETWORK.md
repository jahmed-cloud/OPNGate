# Gaming latency and packet loss

Traffic shaping can reduce queueing delay under load. It cannot choose the upstream ISP's route to a game server or repair packet loss outside the home network. Diagnose actual game loss separately from dashboard refresh delay and from unanswered traceroute probes.

## MGMT-only profile

The 2026-11-01 operational profile uses a confirmed symmetric 300/300 Mbps service with two 285 Mbit/s FQ-CoDel pipes. This reserves 5% headroom as an initial tuning point, not a measured optimum. The queue target is 5 ms, interval 100 ms, quantum defaults to 1514, limit 1000 packets and flows 1024. ECN is disabled. No artificial delay or random packet-drop probability is configured; FQ-CoDel may drop packets deliberately to control persistent queues.

The persistent OPNsense Traffic Shaper model contains two tagged pipes, `[mgmt-gaming-fqcodel] down` and `up`, numbered 20000/20001. Rules use MGMT (`opt1`) as the primary interface and WAN as the second interface, with protocol `ip`, any source/destination and any ports. Download uses direction `out` (receive WAN, transmit MGMT); upload uses direction `in` (receive MGMT, transmit WAN). The interface pair scopes this to forwarded Internet traffic and avoids depending on pre/post-NAT addresses. Local management sessions and inter-segment traffic do not traverse this pair.

This profile limits aggregate MGMT Internet traffic, not just Valorant. Other segments remain unshaped and can still fill the shared ISP link. If that causes latency during gaming, evaluate a shared WAN shaper with the operator before expanding the scope. No routes, NAT, PF access rules or intrusion protection are changed by this profile.

## Verification and tuning

- Check `ipfw sched show`: both pipes must show `type FQ_CODEL`, not just a bandwidth value in `ipfw pipe show`.
- Check `ipfw -a list`: counters must rise on the WAN-to-MGMT and MGMT-to-WAN rules.
- Compare PC-to-firewall and PC-to-Internet loss/RTT before and after. Short clean ping samples do not prove an intermittent game problem is fixed.
- In Valorant, enable incoming/outgoing packet-loss and Network RTT/Jitter statistics and use the same server region for comparisons.
- When no match or important call is active, measure latency while downloading and uploading. Adjust each bandwidth ceiling to the highest value that keeps loaded delay low. Advertised speed alone is not a loaded-latency measurement.
- If drops continue while idle, inspect the PC link and game-server path. Traceroute timeouts alone may reflect filtering or rate limiting; they do not establish loss of forwarded game packets.

On this deployment, before shaping: PC-to-firewall 0/30 lost; PC-to-Internet 0/30 lost, 7 ms average; firewall-to-upstream gateway and firewall-to-Internet each 0/25 lost. After shaping, PC-to-Internet was 0/25 lost, 7 ms average (7–13 ms range). Wired error/discard counters were zero. These are short observations during normal use, not a controlled congestion test or proof that Mumbai match loss has been resolved.

## Rollback and device-cap coexistence

The private full configuration backup is `/root/backups/mgmt-gaming-20261101-before.xml` on the firewall. `/root/backups/mgmt-gaming-rollback.sh` removes only the tagged profile through `/root/mgmt-fqcodel.php`, reloads the shaper/IPFW configuration and removes the two retired kernel pipes. The scoped rollback preserves later unrelated configuration changes; use the full backup only as a separately reviewed recovery action. Keep backups on the firewall and out of Git.

Agent 1.4.1 changes device-cap cleanup: `shaper.php clear` reports the pipe numbers actually removed for the specified device tag, and the agent deletes only those retired kernel pipes. It no longer treats every unlisted number above 10000 as portal-owned. This preserves manually configured gaming/shared pipes and other devices' limits. Agent source rollback copies end in `.gaming-backup`; reverting that code reintroduces the broad-deletion bug, so disable device-cap removal if temporarily reverting it.

This cleanup fix does not compose individual device limiters with the shared profile. Earlier-sequence device-cap rules can take precedence over the MGMT profile for that device; inspect rule counters and retest loaded latency when combining them. No portal device caps were active during this rollout.

References: [OPNsense FQ-CoDel setup and tuning](https://docs.opnsense.org/manual/how-tos/shaper_bufferbloat.html), [Riot's network instability diagnostics](https://playvalorant.com/en-us/news/game-updates/valorant-game-and-network-instability-basics/).
