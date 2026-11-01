"""Agent collectors against captured FreeBSD/OPNsense command output (no firewall needed)."""
import json

import fw_agent

OUTPUTS = {
    ("/usr/local/sbin/pluginctl", "-r", "return_gateways_status"): json.dumps({"dpinger": {"WAN_DHCP": {
        "status": "none", "delay": "6.412 ms", "stddev": "0.3 ms", "loss": "0.0 %", "name": "WAN_DHCP"}}}),
    ("ifconfig", "igb0"): "igb0: flags=8843<UP>\n\tinet 198.51.100.20 netmask 0xffffff00 broadcast 198.51.100.255\n",
    ("arp", "-an", "--libxo", "json"): json.dumps({"arp": {"arp-cache": [
        {"hostname": "?", "ip-address": "10.10.0.20", "mac-address": "00:11:22:33:44:55", "interface": "igb1", "expires": 1100},
        {"hostname": "?", "ip-address": "10.10.0.1", "mac-address": "00:0d:b9:00:00:01", "interface": "igb1", "permanent": True},
        {"hostname": "?", "ip-address": "198.51.100.1", "mac-address": "00:aa:bb:cc:dd:ee", "interface": "igb0", "expires": 900},
    ]}}),
    ("netstat", "-ibn", "--libxo", "json"): json.dumps({"statistics": {"interface": [
        {"name": "igb0", "network": "<Link#1>", "received-bytes": 1000, "sent-bytes": 500},
        {"name": "igb0", "network": "198.51.100.0/24", "received-bytes": 1000, "sent-bytes": 500},
        {"name": "igb1", "network": "<Link#2>", "received-bytes": 2000, "sent-bytes": 4000},
    ]}}),
    ("wg", "show", "all", "dump"): "wg0\tPRIV\tPUB\t51820\toff\n"
                                   "wg0\tPEERKEY=\t(none)\t203.0.113.5:4500\t10.40.0.2/32\t1730000000\t100\t200\toff\n",
    ("sysctl", "-n", "kern.boottime"): "{ sec = 1700000000, usec = 0 } Tue Nov 14 22:13:20 2023\n",
    ("sysctl", "-n", "net.link.ether.inet.max_age"): "1200\n",
}


def fake_run(cmd, timeout=20, check=False, input_data=None):
    out = OUTPUTS.get(tuple(cmd))
    return (0, out, "") if out is not None else (1, "", "not mocked")


def test_collectors(monkeypatch, tmp_path):
    monkeypatch.setattr(fw_agent, "run", fake_run)
    leases = tmp_path / "dnsmasq.leases"
    leases.write_text("1730000000 00:11:22:33:44:55 10.10.0.20 desktop 01:00:11:22:33:44:55\n"
                      "1730000000 66:77:88:99:aa:bb 10.10.0.30 * *\n")
    cfg = {"wan_interface": "igb0", "gateway_name": "WAN_DHCP", "segments": {"igb0": "WAN", "igb1": "LAN"},
           "dhcp_leases": [str(leases)], "wg_names": {"PEERKEY=": "Phone"}}

    gw = fw_agent.gateway_status(cfg)
    assert gw["online"] and gw["latency_ms"] == 6.412 and gw["loss_pct"] == 0.0 and gw["wan_ip"] == "198.51.100.20"

    clients = {c["mac"]: c for c in fw_agent.clients(cfg)}
    assert clients["00:11:22:33:44:55"] == {"mac": "00:11:22:33:44:55", "ip": "10.10.0.20", "hostname": "desktop",
                                             "segment": "LAN", "online": True, "idle_s": 100,
                                             "down_bps": None, "up_bps": None, "paused": False}
    assert not clients["66:77:88:99:aa:bb"]["online"]            # lease only
    assert "00:0d:b9:00:00:01" not in clients                    # firewall's own (permanent) entry
    assert "00:aa:bb:cc:dd:ee" not in clients                    # WAN upstream router

    rates = fw_agent.Rates()
    first = rates.interfaces(cfg)
    assert [i["name"] for i in first] == ["igb0", "igb1"] and first[0]["rx_bps"] == 0

    peers = fw_agent.wireguard(cfg)
    assert peers == [{"interface": "wg0", "public_key": "PEERKEY=", "name": "Phone", "endpoint": "203.0.113.5:4500",
                      "allowed_ips": "10.40.0.2/32", "last_handshake": 1730000000, "rx": 100, "tx": 200}]
    assert fw_agent.uptime_seconds() > 0


def test_tail_starts_at_end_and_follows_rotation(tmp_path):
    state = fw_agent.State(str(tmp_path / "s.json"))
    log = tmp_path / "eve.json"
    log.write_text('{"event_type":"alert"}\n')
    assert fw_agent.tail_new_lines(state, str(log)) == []        # history is skipped
    with open(log, "a") as fh:
        fh.write('{"event_type":"alert","alert":{"severity":1,"signature":"ET SCAN x"},"src_ip":"1.2.3.4","dest_ip":"10.0.0.1"}\n')
    events = fw_agent.collect_events({"suricata_eve": str(log), "event_files": []}, state)
    assert events and events[0]["severity"] == "critical" and "ET SCAN x" in events[0]["title"]
    log.write_text('{"event_type":"dns"}\n')                     # truncated / rotated
    assert len(fw_agent.tail_new_lines(state, str(log))) == 1


PF_STATES = """all tcp 17.0.0.6:443 <- 192.168.20.180:50009       ESTABLISHED:ESTABLISHED
   [4129411934 + 4194240] wscale 7  [2135960825 + 31872] wscale 6
   age 21:56:56, expires in 23:54:38, 318:287 pkts, {a}:{b} bytes, rule 116
   id: a607e66a00000000 creatorid: 206641bb
   origif: igb1
all tcp 198.51.100.20:46616 (192.168.20.180:50009) -> 17.0.0.6:443       ESTABLISHED:ESTABLISHED
   age 21:56:56, expires in 23:54:38, 318:287 pkts, {a}:{b} bytes, rule 106
   id: a707e66a00000000 creatorid: 206641bb route-to: 198.51.100.1@igb0
   origif: igb0
"""


def test_client_rates_from_pf_states(monkeypatch):
    cfg = {"segments": {"igb0": "WAN", "igb1": "LAN"}}
    counters = iter([(1000, 50000), (3000, 1050000)])
    monkeypatch.setattr(fw_agent, "run", lambda cmd, **kw: (0, PF_STATES.format(**dict(zip("ab", next(counters)))), ""))
    clock = iter([100.0, 110.0])
    monkeypatch.setattr(fw_agent.time, "monotonic", lambda: next(clock))
    rates = fw_agent.ClientRates()
    assert rates.sample(cfg) == {}                         # first poll only sets the baseline
    speeds = rates.sample(cfg)
    # 1 MB down and 2 kB up in 10 s; the WAN (NAT) copy of the same state is not counted again.
    assert speeds["192.168.20.180"] == (800000, 1600)
