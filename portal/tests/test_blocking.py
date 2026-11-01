"""Per-device and per-network site blocking: portal validation, agent validation and the pages that show it."""
import json
import uuid

import pytest
from fastapi.testclient import TestClient

from app import actions, db
from app.devices import kind
from app.main import app
from test_e2e import ingest, login_totp, make_user  # noqa: F401  (ingest is a fixture)

import fw_agent

AGENT_CFG = {"segments": {"igc0": "WAN", "igc1": "WiFi", "igc2": "LAN"}, "actions": {}}


@pytest.fixture
def client():
    with TestClient(app, base_url="http://testserver") as c:
        yield c


def test_portal_validates_site_blocks():
    p = actions.validate("block_domains", {"mac": "AA-BB-CC-00-11-22", "lists": ["hgz022", "tvtrack"],
                                            "domains": "https://www.YouTube.com/watch?v=1, *.tiktok.com", "minutes": "0"})
    assert p == {"mac": "aa:bb:cc:00:11:22", "domains": ["tiktok.com", "youtube.com"], "lists": ["hgz022", "tvtrack"], "minutes": 0}
    for bad in ({"mac": "aa:bb:cc:00:11:22"}, {"mac": "aa:bb:cc:00:11:22", "lists": ["nope"]},
                {"mac": "aa:bb:cc:00:11:22", "domains": "localhost"}):
        with pytest.raises(actions.InvalidAction):
            actions.validate("block_domains", bad)


def test_portal_validates_network_blocks():
    p = actions.validate("block_network", {"segment": "WiFi", "lists": ["ag", "ep"], "domains": ""})
    assert p == {"segment": "WiFi", "domains": [], "lists": ["ag", "ep"], "minutes": 0}
    assert actions.reverse_of("block_network", p) == ("unblock_network", {"segment": "WiFi"})
    for bad in ({"segment": "WAN", "lists": ["ag"]}, {"segment": "WiFi"}, {"segment": "x;rm", "lists": ["ag"]}):
        with pytest.raises(actions.InvalidAction):
            actions.validate("block_network", bad)


def _done(kind_, params, ago=0):
    now = db.now() - ago
    db.run("INSERT INTO actions(id, type, params, payload, created_by, created_at, expires_at, status, finished_at) "
           "VALUES (?, ?, ?, '{}', 't', ?, ?, 'done', ?)", str(uuid.uuid4()), kind_, json.dumps(params), now, now + 300, now)


def test_active_effects_track_site_and_network_blocks():
    db.init()
    db.run("DELETE FROM actions")
    _done("block_domains", {"mac": "aa:bb:cc:00:11:22", "minutes": 0}, ago=20)
    _done("block_network", {"segment": "WiFi", "minutes": 0}, ago=20)
    _done("block_network", {"segment": "LAN", "minutes": 1}, ago=600)  # expired
    keys = set(actions.active_effects().values())
    assert keys == {("domains", "aa:bb:cc:00:11:22"), ("network", "WiFi")}
    _done("unblock_network", {"segment": "WiFi"})
    assert ("network", "WiFi") not in set(actions.active_effects().values())


def test_agent_validates_site_and_network_blocks():
    v = fw_agent.validate_params
    assert v("block_domains", {"mac": "aa:bb:cc:00:11:22", "lists": ["phishing"], "domains": [], "minutes": 0}, AGENT_CFG)["lists"] == ["phishing"]
    assert v("block_network", {"segment": "WiFi", "lists": ["ag"], "domains": ["tiktok.com"], "minutes": 60}, AGENT_CFG)["segment"] == "WiFi"
    for k, params in (("block_domains", {"mac": "aa:bb:cc:00:11:22", "lists": ["https://evil.example/x"], "minutes": 0}),
                      ("block_network", {"segment": "WAN", "lists": ["ag"], "minutes": 0}),
                      ("block_network", {"segment": "Guest", "lists": ["ag"], "minutes": 0}),
                      ("block_network", {"segment": "WiFi", "lists": [], "domains": [], "minutes": 0})):
        with pytest.raises(fw_agent.ActionRejected):
            v(k, params, AGENT_CFG)


def test_agent_finds_network_subnets_and_reports_blocks(monkeypatch):
    out = ("igc1: flags=8863<UP>\n\tinet 192.168.20.1 netmask 0xffffff00 broadcast 192.168.20.255\n"
           "\tinet6 fe80::1%igc1 prefixlen 64 scopeid 0x2\n\tinet6 2001:db8:20::1 prefixlen 64\n")
    monkeypatch.setattr(fw_agent, "run", lambda *a, **k: (0, out, ""))
    assert fw_agent._segment_nets(AGENT_CFG, "WiFi") == ["192.168.20.0/24", "2001:db8:20::/64"]
    assert fw_agent._net_tag("Guest WiFi") == "portal-net-guest-wifi"
    state = {"networks": {"WiFi": {"domains": ["tiktok.com"], "lists": ["ag"], "until": 0}}}
    ifs = fw_agent._with_blocks([{"name": "igc1", "segment": "WiFi"}, {"name": "igc2", "segment": "LAN"}], state)
    assert ifs[0]["blocks"] == {"list": ["tiktok.com"], "lists": ["ag"], "until": 0} and "blocks" not in ifs[1]


def test_device_kinds():
    assert kind({"hostname": "nintendo-switch"}) == "console"
    assert kind({"hostname": "core-switch"}) == "network"
    assert kind({"hostname": "Juns-iPhone"}) == "phone"
    assert kind({"hostname": "", "vendor": "Synology Incorporated"}) == "nas"
    assert kind({"hostname": "x", "vendor": "Apple, Inc."}) == "device"


def test_blocks_render_on_clients_overview_and_traffic(client, ingest):  # noqa: F811
    t = {
        "hostname": "opnsense", "version": "1.3.0", "uptime_s": 60,
        "gateway": {"name": "WAN_GW", "online": True, "latency_ms": 5, "loss_pct": 0},
        "interfaces": [{"name": "igc0", "segment": "WAN", "rx_bps": 5_000_000, "tx_bps": 500_000},
                       {"name": "igc1", "segment": "WiFi", "rx_bps": 400_000, "tx_bps": 4_000_000,
                        "blocks": {"list": ["tiktok.com"], "lists": ["ag", "ep"], "until": 0}}],
        "clients": [{"mac": "aa:bb:cc:00:11:33", "ip": "192.168.20.31", "hostname": "living-room-tv", "segment": "WiFi",
                     "online": True, "down_bps": 1000, "up_bps": 100,
                     "domains": {"list": ["youtube.com"], "lists": ["hgz022"], "until": 0}}],
    }
    assert ingest.post("/v1/telemetry", json=t).status_code == 200
    name = f"op-blocks-{uuid.uuid4().hex[:8]}"
    secret, _ = make_user(name)
    client.cookies.clear()
    login_totp(client, name, secret)
    r = client.get("/clients")
    assert r.status_code == 200 and "Social media + 1 site blocked" in r.text and "Block websites" in r.text
    r = client.get("/")  # networks start collapsed: a count, no device cards
    assert r.status_code == 200 and "living-room-tv" not in r.text and "1 device online" in r.text
    assert 'data-segment="WiFi"' in r.text and 'aria-expanded="false"' in r.text
    client.cookies.set("flow_open", "WiFi")
    r = client.get("/")
    assert "living-room-tv" in r.text and 'aria-expanded="true"' in r.text and 'class="flow-ctrl"' in r.text
    client.cookies.set("flow_open", "*")
    assert "living-room-tv" in client.get("/").text
    client.cookies.delete("flow_open")
    r = client.get("/traffic")
    assert r.status_code == 200
    assert "2 lists + 1 site" in r.text and 'name="segment" value="WiFi"' in r.text
    assert 'value="block_network"' in r.text and "Site blocks apply to the inside networks" in r.text
