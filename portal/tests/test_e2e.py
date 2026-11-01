"""End to end: login paths, guards, passkey registration, and the signed action chain
from browser approval through the portal to the firewall agent's own verification."""
import json
import re
import secrets
import time

import pyotp
import pytest
from fastapi.testclient import TestClient

from app import cli, db, security
from app.ingest import ingest_app
from app.main import app
from softkey import SoftKey, b64u

import fw_agent

ORIGIN = "http://testserver"
H = {"Origin": ORIGIN}
PASSWORD = "correct horse battery staple 42"


@pytest.fixture(autouse=True)
def fresh_limiter():
    security.limiter = security.RateLimiter()
    for mod in ("auth",):
        import app.auth as a
        a.limiter = security.limiter
    yield


@pytest.fixture(scope="module")
def client():
    with TestClient(app, base_url=ORIGIN) as c:
        yield c


@pytest.fixture(scope="module")
def ingest():
    with TestClient(ingest_app) as c:
        yield c


def make_user(name, role="operator"):
    secret = pyotp.random_base32()
    db.init()
    db.run(
        "INSERT INTO users(username, password_hash, role, totp_secret_enc, webauthn_user_id, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        name, security.hash_password(PASSWORD), role, security.encrypt(secret), secrets.token_bytes(32), db.now(),
    )
    uid = db.one("SELECT id FROM users WHERE username=?", name)["id"]
    return secret, security.new_recovery_codes(uid)


def csrf_of(client):
    m = re.search(r'name="csrf" content="([^"]+)"', client.get("/security").text)
    return m.group(1)


def login_totp(client, name, secret, step_offset=0):
    code = pyotp.TOTP(secret).at(time.time() + 30 * step_offset)
    return client.post("/login/password", data={"username": name, "password": PASSWORD, "code": code, "next": "/"},
                       headers=H, follow_redirects=False)


# ------------------------------------------------------------------ login

def test_password_only_is_impossible_and_totp_cannot_be_replayed(client):
    secret, _ = make_user("alice")
    r = client.post("/login/password", data={"username": "alice", "password": PASSWORD, "code": "000000"}, headers=H)
    assert r.status_code == 401
    r = login_totp(client, "alice", secret)
    assert r.status_code == 303 and r.headers["location"] == "/"
    client.cookies.clear()
    r = login_totp(client, "alice", secret)  # same 30 s step again
    assert r.status_code == 401
    client.cookies.clear()


def test_recovery_code_works_once(client):
    _, codes = make_user("rec")
    form = {"username": "rec", "password": PASSWORD, "code": codes[0]}
    assert client.post("/login/password", data=form, headers=H, follow_redirects=False).status_code == 303
    client.cookies.clear()
    assert client.post("/login/password", data=form, headers=H, follow_redirects=False).status_code == 401
    client.cookies.clear()


def test_cross_origin_login_refused(client):
    r = client.post("/login/password", data={"username": "x", "password": "y", "code": "1"},
                    headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


def test_rate_limit_and_auth_log(client):
    make_user("bob")
    codes = [client.post("/login/password", data={"username": "bob", "password": "wrong", "code": "123456"},
                         headers=H).status_code for _ in range(7)]
    assert codes[:5] == [401] * 5 and 429 in codes[5:]
    log = security.settings.auth_log.read_text()
    assert 'event=login_failed ok=0 ip=testclient user="bob"' in log or "user=\"bob\"" in log


def test_x_real_ip_trusted_only_from_proxy(client):
    from starlette.requests import Request
    def req(peer, xri):
        return Request({"type": "http", "client": (peer, 1), "headers": [(b"x-real-ip", xri.encode())]})
    assert security.client_ip(req("10.99.0.1", "203.0.113.9")) == "203.0.113.9"
    assert security.client_ip(req("198.51.100.1", "203.0.113.9")) == "198.51.100.1"


def test_pages_need_login_and_csrf(client):
    client.cookies.clear()
    assert client.get("/clients", follow_redirects=False).status_code == 303
    secret, _ = make_user("carol", role="viewer")
    login_totp(client, "carol", secret)
    assert client.get("/clients").status_code == 200
    assert client.get("/actions").status_code == 403  # viewer
    r = client.post("/logout", data={"csrf": "nope"}, headers=H)
    assert r.status_code == 403
    client.cookies.clear()


# ------------------------------------------------------------------ passkeys and actions

def register_key(client, key: SoftKey, name="test key"):
    token = csrf_of(client)
    hdr = {**H, "X-CSRF-Token": token, "Content-Type": "application/json"}
    opts = client.post("/security/passkey/register/begin", headers=hdr).json()
    assert opts["authenticatorSelection"]["userVerification"] == "required"
    r = client.post("/security/passkey/register/finish", headers=hdr,
                    json={"credential": key.create(opts, ORIGIN), "name": name})
    assert r.status_code == 200, r.text
    return hdr


def test_full_action_chain(client, ingest, tmp_path):
    secret, _ = make_user("op")
    login_totp(client, "op", secret)
    key = SoftKey(-7)
    hdr = register_key(client, key)

    # Passkey-only login works.
    client.cookies.clear()
    opts = client.post("/auth/passkey/begin", headers=H).json()
    r = client.post("/auth/passkey/finish", headers=H, json={"credential": key.get(opts["challenge"], "testserver", ORIGIN), "next": "/"})
    assert r.status_code == 200 and r.json()["ok"]
    hdr["X-CSRF-Token"] = csrf_of(client)

    # Firewall trust store, as exported from the portal host.
    keys_file = tmp_path / "operator_keys.json"
    keys_file.write_text(json.dumps(cli.trusted_keys_doc()))
    cfg = {"actions": {"enabled": True, "trusted_keys_file": str(keys_file), "rp_id": "testserver", "origin": ORIGIN,
                       "allowed": ["block_ip", "pause_client"], "protected_cidrs": ["9.9.9.0/24"]}}
    trusted = fw_agent.load_trusted_keys(str(keys_file))
    state = fw_agent.State(str(tmp_path / "state.json"))

    # Create and approve an action.
    r = client.post("/actions/new", data={"csrf": hdr["X-CSRF-Token"], "type": "block_ip", "cidr": "1.2.3.4", "minutes": "30"},
                    headers=H, follow_redirects=False)
    action_id = r.headers["location"].rsplit("/", 1)[1]
    opts = client.post(f"/actions/{action_id}/begin", headers=hdr).json()
    r = client.post(f"/actions/{action_id}/approve", headers=hdr,
                    json={"credential": key.get(opts["challenge"], "testserver", ORIGIN)})
    assert r.status_code == 200, r.text

    # Agent fetches over the ingest API and verifies independently.
    items = ingest.get("/v1/actions").json()["actions"]
    assert len(items) == 1
    item = items[0]
    payload = fw_agent.verify_action(item, trusted, cfg, state)
    assert payload["type"] == "block_ip" and payload["params"] == {"cidr": "1.2.3.4/32", "minutes": 30}

    # A compromised portal swapping the parameters breaks the signature binding.
    forged = dict(item, payload=item["payload"].replace("1.2.3.4/32", "1.2.0.0/16"))
    with pytest.raises(fw_agent.ActionRejected, match="not over this payload"):
        fw_agent.verify_action(forged, trusted, cfg, state)

    # Replay after processing is refused.
    state["seen_actions"][payload["id"]] = int(time.time())
    state["sign_counts"][item["assertion"]["rawId"]] = payload["_sign_count"]
    with pytest.raises(fw_agent.ActionRejected):
        fw_agent.verify_action(item, trusted, cfg, state)

    # Result is reported back.
    assert ingest.post(f"/v1/actions/{action_id}/result", json={"ok": True, "message": "done"}).status_code == 200
    assert db.one("SELECT status FROM actions WHERE id=?", action_id)["status"] == "done"

    # Undo prepares the reverse action, which still needs its own signature.
    from app import actions as portal_actions
    assert action_id in portal_actions.active_effects()
    assert "Undo" in client.get("/actions").text
    r = client.post(f"/actions/{action_id}/undo", data={"csrf": hdr["X-CSRF-Token"]}, headers=H, follow_redirects=False)
    undo_id = r.headers["location"].rsplit("/", 1)[1]
    row = db.one("SELECT type, params, status FROM actions WHERE id=?", undo_id)
    assert (row["type"], json.loads(row["params"]), row["status"]) == ("unblock_ip", {"cidr": "1.2.3.4/32"}, "pending_approval")
    db.run("UPDATE actions SET status='done' WHERE id=?", undo_id)
    assert action_id not in portal_actions.active_effects()


def _signed_item(key, payload: dict, rp="testserver", origin=ORIGIN, flags=0x05):
    payload_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    import hashlib
    challenge = b64u(hashlib.sha256(payload_str.encode()).digest())
    return {"id": payload["id"], "payload": payload_str, "assertion": key.get(challenge, rp, origin, flags=flags)}


@pytest.mark.parametrize("alg", [-7, -8])
def test_agent_rejections(tmp_path, alg):
    key = SoftKey(alg)
    from cryptography.hazmat.primitives import serialization
    pem = key.key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    trusted = {b64u(key.cred_id): {"credential_id": b64u(key.cred_id), "alg": alg, "public_key_pem": pem, "user": "op"}}
    cfg = {"actions": {"rp_id": "testserver", "origin": ORIGIN, "allowed": ["block_ip"], "protected_cidrs": ["9.9.9.0/24"]}}
    now = int(time.time())

    def payload(**over):
        p = {"v": 1, "id": secrets.token_hex(8), "type": "block_ip", "params": {"cidr": "1.2.3.0/24", "minutes": 5},
             "created_by": "op", "created_at": now, "expires_at": now + 600, "rp_id": "testserver", "origin": ORIGIN}
        p.update(over)
        return p

    state = fw_agent.State(str(tmp_path / f"s{alg}.json"))
    assert fw_agent.verify_action(_signed_item(key, payload()), trusted, cfg, state)["type"] == "block_ip"

    cases = {
        "expired": _signed_item(key, payload(created_at=now - 1200, expires_at=now - 600)),
        "not allowed": _signed_item(key, payload(type="backup_config", params={})),
        "protected": _signed_item(key, payload(params={"cidr": "9.9.9.5", "minutes": 5})),
        "private": _signed_item(key, payload(params={"cidr": "192.168.1.0/24", "minutes": 5})),
        "wrong rp": _signed_item(key, payload(), rp="evil.example"),
        "wrong origin": _signed_item(key, payload(), origin="https://evil.example"),
        "no uv": _signed_item(key, payload(), flags=0x01),
        "other portal": _signed_item(key, payload(rp_id="other")),
    }
    for name, item in cases.items():
        with pytest.raises(fw_agent.ActionRejected):
            fw_agent.verify_action(item, trusted, cfg, state)
            pytest.fail(name)

    # Unknown key, and a signature by a different key under a trusted credential id.
    other = SoftKey(alg)
    item = _signed_item(other, payload())
    with pytest.raises(fw_agent.ActionRejected, match="trusted key"):
        fw_agent.verify_action(item, trusted, cfg, state)
    item["assertion"]["rawId"] = item["assertion"]["id"] = b64u(key.cred_id)
    with pytest.raises(fw_agent.ActionRejected, match="bad signature"):
        fw_agent.verify_action(item, trusted, cfg, state)

    # Counter going backwards (cloned key).
    state["sign_counts"][b64u(key.cred_id)] = 10_000
    with pytest.raises(fw_agent.ActionRejected, match="counter"):
        fw_agent.verify_action(_signed_item(key, payload()), trusted, cfg, state)


# ------------------------------------------------------------------ telemetry

def test_telemetry_renders(client, ingest):
    t = {
        "hostname": "opnsense", "version": "1.0.0", "uptime_s": 90061,
        "gateway": {"name": "WAN_DHCP", "online": True, "latency_ms": 7.2, "loss_pct": 0.0, "wan_ip": "198.51.100.20"},
        "interfaces": [{"name": "igb0", "segment": "WAN", "rx_bps": 12_000_000, "tx_bps": 900_000},
                       {"name": "igb1", "segment": "LAN", "rx_bps": 800_000, "tx_bps": 11_000_000}],
        "clients": [{"mac": "aa:bb:cc:00:11:22", "ip": "10.10.0.20", "hostname": "pc", "segment": "LAN", "online": True},
                    {"mac": "3c:22:fb:00:00:01", "ip": "10.20.0.5", "hostname": "tv", "segment": "IoT", "online": False}],
        "vpn": [{"interface": "wg0", "public_key": "A" * 43 + "=", "name": "Phone", "endpoint": "203.0.113.5:51820",
                 "allowed_ips": "10.40.0.2/32", "last_handshake": int(time.time()) - 30, "rx": 1, "tx": 2}],
        "dns": {"total_queries": 1000, "cache_hits": 600, "blocked": 120, "blocked_pct": 12.0, "top_blocked": {"ads.example": 50}},
        "threats": {"tables": {"crowdsec_blacklists": 15000},
                    "crowdsec": {"active_bans": 3, "by_country": {"CN": 2, "RU": 1}, "by_scenario": {"crowdsecurity/ssh-bf": 3}}},
    }
    assert ingest.post("/v1/telemetry", json=t).status_code == 200
    assert ingest.post("/v1/telemetry", json={**t, "gateway": {**t["gateway"], "online": False}}).status_code == 200
    assert ingest.post("/v1/events", json={"events": [{"source": "suricata", "severity": "critical", "title": "ET SCAN test"}]}).status_code == 200

    secret, _ = make_user("viewer2", role="viewer")
    client.cookies.clear()
    login_totp(client, "viewer2", secret)
    for path, needle in [("/", "198.51.100.20"), ("/clients", "aa:bb:cc:00:11:22"), ("/traffic", "12.0 Mbit/s"),
                         ("/threats", "crowdsec_blacklists"), ("/dns", "ads.example"), ("/vpn", "Phone"),
                         ("/alerts", "Internet down"), ("/audit", "login")]:
        r = client.get(path)
        assert r.status_code == 200 and needle in r.text, path
    assert "Private (randomised MAC)" in client.get("/clients?show=all").text  # aa: has the local bit set


def test_forward_auth(client):
    client.cookies.clear()
    r = client.get("/auth/verify", headers={"X-Forwarded-Host": "nas.example.com", "X-Forwarded-Uri": "/x"}, follow_redirects=False)
    assert r.status_code == 302 and "login?next=" in r.headers["location"]
    secret, _ = make_user("fa", role="viewer")
    login_totp(client, "fa", secret)
    r = client.get("/auth/verify")
    assert r.status_code == 200 and r.headers["x-portal-user"] == "fa"
    assert client.get("/auth/verify?role=operator").status_code == 403


def test_open_redirect_blocked():
    from app.auth import _safe_next
    assert _safe_next("https://evil.example/") == "/"
    assert _safe_next("//evil.example") == "/"
    assert _safe_next("/clients") == "/clients"


def test_waf_shipper_counts_reach_threats_page(client, tmp_path):
    from app import waflog
    access = tmp_path / "access.log"
    access.write_text(json.dumps({"ts": time.time(), "status": 403, "request": {"host": "nas.example.com"}}) + "\n"
                      + json.dumps({"ts": time.time(), "status": 200, "request": {"host": "nas.example.com"}}) + "\n"
                      + "not json\n")
    offset, hits = waflog.read_new(access, waflog.parse_access, 0)
    assert not hits and offset == access.stat().st_size
    audit_log = tmp_path / "audit.log"
    audit_log.write_text(json.dumps({"transaction": {"server_id": "nas.example.com", "is_interrupted": True,
        "unix_timestamp": time.time_ns()}}) + "\n")
    _, hits = waflog.read_new(audit_log, waflog.parse_coraza, 0)
    assert sum(hits.values()) == 1

    body = {"hits": [{"day": d, "host": h, "kind": k, "count": c} for (d, h, k), c in hits.items()]}
    body["batch_id"] = "test-idempotent-batch-001"
    with TestClient(app, base_url=ORIGIN, client=("10.99.0.1", 5000)) as proxy:
        assert proxy.post("/internal/waf-hits", json=body, headers={"Authorization": "Bearer wrong"}).status_code == 403
        assert proxy.post("/internal/waf-hits", json=body, headers={"Authorization": "Bearer shiptoken"}).json()["stored"] == 1
        assert proxy.post("/internal/waf-hits", json=body, headers={"Authorization": "Bearer shiptoken"}).json()["duplicate"] is True
    # Right token from a non-proxy address is refused.
    assert client.post("/internal/waf-hits", json=body, headers={"Authorization": "Bearer shiptoken"}).status_code == 403

    secret, _ = make_user("wafviewer", role="viewer")
    client.cookies.clear()
    login_totp(client, "wafviewer", secret)
    assert "nas.example.com" in client.get("/threats").text
