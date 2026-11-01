#!/usr/local/bin/python3
"""OPNsense firewall agent.

Runs on the firewall as root. Standard library only (plus the stock `openssl`,
`pfctl`, `wg`, `arp`, `netstat` binaries), so nothing needs installing from pkg.

- Every 30 s it collects health, clients, traffic, VPN, DNS and threat data and
  PUSHES it to the portal's ingest listener over mutual TLS.
- Every 15 s it PULLS approved control actions. Each action carries a WebAuthn
  assertion made by an operator's security key over the SHA-256 of the exact
  payload. The agent verifies that signature itself, against public keys in a
  local file that only an admin on MGMT can change, then checks the action against
  its own allowlist and rules before running it. The portal is never trusted.
"""
import argparse
import base64
import hashlib
import ipaddress
import json
import logging
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

VERSION = "1.1.0"
log = logging.getLogger("fw-agent")

DEFAULT_CONFIG = "/usr/local/etc/fw-agent/agent.json"


# =============================================================== helpers

def run(cmd, timeout=20, check=False, input_data=None, cwd=None):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input_data, cwd=cwd)
    except (OSError, subprocess.TimeoutExpired) as exc:
        if check:
            raise ActionFailed(f"{cmd[0]}: {exc}") from exc
        return 1, "", str(exc)
    if check and proc.returncode != 0:
        raise ActionFailed(f"{' '.join(cmd)} failed: {proc.stderr.strip() or proc.stdout.strip()}")
    return proc.returncode, proc.stdout, proc.stderr


def b64u_decode(value: str) -> bytes:
    value = str(value)
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def num(value, default=None):
    try:
        return float(str(value).split()[0])
    except (TypeError, ValueError, IndexError):
        return default


class State:
    """Small JSON state file: log offsets, replay protection, active blocks/pauses."""

    def __init__(self, path):
        self.path = path
        try:
            with open(path, encoding="utf-8") as fh:
                self.data = json.load(fh)
        except (OSError, ValueError):
            self.data = {}
        for key, default in (("offsets", {}), ("seen_actions", {}), ("sign_counts", {}), ("blocks", {}), ("paused", {}), ("limits", {})):
            self.data.setdefault(key, default)

    def save(self):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh)
        os.replace(tmp, self.path)

    def __getitem__(self, key):
        return self.data[key]


# =============================================================== collection

def gateway_status(cfg):
    out = {"name": cfg.get("gateway_name", "WAN"), "online": False, "latency_ms": None, "loss_pct": None}
    code, stdout, _ = run(["/usr/local/sbin/pluginctl", "-r", "return_gateways_status"])
    gateways = {}
    if code == 0:
        try:
            gateways = (json.loads(stdout) or {}).get("dpinger", {}) or {}
        except ValueError:
            gateways = {}
    if gateways:
        name = cfg.get("gateway_name") or next(iter(gateways))
        gw = gateways.get(name) or next(iter(gateways.values()))
        status = str(gw.get("status", "")).lower()
        out.update(
            name=gw.get("name", name),
            online=status not in ("down", "force_down"),
            status=status or "none",
            latency_ms=num(gw.get("delay")),
            loss_pct=num(gw.get("loss")),
        )
    else:
        target = cfg.get("ping_target", "1.1.1.1")
        code, stdout, _ = run(["ping", "-c", "3", "-q", "-t", "6", target], timeout=10)
        loss = re.search(r"([\d.]+)% packet loss", stdout)
        rtt = re.search(r"= [\d.]+/([\d.]+)/", stdout)
        out.update(online=code == 0, loss_pct=num(loss.group(1)) if loss else 100.0,
                   latency_ms=num(rtt.group(1)) if rtt else None, status="ping")
    wan = cfg.get("wan_interface")
    if wan:
        _, stdout, _ = run(["ifconfig", wan])
        m = re.search(r"\binet (\d+\.\d+\.\d+\.\d+)", stdout)
        out["wan_ip"] = m.group(1) if m else None
    return out


def uptime_seconds():
    _, stdout, _ = run(["sysctl", "-n", "kern.boottime"])
    m = re.search(r"sec = (\d+)", stdout)
    return int(time.time()) - int(m.group(1)) if m else None


class Rates:
    """Turns interface byte counters into bit/s between two samples."""

    def __init__(self):
        self.prev = {}

    def interfaces(self, cfg):
        segments = cfg.get("segments", {})
        code, stdout, _ = run(["netstat", "-ibn", "--libxo", "json"])
        if code != 0:
            return []
        try:
            rows = json.loads(stdout)["statistics"]["interface"]
        except (ValueError, KeyError):
            return []
        now = time.monotonic()
        out = []
        for row in rows:
            name = row.get("name")
            if name not in segments or not str(row.get("network", "")).startswith("<Link"):
                continue
            rx, tx = int(row.get("received-bytes", 0)), int(row.get("sent-bytes", 0))
            prev = self.prev.get(name)
            self.prev[name] = (now, rx, tx)
            rx_bps = tx_bps = 0.0
            if prev and now > prev[0] and rx >= prev[1] and tx >= prev[2]:
                rx_bps = (rx - prev[1]) * 8 / (now - prev[0])
                tx_bps = (tx - prev[2]) * 8 / (now - prev[0])
            out.append({"name": name, "segment": segments[name], "rx_bps": round(rx_bps), "tx_bps": round(tx_bps)})
        return out


def _state_addr(token):
    """'192.168.20.180:50009' -> '192.168.20.180'; IPv6 is printed as 'fe80::1[443]'."""
    return token.split("[", 1)[0] if "[" in token else token.rsplit(":", 1)[0]


class ClientRates:
    """Per-device download/upload from pf state byte counters (pfctl -vvss), as the change between
    two polls. Only states on inside interfaces count, so NAT's WAN copy of a state is not added twice.
    Bytes of a state that opened and closed between two polls are missed; good enough for a live view."""

    def __init__(self):
        self.prev, self.at = {}, None

    @staticmethod
    def parse(text):
        """Yield (state_id, iface, initiator_ip, responder_ip, bytes_from_initiator, bytes_to_initiator)."""
        block = None
        for line in text.splitlines() + [""]:
            if line and not line[0].isspace():
                if block and block.get("id"):
                    yield block["id"], block.get("iface"), block["init"], block["resp"], block["a"], block["b"]
                f = line.split()
                block = None
                if len(f) >= 5 and f[3] in ("<-", "->"):
                    # "<-": the state was created inbound, right side is the initiator.
                    # "->": created outbound, left side initiated; a NATed original follows in ().
                    if f[3] == "<-":
                        block = {"init": _state_addr(f[4]), "resp": _state_addr(f[2])}
                    else:
                        dest = f[5] if f[4].startswith("(") and len(f) > 5 else f[4]
                        block = {"init": _state_addr(f[2]), "resp": _state_addr(dest)}
                    block.update(a=0, b=0)
                continue
            if block is None:
                continue
            m = re.search(r"(\d+):(\d+) bytes", line)
            if m:
                block["a"], block["b"] = int(m.group(1)), int(m.group(2))
            m = re.search(r"\bid: ([0-9a-f]+)", line)
            if m:
                block["id"] = m.group(1)
            m = re.search(r"origif: (\S+)", line)
            if m:
                block["iface"] = m.group(1)

    def sample(self, cfg):
        """{ip: (down_bps, up_bps)}; empty on the first call."""
        wan = {name for name, seg in cfg.get("segments", {}).items() if seg.upper() == "WAN"}
        code, stdout, _ = run(["pfctl", "-vvss"])
        if code != 0:
            return {}
        now = time.monotonic()
        current, moved = {}, {}
        for sid, iface, init, resp, a, b in self.parse(stdout):
            if iface in wan:
                continue
            current[sid] = (a, b)
            pa, pb = self.prev.get(sid, (0, 0))
            da, db = max(0, a - pa), max(0, b - pb)
            for ip, down, up in ((init, db, da), (resp, da, db)):
                totals = moved.setdefault(ip, [0, 0])
                totals[0] += down
                totals[1] += up
        first, elapsed = self.at is None, now - (self.at or now)
        self.prev, self.at = current, now
        if first or elapsed <= 0:
            return {}
        return {ip: (round(d * 8 / elapsed), round(u * 8 / elapsed)) for ip, (d, u) in moved.items()}


def _leases(cfg):
    """mac -> {ip, hostname} from dnsmasq, Kea or ISC dhcpd lease files (whichever exist)."""
    leases = {}
    for path in cfg.get("dhcp_leases", ["/var/db/dnsmasq.leases", "/var/db/kea/kea-leases4.csv", "/var/dhcpd/var/db/dhcpd.leases"]):
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        if path.endswith(".csv"):  # Kea: address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,...
            for line in text.splitlines()[1:]:
                f = line.split(",")
                if len(f) > 8 and f[1]:
                    leases[f[1].lower()] = {"ip": f[0], "hostname": f[8].rstrip(".")}
        elif "lease " in text and "{" in text:  # ISC dhcpd
            for m in re.finditer(r"lease ([\d.]+) \{(.*?)\}", text, re.S):
                hw = re.search(r"hardware ethernet ([0-9a-f:]+);", m.group(2), re.I)
                host = re.search(r'client-hostname "([^"]*)";', m.group(2))
                if hw:
                    leases[hw.group(1).lower()] = {"ip": m.group(1), "hostname": host.group(1) if host else ""}
        else:  # dnsmasq: expiry mac ip hostname client-id
            for line in text.splitlines():
                f = line.split()
                if len(f) >= 4:
                    leases[f[1].lower()] = {"ip": f[2], "hostname": "" if f[3] == "*" else f[3]}
    return leases


def arp_table():
    code, stdout, _ = run(["arp", "-an", "--libxo", "json"])
    if code != 0:
        return []
    try:
        return json.loads(stdout)["arp"]["arp-cache"]
    except (ValueError, KeyError):
        return []


def _arp_max_age():
    code, stdout, _ = run(["sysctl", "-n", "net.link.ether.inet.max_age"])
    return int(num(stdout.strip(), 1200)) if code == 0 else 1200


def clients(cfg, client_rates=None, state=None):
    segments = cfg.get("segments", {})
    speeds = client_rates.sample(cfg) if client_rates else {}
    paused = (state["paused"] if state else {})
    limits = (state["limits"] if state else {})
    leases = _leases(cfg)
    max_age = _arp_max_age()
    seen = {}
    for entry in arp_table():
        mac = str(entry.get("mac-address", "")).lower()
        if not re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac) or entry.get("permanent"):
            continue
        iface = entry.get("interface", "")
        if segments.get(iface, "").upper() == "WAN":
            continue
        lease = leases.get(mac, {})
        # An ARP entry's countdown restarts at max_age whenever the device is heard from, so the time
        # already counted down is roughly how long it has been quiet.
        expires = entry.get("expires")
        idle = max(0, max_age - int(expires)) if isinstance(expires, (int, float)) else None
        ip = entry.get("ip-address")
        down, up = speeds.get(ip, (0, 0)) if speeds else (None, None)
        seen[mac] = {"mac": mac, "ip": ip, "hostname": lease.get("hostname", ""),
                     "segment": segments.get(iface, iface), "online": True, "idle_s": idle,
                     "down_bps": down, "up_bps": up}
    for mac, lease in leases.items():
        if mac not in seen:
            seen[mac] = {"mac": mac, "ip": lease.get("ip"), "hostname": lease.get("hostname", ""), "segment": None, "online": False}
    for mac, rec in seen.items():
        rec["paused"] = mac in paused
        if mac in limits:
            rec["limit"] = {"down_mbps": limits[mac]["down_mbps"], "up_mbps": limits[mac]["up_mbps"],
                            "until": limits[mac].get("until", 0)}
    return list(seen.values())


def _opn_interfaces(path="/conf/config.xml"):
    """Device name -> OPNsense interface name (igc1 -> lan), as the shaper model wants it."""
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return {}
    ifaces = root.find("interfaces")
    return {} if ifaces is None else {(node.findtext("if") or ""): node.tag for node in ifaces}


def _wg_names_from_config(path="/conf/config.xml"):
    """Peer names as entered in OPNsense (VPN > WireGuard > Peers), keyed by public key."""
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return {}
    return {c.findtext("pubkey").strip(): (c.findtext("name") or "").strip()
            for c in root.iter("client") if c.findtext("pubkey")}


def wireguard(cfg):
    code, stdout, _ = run(["wg", "show", "all", "dump"])
    if code != 0:
        return []
    names = {**_wg_names_from_config(), **cfg.get("wg_names", {})}
    peers = []
    for line in stdout.splitlines():
        f = line.split("\t")
        if len(f) == 9:
            iface, pub, _psk, endpoint, allowed, handshake, rx, tx, _ka = f
            peers.append({
                "interface": iface, "public_key": pub, "name": names.get(pub, ""),
                "endpoint": None if endpoint == "(none)" else endpoint, "allowed_ips": allowed,
                "last_handshake": int(handshake) or None, "rx": int(rx), "tx": int(tx),
            })
    return peers


def dns_stats(cfg):
    out = {}
    code, stdout, _ = run(["unbound-control", "-c", "/var/unbound/unbound.conf", "stats_noreset"])
    if code == 0:
        stats = dict(line.split("=", 1) for line in stdout.splitlines() if "=" in line)
        out["total_queries"] = int(num(stats.get("total.num.queries"), 0))
        out["cache_hits"] = int(num(stats.get("total.num.cachehits"), 0))
    api = cfg.get("opnsense_api") or {}
    if api.get("key") and api.get("secret"):
        try:
            data = local_api(api, "/api/unbound/overview/totals/10")
            out["blocklist_size"] = data.get("blocklist_size")
            blocked = data.get("blocked") or {}
            out["blocked"] = blocked.get("total") if isinstance(blocked, dict) else blocked
            if isinstance(blocked, dict) and blocked.get("pcnt") is not None:
                out["blocked_pct"] = num(blocked.get("pcnt"))
            for key in ("top_blocked", "top_clients"):
                items = data.get(key) or {}
                if isinstance(items, dict):
                    out[key] = {k: (v.get("total") if isinstance(v, dict) else v) for k, v in list(items.items())[:10]}
        except Exception as exc:  # optional source; never break telemetry
            log.debug("unbound API unavailable: %s", exc)
    return out


def local_api(api, path):
    """OPNsense's own API on 127.0.0.1. The key never leaves the firewall."""
    ctx = ssl.create_default_context()
    if not api.get("verify_tls", False):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    token = base64.b64encode(f"{api['key']}:{api['secret']}".encode()).decode()
    req = urllib.request.Request(api.get("url", "https://127.0.0.1").rstrip("/") + path,
                                 headers={"Authorization": f"Basic {token}"})
    with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
        return json.loads(resp.read())


def threats(cfg):
    out = {"tables": {}}
    for table in cfg.get("pf_tables", []):
        code, stdout, _ = run(["pfctl", "-t", table, "-T", "show"])
        if code == 0:
            out["tables"][table] = sum(1 for line in stdout.splitlines() if line.strip())
    if shutil.which("cscli"):
        code, stdout, _ = run(["cscli", "decisions", "list", "-o", "json"], timeout=30)
        if code == 0:
            try:
                alerts = json.loads(stdout) or []
            except ValueError:
                alerts = []
            by_country, by_scenario, bans = {}, {}, 0
            for alert in alerts:
                count = len(alert.get("decisions") or [])
                bans += count
                cc = (alert.get("source") or {}).get("cn") or "??"
                by_country[cc] = by_country.get(cc, 0) + count
                scenario = alert.get("scenario") or "?"
                by_scenario[scenario] = by_scenario.get(scenario, 0) + count
            out["crowdsec"] = {"active_bans": bans, "by_country": by_country, "by_scenario": by_scenario}
    return out


def tail_new_lines(state, path, max_lines=500):
    """New complete lines since last call. Starts at end of file on first sight; follows rotation."""
    try:
        st = os.stat(path)
    except OSError:
        return []
    offsets = state["offsets"]
    rec = offsets.get(path)
    if rec is None or rec.get("inode") != st.st_ino or rec.get("offset", 0) > st.st_size:
        start = st.st_size if rec is None else 0
        rec = {"inode": st.st_ino, "offset": start}
    lines = []
    with open(path, "rb") as fh:
        fh.seek(rec["offset"])
        while len(lines) < max_lines:
            line = fh.readline()
            if not line or not line.endswith(b"\n"):
                break
            lines.append(line.decode("utf-8", "replace"))
            rec["offset"] = fh.tell()
    offsets[path] = rec
    return lines


def collect_events(cfg, state):
    events = []
    eve = cfg.get("suricata_eve", "/var/log/suricata/eve.json")
    for line in tail_new_lines(state, eve):
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if e.get("event_type") != "alert":
            continue
        alert = e.get("alert") or {}
        sev = {1: "critical", 2: "warning"}.get(alert.get("severity"), "info")
        events.append({
            "source": "suricata", "severity": sev,
            "title": f"{alert.get('signature', 'IDS alert')} {e.get('src_ip')} -> {e.get('dest_ip')}:{e.get('dest_port', '')}",
            "detail": {k: e.get(k) for k in ("timestamp", "src_ip", "src_port", "dest_ip", "dest_port", "proto", "in_iface")}
                      | {"category": alert.get("category"), "signature_id": alert.get("signature_id")},
        })
    for path in cfg.get("event_files", ["/var/log/portal-events.jsonl"]):
        for line in tail_new_lines(state, path):
            try:
                e = json.loads(line)
            except ValueError:
                e = {"title": line.strip()}
            if isinstance(e, dict):
                events.append({"source": e.get("source", "telegram"), "severity": e.get("severity", "info"),
                               "title": str(e.get("title") or e.get("text") or "event")[:300], "detail": e.get("detail")})
    return events


# =============================================================== portal client

class Portal:
    def __init__(self, cfg):
        self.base = cfg["portal_url"].rstrip("/")
        self.ctx = ssl.create_default_context(cafile=cfg["ca_file"])
        self.ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self.ctx.load_cert_chain(cfg["cert_file"], cfg["key_file"])

    def request(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"Content-Type": "application/json", "User-Agent": f"fw-agent/{VERSION}"})
        with urllib.request.urlopen(req, timeout=20, context=self.ctx) as resp:
            return json.loads(resp.read() or b"{}")


# =============================================================== action verification

class ActionRejected(Exception):
    pass


class ActionFailed(Exception):
    pass


MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
WG_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")
WG_IF_RE = re.compile(r"^wg[0-9]{1,2}$")
FLAG_UP, FLAG_UV = 0x01, 0x04
MAX_AGE = 15 * 60
CLOCK_SKEW = 120


def load_trusted_keys(path):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return {k["credential_id"]: k for k in data.get("keys", [])}


def openssl_verify(pem: str, alg: int, data: bytes, signature: bytes) -> bool:
    tmp = tempfile.mkdtemp(prefix="fwagent-")
    try:
        paths = {}
        for name, content in (("key.pem", pem.encode()), ("data.bin", data), ("sig.bin", signature)):
            paths[name] = os.path.join(tmp, name)
            with open(paths[name], "wb") as fh:
                fh.write(content)
        if alg in (-7, -257):  # ES256, RS256 (PKCS#1 v1.5)
            cmd = ["openssl", "dgst", "-sha256", "-verify", paths["key.pem"], "-signature", paths["sig.bin"], paths["data.bin"]]
        elif alg == -8:  # EdDSA (Ed25519)
            cmd = ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", paths["key.pem"], "-rawin",
                   "-in", paths["data.bin"], "-sigfile", paths["sig.bin"]]
        else:
            return False
        # Both commands exit 0 only when the signature verifies.
        code, _, _ = run(cmd)
        return code == 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _cidr(value):
    try:
        net = ipaddress.ip_network(str(value), strict=False)
    except ValueError as exc:
        raise ActionRejected("bad cidr") from exc
    if net.prefixlen < (16 if net.version == 4 else 48) or net.is_private or net.is_loopback or net.is_multicast or net.is_link_local:
        raise ActionRejected("cidr not allowed")
    return str(net)


def validate_params(kind, params, cfg):
    """The firewall's own copy of the rules; the portal's validation is not relied on."""
    if not isinstance(params, dict):
        raise ActionRejected("params must be an object")
    acfg = cfg.get("actions", {})
    if kind in ("block_ip", "unblock_ip"):
        cidr = _cidr(params.get("cidr"))
        if kind == "block_ip":
            net = ipaddress.ip_network(cidr)
            for protected in acfg.get("protected_cidrs", []):
                if net.overlaps(ipaddress.ip_network(protected, strict=False)):
                    raise ActionRejected(f"{cidr} overlaps protected {protected}")
            minutes = params.get("minutes")
            if not isinstance(minutes, int) or not 1 <= minutes <= 10080:
                raise ActionRejected("minutes out of range")
            return {"cidr": cidr, "minutes": minutes}
        return {"cidr": cidr}
    if kind == "wg_disconnect":
        if not WG_IF_RE.match(str(params.get("interface", ""))) or not WG_KEY_RE.match(str(params.get("public_key", ""))):
            raise ActionRejected("bad wireguard parameters")
        return {"interface": params["interface"], "public_key": params["public_key"]}
    if kind in ("pause_client", "resume_client"):
        mac = str(params.get("mac", ""))
        if not MAC_RE.match(mac):
            raise ActionRejected("bad mac")
        if mac in [m.lower() for m in acfg.get("protected_macs", [])]:
            raise ActionRejected("mac is protected")
        if kind == "pause_client":
            minutes = params.get("minutes")
            if not isinstance(minutes, int) or not 0 <= minutes <= 10080:
                raise ActionRejected("minutes out of range")
            return {"mac": mac, "minutes": minutes}
        return {"mac": mac}
    if kind in ("limit_client", "unlimit_client"):
        mac = str(params.get("mac", ""))
        if not MAC_RE.match(mac):
            raise ActionRejected("bad mac")
        if mac in [m.lower() for m in acfg.get("protected_macs", [])]:
            raise ActionRejected("mac is protected")
        if kind == "unlimit_client":
            return {"mac": mac}
        speeds = {}
        for key in ("down_mbps", "up_mbps"):
            value = params.get(key)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0.1 <= value <= 1000:
                raise ActionRejected(f"{key} must be 0.1-1000")
            speeds[key] = float(value)
        minutes = params.get("minutes")
        if not isinstance(minutes, int) or not 0 <= minutes <= 10080:
            raise ActionRejected("minutes out of range")
        return {"mac": mac, **speeds, "minutes": minutes}
    if kind == "breakglass":
        if not isinstance(params.get("enable"), bool):
            raise ActionRejected("enable must be true/false")
        return {"enable": params["enable"]}
    if kind == "backup_config":
        return {}
    raise ActionRejected("unknown action")


def verify_action(item, trusted, cfg, state, now=None):
    """Return the verified payload dict, or raise ActionRejected. Pure checks, no side effects."""
    now = int(now if now is not None else time.time())
    acfg = cfg.get("actions", {})
    payload_str = item.get("payload")
    if not isinstance(payload_str, str) or len(payload_str) > 4096:
        raise ActionRejected("missing payload")
    try:
        payload = json.loads(payload_str)
    except ValueError as exc:
        raise ActionRejected("payload is not json") from exc

    assertion = item.get("assertion") or {}
    response = assertion.get("response") or {}
    cred_id = assertion.get("rawId") or assertion.get("id")
    key = trusted.get(cred_id)
    if not key:
        raise ActionRejected("credential not in the firewall's trusted key list")

    try:
        client_data_raw = b64u_decode(response["clientDataJSON"])
        auth_data = b64u_decode(response["authenticatorData"])
        signature = b64u_decode(response["signature"])
        client_data = json.loads(client_data_raw)
    except (KeyError, ValueError, TypeError) as exc:
        raise ActionRejected("malformed assertion") from exc

    if client_data.get("type") != "webauthn.get":
        raise ActionRejected("wrong clientData type")
    if b64u_decode(client_data.get("challenge", "")) != hashlib.sha256(payload_str.encode("utf-8")).digest():
        raise ActionRejected("signature is not over this payload")
    if client_data.get("origin") != acfg["origin"] or client_data.get("crossOrigin"):
        raise ActionRejected("wrong origin")
    if len(auth_data) < 37 or auth_data[:32] != hashlib.sha256(acfg["rp_id"].encode()).digest():
        raise ActionRejected("wrong relying party")
    flags = auth_data[32]
    if not (flags & FLAG_UP and flags & FLAG_UV):
        raise ActionRejected("user presence and verification required")
    if not openssl_verify(key["public_key_pem"], int(key["alg"]), auth_data + hashlib.sha256(client_data_raw).digest(), signature):
        raise ActionRejected("bad signature")

    sign_count = int.from_bytes(auth_data[33:37], "big")
    stored = int(state["sign_counts"].get(cred_id, 0))
    if (sign_count or stored) and sign_count <= stored:
        raise ActionRejected("signature counter went backwards (cloned key or replay)")

    if payload.get("v") != 1 or payload.get("id") != item.get("id"):
        raise ActionRejected("payload id mismatch")
    if payload.get("rp_id") != acfg["rp_id"] or payload.get("origin") != acfg["origin"]:
        raise ActionRejected("payload for a different portal")
    created, expires = payload.get("created_at"), payload.get("expires_at")
    if not isinstance(created, int) or not isinstance(expires, int):
        raise ActionRejected("bad timestamps")
    if expires < now or created > now + CLOCK_SKEW or expires - created > MAX_AGE:
        raise ActionRejected("expired or not yet valid")
    if payload["id"] in state["seen_actions"]:
        raise ActionRejected("already processed (replay)")
    kind = payload.get("type")
    if kind not in acfg.get("allowed", []):
        raise ActionRejected(f"{kind} is not allowed on this firewall")
    payload["params"] = validate_params(kind, payload.get("params"), cfg)
    payload["_signer"] = key.get("user", "?")
    payload["_sign_count"] = sign_count
    return payload


# =============================================================== action execution

def _kill_states(cidr):
    run(["pfctl", "-k", cidr])
    run(["pfctl", "-k", "0.0.0.0/0" if ":" not in cidr else "::/0", "-k", cidr])
    # A LAN device's internet connections are NAT states keyed by the WAN address; the two kills
    # above miss them, so a paused phone would keep its open apps online.
    run(["pfctl", "-k", "nat", "-k", cidr])


def _ips_for_mac(mac):
    ips = [e.get("ip-address") for e in arp_table() if str(e.get("mac-address", "")).lower() == mac]
    code, stdout, _ = run(["ndp", "-an"])
    if code == 0:
        for line in stdout.splitlines():
            f = line.split()
            if len(f) >= 2 and f[1].lower() == mac:
                ips.append(f[0].split("%")[0])
    return sorted({ip for ip in ips if ip})


SHAPER_PHP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shaper.php")


def _shaper(*args):
    """Run shaper.php (OPNsense Traffic Shaper model) and apply it like the GUI's Apply button."""
    code, stdout, stderr = run(["php", SHAPER_PHP, *args], cwd="/usr/local/opnsense/mvc")
    try:
        result = json.loads(stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        result = {"ok": False, "error": (stderr or stdout).strip()[:200]}
    if not result.get("ok"):
        raise ActionFailed(f"shaper: {result.get('error')}")
    if args[0] != "list":
        for step in ("template reload OPNsense/Shaper", "template reload OPNsense/IPFW", "shaper reload", "ipfw reload"):
            run(["configctl", *step.split()])
    return result


def _set_limit(mac, rec):
    ips = [ip for ip in _ips_for_mac(mac) if ":" not in ip]
    if not ips:
        raise ActionFailed("no current IPv4 address for that MAC (device offline?)")
    device = next((e.get("interface") for e in arp_table() if str(e.get("mac-address", "")).lower() == mac), None)
    iface = _opn_interfaces().get(device or "")
    if not iface:
        raise ActionFailed(f"cannot map interface {device} to an OPNsense interface")
    _shaper("set", f"portal-{mac}", ips[0], iface, str(int(rec["down_mbps"] * 1000)), str(int(rec["up_mbps"] * 1000)))
    rec["ip"] = ips[0]


def _clear_limit(mac):
    _shaper("clear", f"portal-{mac}")
    # The shaper reload leaves deleted pipes in the kernel; drop ours (numbers 10000+) that nothing uses.
    code, stdout, _ = run(["dnctl", "pipe", "show"])
    used = set()
    for limits in (_shaper("list").get("limits") or {}).values():
        used.update(str(n) for n in limits.get("numbers", []))
    for number in re.findall(r"^(\d{5}):", stdout, re.M):
        if int(number) >= 10000 and number not in used:
            run(["dnctl", "pipe", number, "delete"])


def execute(payload, cfg, state):
    acfg = cfg["actions"]
    kind, p = payload["type"], payload["params"]
    now = int(time.time())
    if kind == "block_ip":
        table = acfg.get("block_table", "portal_block")
        run(["pfctl", "-t", table, "-T", "add", p["cidr"]], check=True)
        _kill_states(p["cidr"])
        state["blocks"][p["cidr"]] = now + p["minutes"] * 60
        return f"{p['cidr']} added to {table} for {p['minutes']} min"
    if kind == "unblock_ip":
        table = acfg.get("block_table", "portal_block")
        run(["pfctl", "-t", table, "-T", "delete", p["cidr"]])
        state["blocks"].pop(p["cidr"], None)
        return f"{p['cidr']} removed from {table}"
    if kind == "wg_disconnect":
        run(["wg", "set", p["interface"], "peer", p["public_key"], "remove"], check=True)
        return f"peer removed from {p['interface']} until the WireGuard service is next reloaded"
    if kind == "pause_client":
        ips = _ips_for_mac(p["mac"])
        if not ips:
            raise ActionFailed("no current IP for that MAC (device offline?)")
        table = acfg.get("pause_table", "portal_paused")
        run(["pfctl", "-t", table, "-T", "add", *ips], check=True)
        for ip in ips:
            _kill_states(ip)
        state["paused"][p["mac"]] = {"ips": ips, "until": now + p["minutes"] * 60 if p["minutes"] else 0}
        return f"{p['mac']} paused ({', '.join(ips)})"
    if kind == "resume_client":
        rec = state["paused"].pop(p["mac"], None)
        ips = sorted(set((rec or {}).get("ips", []) + _ips_for_mac(p["mac"])))
        if ips:
            run(["pfctl", "-t", acfg.get("pause_table", "portal_paused"), "-T", "delete", *ips])
        return f"{p['mac']} resumed"
    if kind == "limit_client":
        rec = {"down_mbps": p["down_mbps"], "up_mbps": p["up_mbps"],
               "until": now + p["minutes"] * 60 if p["minutes"] else 0}
        _set_limit(p["mac"], rec)
        state["limits"][p["mac"]] = rec
        return f"{p['mac']} limited to {p['down_mbps']:g}/{p['up_mbps']:g} Mbit/s (down/up) on {rec['ip']}"
    if kind == "unlimit_client":
        state["limits"].pop(p["mac"], None)
        _clear_limit(p["mac"])
        return f"speed limit removed from {p['mac']}"
    if kind == "breakglass":
        iface = acfg.get("breakglass_interface")
        if not iface:
            raise ActionFailed("breakglass_interface not configured on the firewall")
        run(["ifconfig", iface, "up" if p["enable"] else "down"], check=True)
        return f"{iface} {'up' if p['enable'] else 'down'} (runtime only; reverts on reboot or interface reconfigure)"
    if kind == "backup_config":
        out_dir = acfg.get("backup_dir", "/var/backups/fw-agent")
        passfile = acfg.get("backup_passphrase_file", "/usr/local/etc/fw-agent/backup.pass")
        if not os.path.exists(passfile):
            raise ActionFailed(f"{passfile} missing")
        os.makedirs(out_dir, mode=0o700, exist_ok=True)
        target = os.path.join(out_dir, time.strftime("config-%Y%m%d-%H%M%S.xml.enc"))
        run(["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "600000", "-salt",
             "-in", "/conf/config.xml", "-out", target, "-pass", f"file:{passfile}"], check=True)
        os.chmod(target, 0o600)
        backups = sorted(f for f in os.listdir(out_dir) if f.startswith("config-"))
        for old in backups[:-30]:
            os.remove(os.path.join(out_dir, old))
        return f"encrypted backup written to {target}"
    raise ActionFailed("no executor")


def housekeeping(cfg, state):
    """Expire timed blocks/pauses and follow paused clients to new IPs."""
    acfg = cfg.get("actions", {})
    now = int(time.time())
    for cidr, until in list(state["blocks"].items()):
        if until <= now:
            run(["pfctl", "-t", acfg.get("block_table", "portal_block"), "-T", "delete", cidr])
            del state["blocks"][cidr]
            log.info("block on %s expired", cidr)
    for mac, rec in list(state["paused"].items()):
        table = acfg.get("pause_table", "portal_paused")
        if rec.get("until") and rec["until"] <= now:
            if rec["ips"]:
                run(["pfctl", "-t", table, "-T", "delete", *rec["ips"]])
            del state["paused"][mac]
            continue
        new_ips = [ip for ip in _ips_for_mac(mac) if ip not in rec["ips"]]
        if new_ips:
            run(["pfctl", "-t", table, "-T", "add", *new_ips])
            rec["ips"] += new_ips
    for mac, rec in list(state["limits"].items()):
        try:
            if rec.get("until") and rec["until"] <= now:
                del state["limits"][mac]
                _clear_limit(mac)
                log.info("speed limit on %s expired", mac)
                continue
            ips = [ip for ip in _ips_for_mac(mac) if ":" not in ip]
            if ips and rec.get("ip") not in ips:
                _set_limit(mac, rec)
                log.info("speed limit on %s moved to %s", mac, rec["ip"])
        except ActionFailed as exc:
            log.warning("speed limit upkeep for %s: %s", mac, exc)
    cutoff = now - 7 * 86400
    state.data["seen_actions"] = {k: v for k, v in state["seen_actions"].items() if v > cutoff}


def process_actions(portal, cfg, state):
    acfg = cfg.get("actions", {})
    if not acfg.get("enabled"):
        return
    try:
        trusted = load_trusted_keys(acfg["trusted_keys_file"])
    except (OSError, ValueError, KeyError) as exc:
        log.error("trusted keys unavailable, refusing all actions: %s", exc)
        trusted = {}
    for item in portal.request("GET", "/v1/actions").get("actions", []):
        action_id = str(item.get("id", ""))[:64]
        try:
            payload = verify_action(item, trusted, cfg, state)
        except ActionRejected as exc:
            log.warning("REJECTED action %s: %s", action_id, exc)
            _report(portal, action_id, False, f"rejected by firewall: {exc}")
            continue
        # Record before running, so a crash mid-way can never lead to a second run.
        cred = item["assertion"].get("rawId") or item["assertion"].get("id")
        state["seen_actions"][payload["id"]] = int(time.time())
        state["sign_counts"][cred] = payload["_sign_count"]
        state.save()
        try:
            message = execute(payload, cfg, state)
            ok = True
        except ActionFailed as exc:
            message, ok = str(exc), False
        state.save()
        log.info("action %s %s by %s: %s", payload["type"], "ok" if ok else "FAILED", payload["_signer"], message)
        _report(portal, action_id, ok, message)


def _report(portal, action_id, ok, message):
    try:
        portal.request("POST", f"/v1/actions/{action_id}/result", {"ok": ok, "message": message, "agent": VERSION})
    except (urllib.error.URLError, OSError, ValueError) as exc:
        log.warning("could not report result for %s: %s", action_id, exc)


# =============================================================== main loop

def collect(cfg, rates, client_rates=None, state=None):
    def safe(fn, *args):
        try:
            return fn(*args)
        except Exception as exc:
            log.warning("%s failed: %s", fn.__name__, exc)
            return None

    return {
        "ts": int(time.time()),
        "version": VERSION,
        "hostname": os.uname().nodename,
        "uptime_s": safe(uptime_seconds),
        "gateway": safe(gateway_status, cfg) or {},
        "interfaces": safe(rates.interfaces, cfg) or [],
        "clients": safe(clients, cfg, client_rates, state) or [],
        "vpn": safe(wireguard, cfg) or [],
        "dns": safe(dns_stats, cfg) or {},
        "threats": safe(threats, cfg) or {},
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", default=DEFAULT_CONFIG)
    parser.add_argument("--once", action="store_true", help="collect once, print JSON, do not send")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    with open(args.config, encoding="utf-8") as fh:
        cfg = json.load(fh)
    rates, client_rates = Rates(), ClientRates()
    if args.once:
        rates.interfaces(cfg)
        client_rates.sample(cfg)
        time.sleep(2)
        print(json.dumps(collect(cfg, rates, client_rates), indent=2))
        return

    state = State(cfg.get("state_file", "/var/db/fw-agent/state.json"))
    portal = Portal(cfg)
    interval, poll = int(cfg.get("interval", 30)), int(cfg.get("action_poll", 15))
    pending_events = []
    next_push = 0.0
    log.info("fw-agent %s started; pushing to %s", VERSION, cfg["portal_url"])
    while True:
        started = time.monotonic()
        try:
            housekeeping(cfg, state)
        except Exception:
            log.exception("housekeeping failed")
        if started >= next_push:
            next_push = started + interval
            try:
                pending_events = (pending_events + collect_events(cfg, state))[-1000:]
                portal.request("POST", "/v1/telemetry", collect(cfg, rates, client_rates, state))
                if pending_events:
                    portal.request("POST", "/v1/events", {"events": pending_events})
                    pending_events = []
            except (urllib.error.URLError, OSError, ValueError) as exc:
                log.warning("push failed: %s", exc)
        try:
            process_actions(portal, cfg, state)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            log.warning("action poll failed: %s", exc)
        state.save()
        time.sleep(max(1.0, poll - (time.monotonic() - started)))


if __name__ == "__main__":
    sys.exit(main())
