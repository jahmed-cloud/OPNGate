"""Count WAF hits per site from the proxy's logs.

- Only Coraza audit records are evidence of WAF activity. Generic HTTP 403s
  may originate from the application, authentication, or CrowdSec.
- Interrupted transactions are blocks; non-interrupted rule matches are detections.

Two modes:
- local: the portal reads the logs itself (proxy and portal on one host).
- ship (`python -m app.waflog ship`): runs next to the proxy on another host, and every
  30 s POSTs per-site counts to the portal's /internal/waf-hits with a shared token.
Parsing is defensive: unknown lines are skipped, never fatal.
"""
import json
import logging
import math
import os
import re
import ssl
import sys
import threading
import time
import urllib.request
import uuid
from collections import Counter
from pathlib import Path

from .config import settings

log = logging.getLogger("portal")


def _host_from_headers(headers) -> str:
    if not isinstance(headers, dict):
        return ""
    for key, value in headers.items():
        if key.lower() == "host":
            return value[0] if isinstance(value, list) and value else str(value)
    return ""


def parse_access(line: str):
    """Access status alone cannot attribute a block to the WAF."""
    return None


def parse_coraza(line: str):
    entry = json.loads(line)
    if not isinstance(entry, dict):
        return None
    tx = entry.get("transaction") or entry
    if not isinstance(tx, dict):
        return None
    req = tx.get("request") or {}
    if not isinstance(req, dict):
        return None
    interrupted = tx.get("is_interrupted") is True
    messages = entry.get("messages") or tx.get("messages") or []
    if not interrupted and not (isinstance(messages, list) and any(isinstance(m, dict) and m for m in messages)):
        return None
    # server_id remains available when request headers are excluded from audit logs.
    host = req.get("host") or _host_from_headers(req.get("headers")) or tx.get("server_id")
    stamp = float(tx.get("unix_timestamp") or 0)
    if not math.isfinite(stamp) or stamp < 0:
        return None
    # Coraza emits Unix nanoseconds. Accept seconds from compatible log exporters.
    if stamp > 10**14:
        stamp /= 1e9
    return str(host or "?")[:120], "waf_blocked" if interrupted else "waf_detected", stamp or None


_RULE_ID = re.compile(r'\[id "(\d+)"\]')
_RULE_MSG = re.compile(r'\[msg "([^"]{0,200})"\]')
_RULE_SEV = re.compile(r'\[severity "([^"]{0,20})"\]')
# CRS bookkeeping rules (anomaly score totals, reporting); listed only when nothing else matched.
_SUMMARY_RULE = re.compile(r"^(949|959|980)\d{3}$")
MAX_EVENTS = 200


def coraza_detail(line: str):
    """One audit record as a small event for the Threats page: who, where, which rules.
    Headers and bodies are never logged (SecAuditLogParts AHZ); the query string is dropped."""
    entry = json.loads(line)
    tx = entry.get("transaction") if isinstance(entry, dict) else None
    if not isinstance(tx, dict):
        return None
    req = tx.get("request") if isinstance(tx.get("request"), dict) else {}
    rules = []
    for m in entry.get("messages") or tx.get("messages") or []:
        text = (m.get("error_message") or m.get("message") or "") if isinstance(m, dict) else ""
        rule_id = _RULE_ID.search(text)
        if rule_id:
            msg, sev = _RULE_MSG.search(text), _RULE_SEV.search(text)
            rules.append({"id": rule_id.group(1), "msg": msg.group(1) if msg else "",
                          "severity": sev.group(1) if sev else ""})
    real = [r for r in rules if not _SUMMARY_RULE.match(r["id"])]
    interrupted = tx.get("is_interrupted") is True
    if not (rules or interrupted):
        return None
    stamp = float(tx.get("unix_timestamp") or 0)
    stamp = stamp / 1e9 if stamp > 10**14 else stamp
    producer = tx.get("producer") if isinstance(tx.get("producer"), dict) else {}
    return {
        "ts": int(stamp) if math.isfinite(stamp) and stamp > 0 else int(time.time()),
        "host": str(req.get("host") or tx.get("server_id") or "?")[:120],
        "client_ip": str(tx.get("client_ip") or "")[:45],
        "method": str(req.get("method") or "")[:10],
        "path": str(req.get("uri") or "").split("?", 1)[0][:200],
        "rules": (real or rules)[:5],
        "blocked": interrupted,
        "engine": str(producer.get("rule_engine") or "")[:20],
    }


def read_new(path: Path, parser, offset: int, max_lines: int = 2000, events: list | None = None,
             detail=None) -> tuple:
    """Return (new_offset, Counter of (day, host, kind)) for complete lines after offset.
    With events and detail, also collect up to MAX_EVENTS detail records."""
    hits = Counter()
    if not path.exists():
        return offset, hits
    if offset > path.stat().st_size:  # rotated
        offset = 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        fh.seek(offset)
        for _ in range(max_lines):
            line = fh.readline()
            if not line or not line.endswith("\n"):
                break
            try:
                hit = parser(line)
                if hit:
                    host, kind, ts = hit
                    day = time.strftime("%Y-%m-%d", time.gmtime(float(ts) if ts else time.time()))
                    hits[(day, str(host or "?")[:120], kind)] += 1
                    if events is not None and detail and len(events) < MAX_EVENTS:
                        record = detail(line)
                        if record:
                            events.append(record)
            except (ValueError, AttributeError, TypeError, OverflowError, OSError):
                hit = None
            offset = fh.tell()
    return offset, hits


SOURCES = (("coraza", lambda: settings.coraza_audit_log, parse_coraza, coraza_detail),)


def store(hits: Counter, batch_id: str | None = None, heartbeat: bool = False) -> bool:
    from . import db

    with db.tx() as conn:
        if heartbeat:
            conn.execute("INSERT INTO kv(k,v) VALUES ('waf_last_seen',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (str(db.now()),))
        if batch_id:
            inserted = conn.execute("INSERT OR IGNORE INTO waf_batches(batch_id,received_at) VALUES (?,?)", (batch_id, db.now())).rowcount
            if not inserted:
                return False
        conn.executemany(
            "INSERT INTO waf_hits(day, host, kind, count) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(day, host, kind) DO UPDATE SET count = count + excluded.count",
            [(day, host, kind, count) for (day, host, kind), count in hits.items()],
        )
    return True


def clean_event(e) -> dict | None:
    """Validate one event from the shipper (or the local reader) before storing it."""
    if not isinstance(e, dict):
        return None
    ts = e.get("ts")
    if type(ts) is not int or ts <= 0:
        return None
    rules = [r for r in (e.get("rules") or []) if isinstance(r, dict)][:5]
    return {
        "ts": ts, "host": str(e.get("host") or "?")[:120], "client_ip": str(e.get("client_ip") or "")[:45],
        "method": str(e.get("method") or "")[:10], "path": str(e.get("path") or "")[:200],
        "rules": [{"id": str(r.get("id") or "")[:10], "msg": str(r.get("msg") or "")[:200],
                   "severity": str(r.get("severity") or "")[:20]} for r in rules],
        "blocked": e.get("blocked") is True, "engine": str(e.get("engine") or "")[:20],
    }


def store_events(events) -> None:
    from . import db

    rows = [e for e in map(clean_event, events if isinstance(events, list) else []) if e]
    if not rows:
        return
    with db.tx() as conn:
        conn.executemany(
            "INSERT INTO waf_events(ts, host, client_ip, method, path, rules, blocked) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(e["ts"], e["host"], e["client_ip"], e["method"], e["path"], json.dumps(e["rules"]), int(e["blocked"]))
             for e in rows],
        )
        latest = max(rows, key=lambda e: e["ts"])
        if latest["engine"]:
            conn.execute("INSERT INTO kv(k,v) VALUES ('waf_engine',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                         (f'{latest["engine"]}|{latest["ts"]}',))


# ------------------------------------------------------------------ local mode

def scan_once() -> None:
    from . import db

    for name, path, parser, detail in SOURCES:
        key = f"waf_offset_{name}"
        events = []
        offset, hits = read_new(path(), parser, int(db.kv_get(key, "0")), events=events, detail=detail)
        store(hits, heartbeat=path().exists())
        store_events(events)
        db.kv_set(key, str(offset))


def start_background(stop: threading.Event) -> threading.Thread:
    from . import db

    def loop():
        last_prune = 0
        while not stop.wait(15):
            try:
                if settings.caddy_access_log.exists() or settings.coraza_audit_log.exists():
                    scan_once()
                if time.monotonic() - last_prune >= 3600:
                    db.prune()
                    last_prune = time.monotonic()
            except Exception:  # keep the reader alive whatever a log line contains
                log.exception("waf log scan failed")

    t = threading.Thread(target=loop, daemon=True, name="waflog")
    t.start()
    return t


# ------------------------------------------------------------------ ship mode

def ship_forever() -> None:
    url = os.environ["PORTAL_SHIP_URL"]
    token = os.environ["PORTAL_WAF_SHIP_TOKEN"]
    ctx = ssl.create_default_context(cafile=os.environ.get("PORTAL_SHIP_CA") or None)
    state_file = settings.data_dir / "shipper-offsets.json"
    pending_file = settings.data_dir / "shipper-pending.json"
    try:
        offsets = json.loads(state_file.read_text())
    except (OSError, ValueError):
        offsets = {}
    log.info("shipping WAF counts to %s", url)
    while True:
        try:
            if pending_file.exists():
                pending = json.loads(pending_file.read_text())
            else:
                new_offsets, hits, events = dict(offsets), Counter(), []
                for name, path, parser, detail in SOURCES:
                    new_offsets[name], found = read_new(path(), parser, int(offsets.get(name, 0)),
                                                        events=events, detail=detail)
                    hits.update(found)
                pending = {"offsets": new_offsets, "body": {"batch_id": uuid.uuid4().hex,
                    "hits": [{"day": d, "host": h, "kind": k, "count": c} for (d, h, k), c in hits.items()],
                    "events": events}}
                _save_json(pending_file, pending)
            req = urllib.request.Request(url, data=json.dumps(pending["body"]).encode(), method="POST", headers={
                "Content-Type": "application/json", "Authorization": f"Bearer {token}"})
            with urllib.request.urlopen(req, timeout=15, context=ctx) as response:
                result = json.loads(response.read())
                if result.get("ok") is not True:
                    raise ValueError("portal did not acknowledge batch")
            offsets = pending["offsets"]
            _save_json(state_file, offsets)
            pending_file.unlink()
        except (OSError, ValueError) as exc:
            log.warning("ship failed, will retry: %s", exc)
        time.sleep(30)


def _save_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value), encoding="utf-8")
    temporary.replace(path)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if sys.argv[1:] == ["ship"]:
        ship_forever()
    else:
        sys.exit("usage: python -m app.waflog ship")
