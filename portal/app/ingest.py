"""Agent-facing API. Served on its own TLS listener that requires a client certificate
from the dedicated agent CA (see deploy/pki). It is never published through Cloudflare.

The firewall connects out to this; the portal never connects to the firewall.
"""
import json
import logging
import math
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request

from . import db, notify, oui
from .config import settings

log = logging.getLogger("portal")
MAX_BODY = 4 * 1024 * 1024
SEVERITIES = {"info", "warning", "critical"}



@asynccontextmanager
async def _lifespan(app):
    db.init()
    yield


ingest_app = FastAPI(title="portal-ingest", docs_url=None, redoc_url=None, openapi_url=None, lifespan=_lifespan)


async def _json(request: Request) -> dict:
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_BODY:
            raise HTTPException(413)
    try:
        data = json.loads(body)
    except ValueError as exc:
        raise HTTPException(400, "bad json") from exc
    if not isinstance(data, dict):
        raise HTTPException(400, "expected object")
    return data


def _num(value, default=None):
    try:
        number = float(value)
        return number if math.isfinite(number) and number >= 0 else default
    except (TypeError, ValueError):
        return default


def add_event(source: str, severity: str, title: str, detail=None, ts=None) -> None:
    severity = severity if severity in SEVERITIES else "info"
    db.run(
        "INSERT INTO events(ts, source, severity, title, detail) VALUES (?, ?, ?, ?, ?)",
        int(ts or db.now()), str(source)[:40], severity, str(title)[:300], json.dumps(detail)[:8000] if detail else None,
    )


@ingest_app.post("/v1/telemetry")
async def telemetry(request: Request):
    data = await _json(request)
    now = db.now()
    gw = data.get("gateway") or {}
    if not isinstance(gw, dict):
        raise HTTPException(400, "gateway must be an object")
    wan_up = 1 if gw.get("online") is True else 0 if gw.get("online") is False else None

    interfaces = [i for i in data.get("interfaces") or [] if isinstance(i, dict)]
    wan = next((i for i in interfaces if str(i.get("segment", "")).upper() == "WAN"), {})
    clients = [c for c in data.get("clients") or [] if isinstance(c, dict) and c.get("mac")]
    online = sum(1 for c in clients if c.get("online"))

    db.run(
        "INSERT OR REPLACE INTO samples(ts, wan_up, latency_ms, loss_pct, clients_online, rx_bps, tx_bps) VALUES (?, ?, ?, ?, ?, ?, ?)",
        now, wan_up, _num(gw.get("latency_ms")), _num(gw.get("loss_pct")), online,
        _num(wan.get("rx_bps")), _num(wan.get("tx_bps")),
    )
    _track_outage(wan_up, gw)

    db.put_snapshot("gateway", {**gw, "hostname": data.get("hostname"), "uptime_s": data.get("uptime_s"),
                                "agent_version": data.get("version")})
    db.put_snapshot("interfaces", interfaces)
    for kind in ("vpn", "dns", "threats"):
        if kind in data:
            db.put_snapshot(kind, data[kind])
    _merge_clients(clients, now)
    db.kv_set("agent_last_seen", str(now))
    return {"ok": True}


def _track_outage(wan_up: int | None, gw: dict) -> None:
    if wan_up is None:
        return
    open_outage = db.one("SELECT id, start_ts FROM outages WHERE end_ts IS NULL ORDER BY id DESC LIMIT 1")
    if not wan_up and not open_outage:
        db.run("INSERT INTO outages(start_ts) VALUES (?)", db.now())
        add_event("gateway", "critical", "Internet down", gw)
    elif wan_up and open_outage:
        db.run("UPDATE outages SET end_ts=? WHERE id=?", db.now(), open_outage["id"])
        minutes = (db.now() - open_outage["start_ts"]) // 60
        add_event("gateway", "warning", f"Internet back after {minutes} min", gw)


def _merge_clients(clients: list, now: int) -> None:
    seen = set()
    with db.tx() as conn:
        for c in clients[:5000]:
            mac = str(c["mac"]).lower()[:17]
            seen.add(mac)
            existing = conn.execute("SELECT mac FROM clients WHERE mac=?", (mac,)).fetchone()
            online = 1 if c.get("online") else 0
            # The agent reports how long an online device has been quiet (from its ARP entry), so
            # "last seen" means last heard from, not "still in the ARP table".
            idle = c.get("idle_s")
            heard = now - min(int(idle), 3600) if isinstance(idle, (int, float)) and idle >= 0 else now
            # What the firewall itself enforces right now; the Clients page badges come from here.
            limit = c.get("limit") if isinstance(c.get("limit"), dict) else None
            limit_json = json.dumps({k: _num(limit.get(k)) for k in ("down_mbps", "up_mbps", "until")}) if limit else None
            live = (_num(c.get("down_bps")) if online else None, _num(c.get("up_bps")) if online else None,
                    1 if c.get("paused") is True else 0, limit_json)
            if existing:
                conn.execute(
                    "UPDATE clients SET ip=COALESCE(?, ip), hostname=COALESCE(NULLIF(?, ''), hostname), "
                    "segment=COALESCE(?, segment), online=?, last_seen=CASE WHEN ? THEN ? ELSE last_seen END, "
                    "down_bps=?, up_bps=?, paused=?, speed_limit=? WHERE mac=?",
                    (c.get("ip"), c.get("hostname") or "", c.get("segment"), online, online, heard, *live, mac),
                )
            else:
                conn.execute(
                    "INSERT INTO clients(mac, ip, hostname, vendor, segment, online, first_seen, last_seen, "
                    "down_bps, up_bps, paused, speed_limit) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (mac, c.get("ip"), c.get("hostname") or "", oui.vendor(mac), c.get("segment"), online, now, heard, *live),
                )
                if db.kv_get("clients_baselined"):
                    conn.execute(
                        "INSERT INTO events(ts, source, severity, title, detail) VALUES (?, 'clients', 'warning', ?, ?)",
                        (now, f"New device: {c.get('hostname') or mac} on {c.get('segment') or '?'}", json.dumps(c)),
                    )
                    notify.send(f"New device on {c.get('segment') or '?'}: {c.get('hostname') or '(no name)'} {mac} {c.get('ip') or ''}")
        if seen:
            marks = ",".join("?" * len(seen))
            conn.execute(f"UPDATE clients SET online=0, down_bps=NULL, up_bps=NULL WHERE mac NOT IN ({marks})", tuple(seen))
        else:
            conn.execute("UPDATE clients SET online=0, down_bps=NULL, up_bps=NULL")
    # The first report is the baseline; only devices after that count as "new".
    if clients and not db.kv_get("clients_baselined"):
        db.kv_set("clients_baselined", "1")


@ingest_app.post("/v1/events")
async def events(request: Request):
    data = await _json(request)
    items = [e for e in data.get("events") or [] if isinstance(e, dict)][:1000]
    for e in items:
        add_event(e.get("source", "agent"), e.get("severity", "info"), e.get("title", "(no title)"), e.get("detail"), e.get("ts"))
    return {"ok": True, "stored": len(items)}


@ingest_app.get("/v1/actions")
def pending_actions():
    """Approved, unexpired actions with their signed approvals. The agent verifies each one itself."""
    rows = db.q("SELECT id, payload, assertion FROM actions WHERE status='approved' AND expires_at >= ?", db.now())
    for row in rows:
        db.run("UPDATE actions SET status='fetched' WHERE id=? AND status='approved'", row["id"])
    return {"actions": [{"id": r["id"], "payload": r["payload"], "assertion": json.loads(r["assertion"])} for r in rows]}


@ingest_app.post("/v1/actions/{action_id}/result")
async def action_result(action_id: str, request: Request):
    data = await _json(request)
    ok = bool(data.get("ok"))
    cur = db.run(
        "UPDATE actions SET status=?, result=?, finished_at=? WHERE id=? AND status='fetched'",
        "done" if ok else "failed", json.dumps(data)[:8000], db.now(), action_id,
    )
    if cur.rowcount != 1:
        raise HTTPException(409, "unknown or already finished action")
    row = db.one("SELECT type, params, created_by FROM actions WHERE id=?", action_id)
    add_event("actions", "info" if ok else "warning",
              f"Action {row['type']} {'done' if ok else 'FAILED'} ({row['created_by']})", data)
    notify.send(f"Firewall {'ran' if ok else 'REFUSED/FAILED'} {row['type']} {row['params']}: {str(data.get('message', ''))[:200]}")
    return {"ok": True}


@ingest_app.get("/v1/health")
def health():
    return {"ok": True, "rp_id": settings.rp_id}
