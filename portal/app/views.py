"""Authenticated dashboards and bounded telemetry exports."""
import csv
import io
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote, urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response

from . import actions, crowdsec, db, metrics
from .config import settings
from .security import Session, audit, check_csrf, require_user
from .templating import flow_layout, render

router = APIRouter()
RANGES = metrics.RANGES


def _window(request: Request) -> tuple:
    key = request.query_params.get("range", "24h")
    key = key if key in RANGES else "24h"
    return key, RANGES[key]


def _like(term: str) -> str:
    """Treat user search text literally, including SQL LIKE wildcards."""
    return "%" + term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


DEVICE_ACTIONS = ("pause_client", "resume_client", "limit_client", "unlimit_client", "block_domains", "unblock_domains")
NETWORK_ACTIONS = ("block_network", "unblock_network")
FLOW_DEVICES_PER_SEGMENT = 8


def _client(row) -> dict:
    c = dict(row)
    c["limit"] = _json(c.get("speed_limit")) or None
    c["domains"] = _json(c.get("blocked_domains")) or None
    return c


def _device_controls() -> dict:
    """Waiting and in-force device actions, for the status badges and Manage menus (_device.html)."""
    effects = actions.active_effects()
    pending = {}
    marks = ",".join("?" * len(DEVICE_ACTIONS))
    for row in db.q(f"SELECT id, type, params FROM actions WHERE status IN ('pending_approval','approved','fetched') "
                    f"AND type IN ({marks}) AND expires_at >= ?", *DEVICE_ACTIONS, db.now()):
        pending.setdefault(_json(row["params"]).get("mac"), (row["id"], row["type"]))
    by_kind = lambda kind: {key[1]: aid for aid, key in effects.items() if key[0] == kind}  # noqa: E731
    return {
        "pending": pending, "paused": by_kind("mac"), "limits": by_kind("limit"), "domain_blocks": by_kind("domains"),
        "labels_short": {"pause_client": "Pause waiting", "resume_client": "Resume waiting", "limit_client": "Limit waiting",
                         "unlimit_client": "Unlimit waiting", "block_domains": "Site block waiting",
                         "unblock_domains": "Unblock waiting"},
    }


def _flow_open(request: Request) -> set:
    """Networks whose devices the flow map shows, from the flow_open cookie portal.js sets when a network is
    clicked ("*" = all). Collapsed networks only cost one row, which keeps the overview light."""
    raw = unquote(request.cookies.get("flow_open", ""))
    return {"*"} if raw == "*" else {name for name in raw.split(",") if name}


def _flow_data(gw: dict, latest, open_segments=frozenset({"*"})) -> tuple:
    """On an inside interface the firewall's transmit is the devices' download. The busiest online devices of
    each open segment get their own node; the rest are counted."""
    _, interfaces = db.get_snapshot("interfaces", [])
    wan, segments, grouped = {}, [], defaultdict(list)
    for row in db.q("SELECT * FROM clients WHERE online=1 "
                    "ORDER BY COALESCE(down_bps, 0) + COALESCE(up_bps, 0) DESC, hostname"):
        c = _client(row)
        c["label"] = c.get("hostname") or c.get("vendor") or c.get("ip") or c["mac"]
        grouped[c["segment"]].append(c)
    for interface in interfaces:
        if (interface.get("segment") or "").upper() == "WAN":
            wan = interface
            continue
        devices = grouped[interface.get("segment")]
        name = interface.get("segment") or interface.get("name")
        is_open = "*" in open_segments or name in open_segments
        segments.append({
            "name": name, "iface": interface.get("name"), "open": is_open,
            "down_bps": interface.get("tx_bps"), "up_bps": interface.get("rx_bps"),
            "online": len(devices), "devices": devices[:FLOW_DEVICES_PER_SEGMENT] if is_open else [],
            "more": max(0, len(devices) - FLOW_DEVICES_PER_SEGMENT) if is_open else 0,
        })
    return {**gw, "latency_ms": latest["latency_ms"] if latest else None}, wan, segments


@router.get("/")
def overview(request: Request, session: Session = Depends(require_user)):
    key, _ = _window(request)
    now = db.now()
    data = metrics.window(key, now)
    gw_ts, gw = db.get_snapshot("gateway", {})
    last_seen = int(db.kv_get("agent_last_seen", "0"))
    agent_online = bool(last_seen and 0 <= now - last_seen < 120)
    wan_state = "unknown" if gw.get("online") is None else "online" if gw["online"] else "offline"
    if last_seen and not agent_online:
        wan_state = "stale"
    segments = [((min(data["end"], p["ts"] + data["bucket_seconds"]) - max(data["start"], p["ts"])) / (data["end"] - data["start"]), "down" if p["wan_up"] == 0 else
                 "up" if p["wan_up"] == 1 else "nodata") for p in data["points"]]
    outages = db.q(
        "SELECT * FROM outages WHERE start_ts <= ? AND COALESCE(end_ts, ?) >= ? "
        "ORDER BY start_ts DESC LIMIT 50", now, now, data["start"],
    )
    latest = db.one("SELECT * FROM samples WHERE ts >= ? AND ts <= ? ORDER BY ts DESC LIMIT 1", data["start"], now)
    flow_gw, flow_wan, flow_segments = _flow_data(gw, latest, _flow_open(request))
    flow_gw["state"] = wan_state
    flow_gw["last_seen"] = last_seen
    flow_height = flow_layout(flow_segments)
    return render(
        request, "overview.html", session=session, range_key=key, ranges=list(RANGES), gw=gw, latest=latest,
        metrics=data, flow_gw=flow_gw, flow_wan=flow_wan, flow_segments=flow_segments, flow_height=flow_height,
        refresh=30, **_device_controls(),
        wan_state=wan_state, agent_online=agent_online, last_seen=last_seen, segments=segments,
        availability=data["summary"]["availability_pct"], outages=outages,
        latency=[p["latency_ms"] for p in data["points"]], loss=[p["loss_pct"] for p in data["points"]],
        open_alerts=db.one("SELECT COUNT(*) AS n FROM events WHERE acked_at IS NULL AND severity != 'info'")["n"],
        recent_alerts=db.q("SELECT * FROM events WHERE acked_at IS NULL ORDER BY ts DESC LIMIT 5"),
        clients_online=db.one("SELECT COUNT(*) AS n FROM clients WHERE online=1")["n"], now=now,
    )


@router.get("/api/metrics")
def metrics_api(request: Request, session: Session = Depends(require_user)):
    return metrics.window(_window(request)[0])


@router.get("/exports/metrics.csv")
def metrics_csv(request: Request, session: Session = Depends(require_user)):
    data = metrics.window(_window(request)[0])
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["bucket_start_utc", "bucket_seconds", "sample_count", "wan_up", "latency_ms",
                     "loss_pct", "rx_bps", "tx_bps"])
    for point in data["points"]:
        writer.writerow([
            datetime.fromtimestamp(point["ts"], timezone.utc).isoformat(), data["bucket_seconds"],
            point["sample_count"], point["wan_up"], *(point[field] for field in metrics.FIELDS),
        ])
    return Response(output.getvalue(), media_type="text/csv", headers={
        "Content-Disposition": f'attachment; filename="gateway-metrics-{data["range_key"]}.csv"',
    })


@router.get("/clients")
def clients(request: Request, session: Session = Depends(require_user)):
    segment = request.query_params.get("segment", "")[:100]
    show = "all" if request.query_params.get("show") == "all" else "online"
    term = request.query_params.get("q", "").strip()[:200]
    sql, args = "SELECT * FROM clients WHERE 1=1", []
    if segment:
        sql += " AND segment=?"
        args.append(segment)
    if show == "online":
        sql += " AND online=1"
    if term:
        sql += " AND (hostname LIKE ? ESCAPE '\\' OR ip LIKE ? ESCAPE '\\' OR mac LIKE ? ESCAPE '\\' OR vendor LIKE ? ESCAPE '\\')"
        args += [_like(term)] * 4
    rows = db.q(sql + " ORDER BY online DESC, segment, hostname, ip LIMIT 501", *args)
    segments = [r["segment"] for r in db.q("SELECT DISTINCT segment FROM clients WHERE segment IS NOT NULL ORDER BY segment")]
    return render(request, "clients.html", session=session, rows=[_client(r) for r in rows[:500]], segments=segments,
                  segment=segment, show=show, q=term, limited=len(rows) > 500, now=db.now(), refresh=30,
                  **_device_controls())


@router.get("/traffic")
def traffic(request: Request, session: Session = Depends(require_user)):
    key, _ = _window(request)
    now = db.now()
    data = metrics.window(key, now)
    ts, interfaces = db.get_snapshot("interfaces", [])
    rx = [p["rx_bps"] for p in data["points"] if isinstance(p.get("rx_bps"), (int, float))]
    tx = [p["tx_bps"] for p in data["points"] if isinstance(p.get("tx_bps"), (int, float))]
    latest = db.one("SELECT ts, rx_bps, tx_bps FROM samples WHERE ts <= ? ORDER BY ts DESC LIMIT 1", now)
    stats = {"rx_now": latest["rx_bps"] if latest else None, "tx_now": latest["tx_bps"] if latest else None,
             "updated": latest["ts"] if latest else None,
             "stale": latest is None or now - latest["ts"] >= 120,
             "rx_avg": sum(rx) / len(rx) if rx else None, "tx_avg": sum(tx) / len(tx) if tx else None}
    # From the devices' side: on the WAN, in is download; on an inside interface, out is the devices' download.
    ifaces = []
    for i in interfaces:
        wan = (i.get("segment") or "").upper() == "WAN"
        ifaces.append({**i, "wan": wan, "down": i.get("rx_bps") if wan else i.get("tx_bps"),
                       "up": i.get("tx_bps") if wan else i.get("rx_bps")})
    peak_iface = max([max(i["down"] or 0, i["up"] or 0) for i in ifaces] or [0])
    net_pending = {}
    if session.is_operator:
        for row in db.q("SELECT id, type, params FROM actions WHERE status IN ('pending_approval','approved','fetched') "
                        "AND type IN (?, ?) AND expires_at >= ?", *NETWORK_ACTIONS, db.now()):
            net_pending.setdefault(_json(row["params"]).get("segment"), (row["id"], row["type"]))
    net_blocks = {key[1]: aid for aid, key in actions.active_effects().items() if key[0] == "network"}
    return render(
        request, "traffic.html", session=session, range_key=key, ranges=list(RANGES), interfaces=ifaces,
        peak_iface=peak_iface, updated=ts, metrics=data, stats=stats, refresh=30,
        net_pending=net_pending, net_blocks=net_blocks,
    )


_IDS_TAIL = re.compile(r"\s+\S+\s+->\s+\S+$")


def _json(value) -> dict:
    try:
        data = json.loads(value) if value else {}
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _ids_details(since: int) -> tuple:
    """Suricata alerts with source, target and category pulled out of the stored eve record."""
    rows, sources, signatures = [], Counter(), Counter()
    for e in db.q("SELECT ts, severity, title, detail FROM events WHERE source='suricata' AND ts >= ? "
                  "ORDER BY ts DESC LIMIT 5000", since):
        d = _json(e["detail"])
        signature = _IDS_TAIL.sub("", e["title"])
        sources[d.get("src_ip") or "?"] += 1
        signatures[signature] += 1
        if len(rows) < 100:
            rows.append({"ts": e["ts"], "severity": e["severity"], "signature": signature,
                         "src": f'{d.get("src_ip", "?")}:{d.get("src_port", "")}'.rstrip(":"),
                         "dest_port": d.get("dest_port"), "proto": d.get("proto"),
                         "category": d.get("category"), "sid": d.get("signature_id"), "iface": d.get("in_iface")})
    return rows, sources.most_common(10), signatures.most_common(10)


def _waf_details(since: int) -> tuple:
    """Recent WAF events plus the rules, clients and paths that trip it most."""
    recent, rules, clients, paths = [], Counter(), Counter(), Counter()
    names = {}
    for e in db.q("SELECT * FROM waf_events WHERE ts >= ? ORDER BY ts DESC LIMIT 5000", since):
        try:
            matched = json.loads(e["rules"] or "[]")
        except ValueError:
            matched = []
        for r in matched:
            rules[r.get("id", "?")] += 1
            names.setdefault(r.get("id", "?"), r.get("msg") or "")
        clients[e["client_ip"] or "?"] += 1
        paths[(e["host"], e["path"] or "/")] += 1
        if len(recent) < 50:
            recent.append({**dict(e), "rules": matched})
    top_rules = [(rule_id, names.get(rule_id, ""), n) for rule_id, n in rules.most_common(10)]
    return recent, top_rules, clients.most_common(10), paths.most_common(10)


@router.get("/threats")
def threats(request: Request, session: Session = Depends(require_user)):
    ts, data = db.get_snapshot("threats", {})
    now = db.now()
    since = now - 86400
    ids, ids_sources, ids_signatures = _ids_details(since)
    ids_count = db.one("SELECT COUNT(*) AS n FROM events WHERE source='suricata' AND ts >= ?", since)["n"]
    waf_recent, waf_rules, waf_clients, waf_paths = _waf_details(now - 7 * 86400)
    engine, _, engine_ts = (db.kv_get("waf_engine") or "").partition("|")
    today = datetime.fromtimestamp(now, timezone.utc).date()
    start = today - timedelta(days=6)
    args = (start.isoformat(), today.isoformat())
    waf = db.q(
        "SELECT host, kind, SUM(count) AS n FROM waf_hits WHERE day BETWEEN ? AND ? "
        "AND kind IN ('waf_blocked','waf_detected') GROUP BY host, kind ORDER BY n DESC", *args,
    )
    waf_hosts, totals = {}, {"blocked": 0, "detected": 0}
    for row in waf:
        kind = row["kind"].removeprefix("waf_")
        waf_hosts.setdefault(row["host"], {"blocked": 0, "detected": 0})[kind] = row["n"]
        totals[kind] += row["n"]
    by_day = {row["day"]: row for row in db.q(
        "SELECT day, SUM(CASE WHEN kind='waf_blocked' THEN count ELSE 0 END) AS blocked, "
        "SUM(CASE WHEN kind='waf_detected' THEN count ELSE 0 END) AS detected FROM waf_hits "
        "WHERE day BETWEEN ? AND ? AND kind IN ('waf_blocked','waf_detected') GROUP BY day", *args,
    )}
    waf_days = []
    for offset in range(7):
        day = start + timedelta(days=offset)
        row = by_day.get(day.isoformat())
        waf_days.append({"day": day.isoformat(), "ts": int(datetime.combine(day, datetime.min.time(), timezone.utc).timestamp()),
                         "blocked": row["blocked"] if row else 0, "detected": row["detected"] if row else 0})
    legacy = db.one("SELECT COALESCE(SUM(count),0) AS n FROM waf_hits WHERE day BETWEEN ? AND ? "
                    "AND kind IN ('blocked','detected')", *args)["n"]
    by_country = sorted((data.get("crowdsec") or {}).get("by_country", {}).items(), key=lambda kv: -kv[1])[:20]
    by_scenario = sorted((data.get("crowdsec") or {}).get("by_scenario", {}).items(), key=lambda kv: -kv[1])[:20]
    return render(
        request, "threats.html", session=session, data=data, updated=ts, ids=ids, ids_count=ids_count,
        ids_sources=ids_sources, ids_signatures=ids_signatures, waf_recent=waf_recent, waf_rules=waf_rules,
        waf_clients=waf_clients, waf_paths=waf_paths, waf_engine=engine,
        waf_engine_ts=int(engine_ts) if engine_ts.isdigit() else 0, bans=crowdsec.decisions(),
        waf_hosts=waf_hosts, waf_days=waf_days, waf_totals=totals, legacy_waf_count=legacy,
        waf_last_seen=int(db.kv_get("waf_last_seen", "0")),
        waf_audit_available=db.kv_get("waf_audit_available", "unknown"), now=now,
        by_country=by_country, by_scenario=by_scenario, refresh=60,
    )


@router.get("/dns")
def dns(request: Request, session: Session = Depends(require_user)):
    ts, data = db.get_snapshot("dns", {})
    return render(request, "dns.html", session=session, data=data, updated=ts, refresh=60)


@router.get("/vpn")
def vpn(request: Request, session: Session = Depends(require_user)):
    ts, peers = db.get_snapshot("vpn", [])
    return render(request, "vpn.html", session=session, peers=peers, updated=ts, now=db.now(), refresh=30)


@router.get("/alerts")
def alerts(request: Request, session: Session = Depends(require_user)):
    term = request.query_params.get("q", "").strip()[:200]
    show = "all" if request.query_params.get("show") == "all" else "open"
    severities = ["info", "warning", "critical"]
    severity = request.query_params.get("severity", "")
    severity = severity if severity in severities else ""
    source = request.query_params.get("source", "")[:100]
    sql, args = "SELECT * FROM events WHERE 1=1", []
    if show == "open":
        sql += " AND acked_at IS NULL"
    if term:
        sql += " AND (title LIKE ? ESCAPE '\\' OR source LIKE ? ESCAPE '\\' OR detail LIKE ? ESCAPE '\\')"
        args += [_like(term)] * 3
    if severity:
        sql += " AND severity=?"
        args.append(severity)
    if source:
        sql += " AND source=?"
        args.append(source)
    rows = db.q(sql + " ORDER BY ts DESC LIMIT 300", *args)
    sources = [row["source"] for row in db.q("SELECT DISTINCT source FROM events ORDER BY source LIMIT 100")]
    return render(request, "alerts.html", session=session, rows=rows, q=term, show=show, severity=severity,
                  source=source, sources=sources, severities=severities, refresh=30)


@router.post("/alerts/{event_id}/ack")
async def ack(event_id: int, request: Request, session: Session = Depends(require_user)):
    await check_csrf(request, session)
    cur = db.run("UPDATE events SET acked_by=?, acked_at=? WHERE id=? AND acked_at IS NULL", session.username, db.now(), event_id)
    if not cur.rowcount:
        raise HTTPException(404)
    audit("alert_ack", True, request, session.username, str(event_id))
    # Preserve filters only on the local Alerts page, never a supplied foreign host.
    target = "/alerts"
    try:
        referer = urlsplit(request.headers.get("referer", ""))
        origin = urlsplit(settings.origin)
        if (referer.scheme, referer.netloc) == (origin.scheme, origin.netloc) and referer.path == "/alerts":
            target += "?" + referer.query if referer.query else ""
    except ValueError:
        pass
    return RedirectResponse(target, 303)


@router.get("/audit")
def audit_page(request: Request, session: Session = Depends(require_user)):
    rows = db.q("SELECT * FROM audit ORDER BY id DESC LIMIT 500")
    return render(request, "audit.html", session=session, rows=rows)


@router.get("/healthz")
def healthz():
    db.one("SELECT 1")
    return {"ok": True}
