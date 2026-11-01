"""Authenticated dashboards and bounded telemetry exports."""
import csv
import io
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response

from . import actions, db, metrics
from .config import settings
from .security import Session, audit, check_csrf, require_user
from .templating import render

router = APIRouter()
RANGES = metrics.RANGES


def _window(request: Request) -> tuple:
    key = request.query_params.get("range", "24h")
    key = key if key in RANGES else "24h"
    return key, RANGES[key]


def _like(term: str) -> str:
    """Treat user search text literally, including SQL LIKE wildcards."""
    return "%" + term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _flow_data(gw: dict, latest) -> tuple:
    """On an inside interface the firewall's transmit is the devices' download."""
    _, interfaces = db.get_snapshot("interfaces", [])
    wan, segments, grouped = {}, [], defaultdict(list)
    for client in db.q(
        "SELECT segment, COALESCE(NULLIF(hostname, ''), vendor, ip, mac) AS label FROM clients "
        "WHERE online=1 ORDER BY last_seen DESC"
    ):
        grouped[client["segment"]].append(client["label"])
    for interface in interfaces:
        if (interface.get("segment") or "").upper() == "WAN":
            wan = interface
            continue
        names = grouped[interface.get("segment")]
        segments.append({
            "name": interface.get("segment") or interface.get("name"), "iface": interface.get("name"),
            "down_bps": interface.get("tx_bps"), "up_bps": interface.get("rx_bps"),
            "online": len(names), "names": names[:3],
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
    flow_gw, flow_wan, flow_segments = _flow_data(gw, latest)
    flow_gw["state"] = wan_state
    flow_gw["last_seen"] = last_seen
    return render(
        request, "overview.html", session=session, range_key=key, ranges=list(RANGES), gw=gw, latest=latest,
        metrics=data, flow_gw=flow_gw, flow_wan=flow_wan, flow_segments=flow_segments, refresh=15,
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
    return render(request, "clients.html", session=session, rows=rows[:500], segments=segments, segment=segment,
                  show=show, q=term, limited=len(rows) > 500, now=db.now(), refresh=30,
                  paused={key[1]: aid for aid, key in actions.active_effects().items() if key[0] == "mac"})


@router.get("/traffic")
def traffic(request: Request, session: Session = Depends(require_user)):
    key, _ = _window(request)
    data = metrics.window(key)
    ts, interfaces = db.get_snapshot("interfaces", [])
    return render(
        request, "traffic.html", session=session, range_key=key, ranges=list(RANGES), interfaces=interfaces,
        updated=ts, metrics=data, rx=[p["rx_bps"] for p in data["points"]],
        tx=[p["tx_bps"] for p in data["points"]], refresh=15,
    )


@router.get("/threats")
def threats(request: Request, session: Session = Depends(require_user)):
    ts, data = db.get_snapshot("threats", {})
    now = db.now()
    since = now - 86400
    ids = db.q("SELECT * FROM events WHERE source='suricata' AND ts >= ? ORDER BY ts DESC LIMIT 100", since)
    ids_count = db.one("SELECT COUNT(*) AS n FROM events WHERE source='suricata' AND ts >= ?", since)["n"]
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
