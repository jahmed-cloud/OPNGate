"""Security events, WAF evidence, alerts and audit."""
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response, StreamingResponse
from .. import actions, crowdsec, db, devices, identity, live, metrics
from ..config import settings
from ..security import Session, audit, check_csrf, require_operator, require_user
from ..templating import flow_layout, render
import json
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
from .common import _json, _like

router = APIRouter()
_IDS_TAIL = re.compile(r"\s+\S+\s+->\s+\S+$")

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
        origin = urlsplit(identity.current().origin)
        if (referer.scheme, referer.netloc) == (origin.scheme, origin.netloc) and referer.path == "/alerts":
            target += "?" + referer.query if referer.query else ""
    except ValueError:
        pass
    return RedirectResponse(target, 303)


@router.get("/audit")
def audit_page(request: Request, session: Session = Depends(require_user)):
    rows = db.q("SELECT * FROM audit ORDER BY id DESC LIMIT 500")
    return render(request, "audit.html", session=session, rows=rows)
