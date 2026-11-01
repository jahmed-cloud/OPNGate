"""Metrics correctness, bounded reads, dashboard filters, and export guards."""
import csv
import hashlib
import io
import secrets
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import db, metrics
from app.config import settings
from app.main import app


@pytest.fixture(autouse=True)
def clean_telemetry():
    db.init()
    for table in ("samples", "snapshots", "clients", "events", "outages", "waf_hits", "kv"):
        db.run(f"DELETE FROM {table}")
    yield


@pytest.fixture
def client():
    with TestClient(app, base_url="http://testserver") as test_client:
        yield test_client


def sign_in(client):
    """Install a real persisted viewer session; do not bypass route dependencies."""
    username = "metrics-" + secrets.token_hex(8)
    now = db.now()
    user_id = db.run(
        "INSERT INTO users(username,password_hash,role,webauthn_user_id,created_at) VALUES (?,?,'viewer',?,?)",
        username, "!", secrets.token_bytes(32), now,
    ).lastrowid
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    db.run(
        "INSERT INTO sessions(id_hash,user_id,csrf,created_at,last_seen,last_mfa) VALUES (?,?,?,?,?,?)",
        hashlib.sha256(token.encode()).hexdigest(), user_id, csrf, now, now, now,
    )
    client.cookies.set(settings.session_cookie, token)
    return csrf


def sample(ts, wan=1, latency=10, loss=0, rx=1000, tx=500):
    db.run("INSERT INTO samples(ts,wan_up,latency_ms,loss_pct,rx_bps,tx_bps) VALUES (?,?,?,?,?,?)",
           ts, wan, latency, loss, rx, tx)


def test_month_aggregates_in_sql_to_at_most_240_rows(monkeypatch):
    now = db.now()
    with db.tx() as conn:
        conn.executemany(
            "INSERT INTO samples(ts,wan_up,latency_ms,loss_pct,rx_bps,tx_bps) VALUES (?,1,10,0,2000,1000)",
            ((now - i * 30,) for i in range(86_400)),
        )
    received = []
    query = db.q

    def bounded_query(sql, *args):
        rows = query(sql, *args)
        received.append(len(rows))
        return rows

    monkeypatch.setattr(db, "q", bounded_query)
    result = metrics.window("30d", now)
    assert received and max(received) <= metrics.MAX_POINTS
    assert len(result["points"]) <= metrics.MAX_POINTS
    assert result["summary"]["sample_count"] == 86_400
    assert result["summary"]["latency_avg_ms"] == 10
    assert result["summary"]["availability_pct"] == 100
    assert result["summary"]["coverage_pct"] == 100


def test_missing_buckets_unknown_wan_and_weighted_summary():
    now = db.now()
    sample(now - 1000, wan=None, latency=0, loss=None, rx=0, tx=0)
    sample(now - 999, wan=1, latency=20, loss=0, rx=200, tx=100)
    sample(now - 10, wan=0, latency=100, loss=80, rx=400, tx=200)
    sample(now - 3600, wan=1, latency=9999)  # Outside the exclusive lower bound.
    sample(now + 1, wan=1, latency=9999)     # Future data is not charted.
    result = metrics.window("1h", now)
    summary = result["summary"]
    assert summary["sample_count"] == 3
    assert summary["known_samples"] == 2
    assert summary["latency_avg_ms"] == 40
    assert summary["latency_max_ms"] == 100
    assert summary["loss_avg_pct"] == 40
    assert summary["rx_peak_bps"] == 400
    assert summary["tx_peak_bps"] == 200
    assert summary["availability_pct"] == 50
    assert 0 < summary["coverage_pct"] < 100
    assert any(point["sample_count"] == 0 and point["latency_ms"] is None for point in result["points"])
    assert result["end"] - result["start"] == 3600
    assert all(point["ts"] % result["bucket_seconds"] == 0 for point in result["points"])


def test_unknown_is_not_available_and_empty_has_no_fake_zeros():
    now = db.now()
    empty = metrics.window("1h", now)
    assert empty["summary"]["availability_pct"] is None
    assert empty["summary"]["latency_avg_ms"] is None
    assert empty["summary"]["coverage_pct"] == 0
    sample(now, wan=None, latency=None, loss=None, rx=None, tx=None)
    unknown = metrics.window("1h", now)
    assert unknown["summary"]["availability_pct"] is None
    assert unknown["summary"]["known_samples"] == 0
    assert all(point["wan_up"] is None for point in unknown["points"])


@pytest.mark.parametrize("key,seconds", list(metrics.RANGES.items()))
def test_ranges_keep_bounded_regular_timestamps(key, seconds):
    now = db.now()
    result = metrics.window(key, now)
    assert result["end"] - result["start"] == seconds
    assert 0 < len(result["points"]) <= 240
    ticks = [point["ts"] for point in result["points"]]
    assert all(right - left == result["bucket_seconds"] for left, right in zip(ticks, ticks[1:]))
    assert metrics.window("not-a-range", now)["range_key"] == "24h"


def test_metrics_and_csv_require_session_and_have_bounded_numeric_export(client):
    for path in ("/api/metrics", "/exports/metrics.csv"):
        response = client.get(path, headers={"Accept": "application/json"}, follow_redirects=False)
        assert response.status_code == 401
    sign_in(client)
    sample(db.now(), wan=1, latency=12, rx=1024, tx=512)
    response = client.get("/api/metrics?range=1h")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    data = response.json()
    assert data["summary"]["sample_count"] == 1
    exported = client.get("/exports/metrics.csv?range=1h")
    assert exported.status_code == 200
    assert "attachment" in exported.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(exported.text)))
    assert len(rows) <= 240
    assert sum(int(row["sample_count"]) for row in rows) == 1
    actual = next(row for row in rows if row["sample_count"] == "1")
    assert actual["latency_ms"] == "12.0"
    assert actual["bucket_start_utc"].endswith("+00:00")
    assert "csrf" not in exported.text and "username" not in exported.text


def test_overview_unknown_stale_and_fresh_state(client):
    sign_in(client)
    assert client.get("/").context["wan_state"] == "unknown"
    db.put_snapshot("gateway", {"online": True})
    db.kv_set("agent_last_seen", str(db.now() - 180))
    assert client.get("/").context["wan_state"] == "stale"
    db.kv_set("agent_last_seen", str(db.now()))
    assert client.get("/").context["wan_state"] == "online"


def test_client_search_treats_wildcards_literally_and_limits_rows(client):
    sign_in(client)
    now = db.now()
    with db.tx() as conn:
        conn.executemany(
            "INSERT INTO clients(mac,hostname,segment,online,first_seen,last_seen) VALUES (?,?,'LAN',1,?,?)",
            ((f"00:00:00:00:{i // 256:02x}:{i % 256:02x}", f"host-{i}", now, now) for i in range(502)),
        )
    db.run("UPDATE clients SET hostname='printer_100%' WHERE mac='00:00:00:00:00:00'")
    response = client.get("/clients?q=%25")
    assert len(response.context["rows"]) == 1
    assert response.context["rows"][0]["hostname"] == "printer_100%"
    bounded = client.get("/clients")
    assert len(bounded.context["rows"]) == 500
    assert bounded.context["limited"] is True
    assert len(client.get("/clients?q=host-501&segment=LAN").context["rows"]) == 1


def test_alert_filters_and_ack_redirect_stays_local(client):
    csrf = sign_in(client)
    now = db.now()
    for source, severity, title in (("suricata", "critical", "IDS test"), ("agent", "warning", "Agent stale")):
        db.run("INSERT INTO events(ts,source,severity,title) VALUES (?,?,?,?)", now, source, severity, title)
    filtered = client.get("/alerts?severity=critical&source=suricata")
    assert len(filtered.context["rows"]) == 1
    event_id = filtered.context["rows"][0]["id"]
    response = client.post(f"/alerts/{event_id}/ack", data={"csrf": csrf},
                           headers={"Origin": "http://testserver", "Referer": "https://evil.example/path"},
                           follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/alerts"
    other = db.one("SELECT id FROM events WHERE acked_at IS NULL")["id"]
    response = client.post(f"/alerts/{other}/ack", data={"csrf": csrf},
                           headers={"Origin": "http://testserver", "Referer": "http://testserver/alerts?show=all"},
                           follow_redirects=False)
    assert response.headers["location"] == "/alerts?show=all"


def test_waf_series_is_seven_utc_days_and_legacy_counts_stay_separate(client):
    sign_in(client)
    today = datetime.fromtimestamp(db.now(), timezone.utc).date()
    for day, kind, count in ((today, "waf_blocked", 3), (today, "waf_detected", 2),
                             (today, "blocked", 99), (today - timedelta(days=7), "waf_blocked", 40),
                             (today + timedelta(days=1), "waf_detected", 50)):
        db.run("INSERT INTO waf_hits(day,host,kind,count) VALUES (?,'app.example',?,?)", day.isoformat(), kind, count)
    page = client.get("/threats")
    assert len(page.context["waf_days"]) == 7
    assert page.context["waf_totals"] == {"blocked": 3, "detected": 2}
    assert page.context["legacy_waf_count"] == 99
    assert page.context["waf_days"][-1]["day"] == today.isoformat()
    assert all(point["ts"] % 86400 == 0 for point in page.context["waf_days"])


def test_live_refresh_is_authenticated_fragment_and_filters_are_visible(client):
    sign_in(client)
    full = client.get("/")
    assert 'id="refresh-now"' in full.text
    fragment = client.get("/", headers={"X-Auto-Refresh": "1"})
    assert fragment.headers["x-portal-fragment"] == "1"
    assert "<!doctype" not in fragment.text and 'id="main"' not in fragment.text
    assert "Gateway overview" in fragment.text
    assert 'name="q"' in client.get("/clients").text
    alerts = client.get("/alerts").text
    assert 'name="severity"' in alerts and 'name="source"' in alerts
    client.cookies.clear()
    assert client.get("/", headers={"X-Auto-Refresh": "1", "Accept": "application/json"}).status_code == 401


def test_chart_has_utc_times_and_breaks_across_missing_data():
    from app.templating import time_chart, uptime_bar
    points = [{"ts": 1700000000 + n * 60, "latency_ms": v} for n, v in enumerate([10, 20, None, 30, 40])]
    chart = str(time_chart(points, "latency_ms", "Latency", "ms"))
    assert chart.count('<polyline class="chart-line"') == 2
    assert "UTC" in chart and "2023-11-14" in chart
    assert 'class="chart-label"' in chart
    bar = str(uptime_bar([(0.5, "up"), (0.5, "nodata")], 1700000000, 1700000240))
    assert "UTC" in bar and "No WAN observation" in bar
