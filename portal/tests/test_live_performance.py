import dataclasses
import json
import threading

import pytest
from fastapi.testclient import TestClient

from app import crowdsec, db, live, metrics
from app.config import settings
from app.ingest import ingest_app
from app.main import app
from test_dashboard import sign_in
import fw_agent


@pytest.fixture
def clients():
    db.init()
    for table in ("snapshots", "samples"):
        db.run(f"DELETE FROM {table}")
    with TestClient(app) as browser, TestClient(ingest_app) as agent:
        yield browser, agent


def test_live_is_authenticated_revision_based_and_does_not_query_history(clients, monkeypatch):
    browser, agent = clients
    assert browser.get('/api/live', headers={'Accept': 'application/json'}).status_code == 401
    sign_in(browser)
    now = db.now()
    before = db.one("SELECT last_seen FROM sessions ORDER BY created_at DESC LIMIT 1")[0]
    monkeypatch.setattr(db, 'now', lambda: now + 10)
    monkeypatch.setattr(live.time, 'time', lambda: now + 10)
    payload = {'interfaces': [{'name': 'igc0', 'segment': 'WAN', 'rx_bps': 9000000, 'tx_bps': 200000}]}
    assert agent.post('/v1/live', json=payload).status_code == 200
    monkeypatch.setattr(metrics, 'window', lambda *a: pytest.fail('current feed queried history'))
    headers = {'X-Auto-Refresh': '1', 'Accept': 'application/json'}
    response = browser.get('/api/live', headers=headers)
    data = response.json()
    assert data['wan']['rx_bps'] == 9000000 and data['source'] == 'live'
    assert not data['stale'] and response.headers['cache-control'] == 'no-store'
    assert db.one('SELECT COUNT(*) FROM samples')[0] == 0
    assert db.one("SELECT last_seen FROM sessions ORDER BY created_at DESC LIMIT 1")[0] == before
    headers['X-Live-Revision'] = data['revision']
    assert browser.get('/api/live', headers=headers).status_code == 204
    monkeypatch.setattr(db, 'now', lambda: now + 40)
    monkeypatch.setattr(live.time, 'time', lambda: now + 40)
    stale = browser.get('/api/live', headers=headers)
    assert stale.status_code == 200 and stale.json()['stale']
    browser.cookies.clear()
    assert browser.get('/api/live', headers=headers).status_code == 401


def test_live_ingest_validation_and_legacy_fallback(clients):
    browser, agent = clients
    assert agent.post('/v1/live', json={'interfaces': []}).status_code == 400
    row = {'name': 'eth0', 'segment': 'WAN', 'rx_bps': -1, 'tx_bps': 'nan'}
    assert agent.post('/v1/live', json={'interfaces': [row, row]}).status_code == 400
    assert agent.post('/v1/live', json={'interfaces': [row]}).status_code == 200
    sign_in(browser)
    assert browser.get('/api/live').json()['wan'] == {'rx_bps': None, 'tx_bps': None}
    db.run("DELETE FROM snapshots")
    (settings.live_dir / 'current.json').unlink()
    db.put_snapshot('interfaces', [{'name': 'eth0', 'segment': 'WAN', 'rx_bps': 12, 'tx_bps': 34}])
    assert browser.get('/api/live').json()['source'] == 'telemetry'


def test_crowdsec_slow_refresh_never_blocks_page_reads_and_failure_keeps_data(monkeypatch):
    monkeypatch.setattr(crowdsec, 'settings', dataclasses.replace(settings, crowdsec_lapi='http://test', crowdsec_key='test'))
    monkeypatch.setattr(crowdsec, '_cache', {'at': 0, 'data': None, 'updated_at': None, 'error': None})
    entered, release = threading.Event(), threading.Event()
    def slow_fetch():
        entered.set()
        release.wait(3)
        return [{'origin': 'crowdsec', 'value': '192.0.2.1', 'duration': '1h'}]
    monkeypatch.setattr(crowdsec, '_fetch', slow_fetch)
    worker = threading.Thread(target=crowdsec.refresh_once)
    worker.start()
    try:
        assert entered.wait(1)
        assert crowdsec.decisions()['loading']  # Completes while API is still blocked.
    finally:
        release.set()
        worker.join(2)
    assert crowdsec.decisions()['local'] == 1
    monkeypatch.setattr(crowdsec, '_fetch', lambda: (_ for _ in ()).throw(OSError('test failure')))
    crowdsec.refresh_once()
    cached = crowdsec.decisions()
    assert cached['stale'] and cached['error'] and cached['local'] == 1


def test_lightweight_collection_only_reads_counters_and_skips_initial_baseline(monkeypatch):
    calls = []
    counters = iter([100, 200])
    def run(command, **kw):
        calls.append(command)
        value = next(counters)
        return 0, json.dumps({'statistics': {'interface': [{'name': 'eth0', 'network': '<Link#1>', 'received-bytes': value, 'sent-bytes': value}]}}), ''
    monkeypatch.setattr(fw_agent, 'run', run)
    clock = iter([10., 12.])
    monkeypatch.setattr(fw_agent.time, 'monotonic', lambda: next(clock))
    rates = fw_agent.Rates()
    assert fw_agent.collect_live({'segments': {'eth0': 'WAN'}}, rates) is None
    assert fw_agent.collect_live({'segments': {'eth0': 'WAN'}}, rates)['interfaces'][0]['rx_bps'] == 400
    assert all(command[0] == 'netstat' for command in calls)
