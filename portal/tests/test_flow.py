import pytest
from fastapi.testclient import TestClient

from app import db, metrics, views
from app.main import app
from app.config import settings
from test_dashboard import sign_in


@pytest.fixture
def browser():
    db.init()
    for table in ('snapshots', 'clients', 'kv'):
        db.run(f'DELETE FROM {table}')
    db.put_snapshot('gateway', {'online': True, 'latency_ms': 9})
    db.put_snapshot('interfaces', [
        {'name': 'igc0', 'segment': 'WAN', 'rx_bps': 1000, 'tx_bps': 500},
        {'name': 'igc1', 'segment': 'LAN', 'rx_bps': 100, 'tx_bps': 200},
    ])
    db.kv_set('agent_last_seen', str(db.now()))
    for mac, name, rate in [('00:11:22:33:44:02', 'Beta', 5000), ('00:11:22:33:44:01', 'Alpha', 100)]:
        db.run('INSERT INTO clients(mac,hostname,segment,online,first_seen,last_seen,down_bps) VALUES (?,?,?,1,?,?,?)',
               mac, name, 'LAN', db.now(), db.now(), rate)
    with TestClient(app) as browser:
        yield browser


def test_map_endpoint_auth_and_history_isolation(browser, monkeypatch):
    assert browser.get('/api/flow', headers={'Accept': 'application/json'}).status_code == 401
    sign_in(browser)
    monkeypatch.setattr(metrics, 'window', lambda *a: pytest.fail('map queried historical samples'))
    response = browser.get('/api/flow', headers={'X-Auto-Refresh': '1'})
    assert response.status_code == 200 and response.headers['cache-control'] == 'no-store'
    assert 'id="flow-panel"' in response.text and '<!doctype' not in response.text
    assert 'data-flow-interface="igc0" data-flow-rate="rx_bps"' in response.text
    assert 'data-flow-interface="igc1" data-flow-rate="tx_bps"' in response.text


def test_collapsed_map_only_loads_counts_and_open_map_is_stable(browser, monkeypatch):
    sign_in(browser)
    queries, original = [], db.q
    def record(sql, *args):
        queries.append(sql)
        return original(sql, *args)
    monkeypatch.setattr(db, 'q', record)
    collapsed = browser.get('/api/flow')
    assert collapsed.context['flow_segments'][0]['online'] == 2
    assert collapsed.context['flow_segments'][0]['devices'] == []
    assert not any('SELECT * FROM clients' in sql for sql in queries)
    browser.cookies.set('flow_open', 'LAN')
    first = browser.get('/api/flow')
    order = [d['mac'] for d in first.context['flow_segments'][0]['devices']]
    assert order == sorted(order)
    db.run('UPDATE clients SET down_bps=9999999 WHERE hostname=?', 'Alpha')
    second = browser.get('/api/flow')
    assert [d['mac'] for d in second.context['flow_segments'][0]['devices']] == order
    assert 'data-refresh-section="device-00:11:22:33:44:01"' in second.text


def test_history_refresh_leaves_client_owned_flow_untouched(browser, monkeypatch):
    sign_in(browser)
    monkeypatch.setattr(views, '_flow_data', lambda *a: pytest.fail('history rebuilt the flow map'))
    response = browser.get('/', headers={'X-Auto-Refresh': '1'})
    assert response.status_code == 200
    assert 'data-client-owned data-refresh-section="overview-8" id="flow-panel"' in response.text
    assert 'class="flowmap"' not in response.text


H = {'Origin': settings.origin}


def promote(csrf):
    db.run("UPDATE users SET role='operator' WHERE id IN (SELECT user_id FROM sessions WHERE csrf=?)", csrf)


def test_operator_names_device_and_picks_icon(browser):
    csrf = sign_in(browser)
    form = {'csrf': csrf, 'mac': '00:11:22:33:44:01', 'name': 'Kids  tablet\x07', 'icon': 'tablet', 'next': '/'}
    assert browser.post('/clients/label', data=form, headers=H, follow_redirects=False).status_code == 403  # viewers cannot
    promote(csrf)
    assert browser.post('/clients/label', data={**form, 'csrf': 'wrong'}, headers=H, follow_redirects=False).status_code in (400, 403)
    r = browser.post('/clients/label', data=form, headers=H, follow_redirects=False)
    assert r.status_code == 303 and r.headers['location'] == '/'
    assert dict(db.one('SELECT name, icon FROM device_labels WHERE mac=?', '00:11:22:33:44:01')) == {'name': 'Kids tablet', 'icon': 'tablet'}
    browser.cookies.set('flow_open', 'LAN')
    page = browser.get('/api/flow').text
    assert 'Kids tablet' in page and 'Alpha' not in page.split('<svg')[1].split('</svg>')[0].replace('Alpha ·', '')
    clients = browser.get('/clients?q=kids').text
    assert 'Kids tablet' in clients and 'Beta' not in clients
    # The agent's next report leaves the name alone; clearing both puts the network's name back.
    db.run("UPDATE clients SET hostname='alpha-2' WHERE mac=?", '00:11:22:33:44:01')
    assert 'Kids tablet' in browser.get('/api/flow').text
    browser.post('/clients/label', data={**form, 'name': '', 'icon': 'bogus'}, headers=H, follow_redirects=False)
    assert db.one('SELECT 1 FROM device_labels WHERE mac=?', '00:11:22:33:44:01') is None
    assert 'alpha-2' in browser.get('/api/flow').text


def test_busy_network_uses_compact_rows_for_120_devices(browser):
    promote(sign_in(browser))
    for i in range(120):
        db.run('INSERT INTO clients(mac,hostname,segment,online,first_seen,last_seen,down_bps,up_bps) VALUES (?,?,?,1,?,?,?,?)',
               f'00:aa:00:00:{i // 256:02x}:{i % 256:02x}', f'device-{i:03d}-with-a-long-hostname', 'LAN', db.now(), db.now(), i * 1000, 10)
    browser.cookies.set('flow_open', 'LAN')
    r = browser.get('/api/flow')
    segment = r.context['flow_segments'][0]
    assert len(segment['devices']) == 122 and segment['compact'] and segment['more'] == 0
    height = r.context['flow_height']
    assert height < 122 * 30 + 200  # compact rows, not 50-unit cards
    assert r.text.count('class="node device compact') == 122 and 'class="lane trunk"' in r.text
    assert r.text.count('class="flow-ctrl compact"') == 122
    tops = [d['top_pct'] for d in segment['devices']]
    assert tops == sorted(tops) and all(0 <= t < 100 for t in tops)
