from fastapi.testclient import TestClient
import pytest
from app import db, live, metrics
from app.main import app
from app.console import inventory
from test_dashboard import sign_in

@pytest.fixture
def browser():
    db.init()
    for table in ('snapshots','clients','kv'):
        db.run('DELETE FROM '+table)
    db.put_snapshot('interfaces',[{'name':'igc0','segment':'WAN','rx_bps':8000,'tx_bps':1000},{'name':'igc1','segment':'LAN','rx_bps':1000,'tx_bps':8000}])
    db.put_snapshot('gateway',{'online':True})
    db.kv_set('agent_last_seen',str(db.now()))
    now=db.now()
    db.run("INSERT INTO clients(mac,segment,online,first_seen,last_seen) VALUES ('02:00:00:00:00:01','LAN',1,?,?)",now,now)
    with TestClient(app) as browser:
        yield browser


def test_network_workspace_authentication_and_no_history(browser,monkeypatch):
    assert browser.get('/api/console',headers={'Accept':'application/json'}).status_code==401
    assert browser.get('/networks',follow_redirects=False).status_code==303
    sign_in(browser)
    monkeypatch.setattr(metrics,'window',lambda *a:pytest.fail('network inventory queried history'))
    page=browser.get('/networks')
    assert page.status_code==200 and '1 devices online' in page.text
    assert 'data-live-interface="igc1"' in page.text
    assert 'data-live-rate="tx_bps"' in page.text
    result=browser.get('/api/console')
    assert result.headers['cache-control']=='no-store'
    wan,lan=result.json()['networks']
    assert (wan['down_bps'],lan['down_bps'],lan['online_clients'])==(8000,8000,1)
    assert not {'secret','public_key','password','token'} & set(result.json())


def test_stale_network_rates_are_unknown(browser,monkeypatch):
    start=db.now()
    monkeypatch.setattr(db,'now',lambda:start+121)
    data=inventory.snapshot()
    assert data['agent_online'] is False
    assert all(n['stale'] and n['down_bps'] is None and n['up_bps'] is None for n in data['networks'])


def test_live_network_binding_cannot_cross_segments(browser,monkeypatch):
    frame=live.snapshot()
    frame.update(reported_at=db.now(),stale=False,interfaces=[{'name':'igc1','segment':'OTHER','rx_bps':999,'tx_bps':999}])
    monkeypatch.setattr(live,'snapshot',lambda:frame)
    lan=inventory.snapshot()['networks'][1]
    assert lan['name']=='LAN' and lan['down_bps']==8000


def test_blocking_help_is_authenticated_and_explains_scope(browser):
    assert browser.get('/help',follow_redirects=False).status_code==303
    sign_in(browser)
    page=browser.get('/help')
    assert page.status_code==200
    assert 'viewer access' in page.text
    for text in ('Pause internet','Block sites','Block an external IP','Approve with security key','Allow all sites again','WAF blocking is separate'):
        assert text in page.text
    assert 'id="approve-action"' not in page.text
    assert 'Blocking guide' in browser.get('/clients').text
