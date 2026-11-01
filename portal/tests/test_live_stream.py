import asyncio
import json

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from app import db, live
from app.config import settings
from app.ingest import ingest_app
from app.main import app
from app.security import load_session
from test_dashboard import sign_in
from test_agent_collect import PF_STATES
import fw_agent


INTERFACES = [{'name':'igc0','segment':'WAN','rx_bps':1000,'tx_bps':200},
              {'name':'igc3','segment':'MGMT','rx_bps':200,'tx_bps':1000}]
CLIENT = {'mac':'00:11:22:33:44:55','ip':'192.0.2.20','interface':'igc3','segment':'MGMT',
          'down_bps':8000,'up_bps':400}


def test_fast_ingest_uses_last_value_file_without_database_writes(monkeypatch):
    with TestClient(ingest_app) as agent:
        before = db.one('SELECT COUNT(*) FROM samples')[0]
        monkeypatch.setattr(db, 'put_snapshot', lambda *a: pytest.fail('fast ingest wrote SQLite snapshot'))
        monkeypatch.setattr(db, 'run', lambda *a: pytest.fail('fast ingest wrote database'))
        for value in (1234, 5678):
            response = agent.post('/v1/live', json={'interfaces':INTERFACES, 'clients':[{**CLIENT,'down_bps':value}]})
            assert response.status_code == 200
        assert live.read_frame()['clients'][0]['down_bps'] == 5678
        assert db.one('SELECT COUNT(*) FROM samples')[0] == before
        assert list(settings.live_dir.iterdir()) == [settings.live_dir / 'current.json']


@pytest.mark.parametrize('clients', [
    [CLIENT, CLIENT], [{**CLIENT,'mac':'bad'}], [{**CLIENT,'ip':'not-an-ip'}],
    [{**CLIENT,'interface':[]}], [{**CLIENT,'interface':'igc0','segment':'WAN'}],
])
def test_bad_device_frames_do_not_replace_good_frame(clients):
    with TestClient(ingest_app) as agent:
        assert agent.post('/v1/live',json={'interfaces':INTERFACES,'clients':[CLIENT]}).status_code == 200
        previous = live.read_frame()
        assert agent.post('/v1/live',json={'interfaces':INTERFACES,'clients':clients}).status_code == 400
        assert live.read_frame() == previous


def test_shared_hub_coalesces_slow_consumers_and_bounds_connections():
    async def scenario():
        hub = live.LiveHub()
        slow = hub.subscribe('session')
        for n in range(100):
            hub.broadcast({'revision':str(n)})
        assert slow.qsize() == 1 and (await slow.get())['revision'] == '99'
        others = [hub.subscribe('session') for _ in range(3)]
        with pytest.raises(ValueError):
            hub.subscribe('session')
        for queue in [slow, *others]: hub.unsubscribe(queue)
        assert not hub.listeners
    asyncio.run(scenario())


def test_sse_auth_headers_and_idle_timeout_are_preserved(monkeypatch):
    async def finite(request, session, hub, queue):
        try:
            yield 'event: telemetry\ndata: {}\n\n'
        finally:
            hub.unsubscribe(queue)
    with TestClient(app) as browser:
        assert browser.get('/api/live/stream', headers={'Accept':'text/event-stream'}).status_code == 401
        sign_in(browser)
        before = db.one('SELECT last_seen FROM sessions ORDER BY created_at DESC LIMIT 1')[0]
        now = db.now()
        monkeypatch.setattr(db,'now',lambda: now+10)
        monkeypatch.setattr(live,'events',finite)
        response = browser.get('/api/live/stream')
        assert response.status_code == 200
        assert response.headers['content-type'].startswith('text/event-stream')
        assert response.headers['cache-control'] == 'no-store, no-transform'
        assert response.headers['x-accel-buffering'] == 'no'
        assert db.one('SELECT last_seen FROM sessions ORDER BY created_at DESC LIMIT 1')[0] == before
        assert not app.state.live_hub.listeners


def test_stream_stops_when_session_is_revoked_and_releases_slot(monkeypatch):
    with TestClient(app) as browser:
        sign_in(browser)
        token = browser.cookies.get(settings.session_cookie)
        request = Request({'type':'http','method':'GET','path':'/api/live/stream',
                           'headers':[(b'cookie',f'{settings.session_cookie}={token}'.encode())]})
        session = load_session(request)
        monkeypatch.setattr(live,'SESSION_CHECK_INTERVAL',0)
        async def scenario():
            hub = live.LiveHub()
            hub.latest = {'revision':'initial','interfaces':[]}
            queue = hub.subscribe(session.id_hash)
            stream = live.events(request,session,hub,queue)
            assert (await anext(stream)).startswith('retry:')
            assert 'event: telemetry' in await anext(stream)
            db.run('DELETE FROM sessions WHERE id_hash=?',session.id_hash)
            queue.put_nowait({'revision':'next'})
            assert 'event: auth' in await anext(stream)
            await stream.aclose()
            assert not hub.listeners
        asyncio.run(scenario())


def test_device_parser_keeps_final_state_and_deduplicates_inside_copies(monkeypatch):
    inside = PF_STATES.split('all tcp 198.51.100.20')[0]
    assert len(list(fw_agent.ClientRates.parse(inside.format(a=1,b=2)))) == 1
    cfg = {'segments':{'igb0':'WAN','igb1':'LAN'}}
    counters = iter([(1000,50000),(3000,1050000)])
    def sample(command, **kwargs):
        a,b = next(counters)
        return 0, 2 * inside.format(a=a,b=b), ''
    clock = iter([100.,101.])
    monkeypatch.setattr(fw_agent,'run',sample)
    monkeypatch.setattr(fw_agent.time,'monotonic',lambda:next(clock))
    rates = fw_agent.ClientRates()
    assert rates.sample(cfg) == {}
    assert rates.sample(cfg)['192.168.20.180'] == (8000000,16000)


def test_fast_device_collection_caches_neighbors_and_reports_failure_as_unknown(monkeypatch):
    now = [100.]
    arp_calls = []
    monkeypatch.setattr(fw_agent.time,'monotonic',lambda:now[0])
    def arp(**kwargs):
        arp_calls.append(kwargs)
        return [{'mac-address':CLIENT['mac'],'ip-address':'192.168.20.180','interface':'igb1'}]
    monkeypatch.setattr(fw_agent,'arp_table',arp)
    outputs = iter([(0,PF_STATES.format(a=100,b=200),''),(0,PF_STATES.format(a=200,b=1200),''),(1,'','failed')])
    monkeypatch.setattr(fw_agent,'run',lambda *a,**kw:next(outputs))
    monkeypatch.setattr(fw_agent,'_leases',lambda *a:pytest.fail('fast collector read leases'))
    collector = fw_agent.LiveClients()
    cfg = {'segments':{'igb0':'WAN','igb1':'LAN'}}
    assert collector.sample(cfg) is None
    now[0] += 1
    rows = collector.sample(cfg)
    assert rows[0]['down_bps'] == 8000 and rows[0]['up_bps'] == 800
    now[0] += 1
    assert collector.sample(cfg) is None
    assert len(arp_calls) == 1


def test_current_file_size_and_malformed_content_are_bounded():
    settings.live_dir.mkdir(parents=True,exist_ok=True)
    path = settings.live_dir / 'current.json'
    path.write_bytes(b'x' * (live.MAX_FRAME_BYTES+1))
    assert live.read_frame() is None
    path.write_text('{broken')
    assert live.read_frame() is None


def test_fresh_fast_frame_is_not_replaced_by_newer_slow_average(monkeypatch):
    db.init()
    now = db.now()
    monkeypatch.setattr(live.time,'time',lambda:now + 0.8)
    live.publish(INTERFACES,[CLIENT])
    db.put_snapshot('interfaces',[{**INTERFACES[0],'rx_bps':99999999}])
    db.run("UPDATE snapshots SET ts=? WHERE kind='interfaces'",now+1)
    current = live.snapshot()
    assert current['source'] == 'live' and current['wan']['rx_bps'] == 1000
