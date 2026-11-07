"""Local security regressions; no production credentials, scans or firewall actions."""
import asyncio
import dataclasses
import hashlib
import json
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request
from starlette.responses import Response

from app import actions, auth, db, security, wa
from app.main import app
from app.requests import BROWSER_BODY_LIMIT, BrowserBodyLimit
from softkey import SoftKey, b64u
from test_dashboard import sign_in

ORIGIN = 'http://testserver'


@pytest.fixture
def browser(monkeypatch):
    monkeypatch.setattr(auth, 'limiter', security.RateLimiter())
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client


def operator(client):
    csrf = sign_in(client)
    token = client.cookies.get(security.settings.session_cookie)
    row = db.one('SELECT * FROM sessions WHERE id_hash=?', hashlib.sha256(token.encode()).hexdigest())
    db.run("UPDATE users SET role='operator' WHERE id=?", row['user_id'])
    return csrf, db.one('SELECT * FROM users WHERE id=?', row['user_id'])


@pytest.mark.parametrize('raw', [
    b'{', b'[]', b'null', b'"text"', b'123', b'{"credential":null}',
    b'{"credential":[]}', b'{"credential":{},"name":[]}', b'{"next":{}}',
    b'{"credential":{},"extra":NaN}', b'\xff',
    ('{"credential":'+('['*1500)+'0'+(']'*1500)+'}').encode(),
])
def test_malformed_webauthn_envelopes_are_400_not_server_errors(browser, raw):
    csrf, user = operator(browser)
    aid = actions.create('block_ip', {'cidr':'1.2.3.4','minutes':1}, user['username'])
    for endpoint in ('/auth/passkey/finish', '/security/stepup/passkey/finish',
                     '/security/passkey/register/finish', f'/actions/{aid}/approve'):
        response = browser.post(endpoint, content=raw,
            headers={'Origin':ORIGIN,'X-CSRF-Token':csrf,'Content-Type':'application/json'})
        assert response.status_code == 400, (endpoint, response.status_code)
        assert 'Traceback' not in response.text
    assert db.one('SELECT status FROM actions WHERE id=?', aid)['status']=='pending_approval'


def test_invalid_envelope_does_not_consume_a_valid_challenge(browser):
    options = browser.post('/auth/passkey/begin', headers={'Origin':ORIGIN})
    assert options.status_code == 200
    token = browser.cookies.get(security.settings.challenge_cookie)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    assert browser.post('/auth/passkey/finish',json=[],headers={'Origin':ORIGIN}).status_code == 400
    assert db.one('SELECT 1 FROM challenges WHERE token_hash=?', token_hash)


@pytest.mark.parametrize('content_type', ['application/json','application/x-www-form-urlencoded','multipart/form-data; boundary=security-test'])
def test_large_browser_bodies_are_rejected_before_parsing(browser, content_type):
    response=browser.post('/login/password',content=b'x'*(BROWSER_BODY_LIMIT+1),
                          headers={'Origin':ORIGIN,'Content-Type':content_type})
    assert response.status_code == 413
    assert response.headers['cache-control']=='no-store'
    assert response.headers['x-content-type-options']=='nosniff'


def test_body_budget_counts_chunked_data_and_preserves_sse():
    async def scenario():
        invoked=[]; sent=[]; read=[]
        async def application(scope,receive,send):
            invoked.append(scope['method'])
            if scope['method']=='POST':
                message=await receive()
                assert len(message['body'])==BROWSER_BODY_LIMIT
            await send({'type':'http.response.start','status':200,'headers':[]})
            await send({'type':'http.response.body','body':b'ok'})
        middleware=BrowserBodyLimit(application)
        async def send(message): sent.append(message)
        scope={'type':'http','method':'POST','path':'/login/password','headers':[]}
        chunks=iter([{'type':'http.request','body':b'x'*BROWSER_BODY_LIMIT,'more_body':True},
                     {'type':'http.request','body':b'x','more_body':True},
                     {'type':'http.request','body':b'should not read','more_body':False}])
        async def receive():
            read.append(True); return next(chunks)
        await middleware(scope,receive,send)
        assert not invoked and len(read)==2 and sent[0]['status']==413
        sent.clear()
        async def exact(): return {'type':'http.request','body':b'x'*BROWSER_BODY_LIMIT,'more_body':False}
        await middleware(scope,exact,send)
        assert invoked==['POST'] and sent[0]['status']==200
        async def never_receive(): pytest.fail('SSE waited for a request body')
        await middleware({**scope,'method':'GET','path':'/api/live/stream'},never_receive,send)
        assert invoked==['POST','GET']
    asyncio.run(scenario())


@pytest.mark.parametrize('length,status', [(b'-1',400),(b'bad',400),(str(BROWSER_BODY_LIMIT+1).encode(),413)])
def test_body_budget_checks_declared_length_without_reading(length,status):
    async def scenario():
        sent=[]
        async def forbidden(*args): pytest.fail('Oversized or invalid request reached body parser')
        async def send(message): sent.append(message)
        scope={'type':'http','method':'POST','path':'/login/password','headers':[(b'content-length',length)]}
        await BrowserBodyLimit(forbidden)(scope,forbidden,send)
        assert sent[0]['status']==status
    asyncio.run(scenario())


def test_body_disconnect_never_invokes_control_handler():
    async def scenario():
        async def forbidden(*args): pytest.fail('Disconnected request reached control handler')
        async def receive(): return {'type':'http.disconnect'}
        await BrowserBodyLimit(forbidden)({'type':'http','method':'POST','path':'/logout','headers':[]},receive,forbidden)
    asyncio.run(scenario())


def test_trusted_waf_shipper_retains_its_separate_batch_budget():
    body=json.dumps({'hits':[],'batch_id':secrets.token_hex(16),'padding':'x'*BROWSER_BODY_LIMIT})
    with TestClient(app,base_url=ORIGIN,client=('10.99.0.1',5000)) as proxy:
        headers={'Authorization':'Bearer shiptoken','Content-Type':'application/json'}
        assert proxy.post('/internal/waf-hits',content=body,headers=headers).status_code==200
        assert proxy.post('/internal/waf-hits',content=b'x'*(2*1024*1024+1),headers=headers).status_code==413
        headers['Authorization']='Bearer wrong'
        assert proxy.post('/internal/waf-hits',content=body,headers=headers).status_code==403


def test_blocked_ip_cannot_allocate_unbounded_username_records(monkeypatch):
    monkeypatch.setattr(security.time,'monotonic',lambda:1000)
    limiter=security.RateLimiter(per_minute=1,max_keys=4)
    assert limiter.check('ip:a','user:known')==0
    limiter.failure('ip:a','user:known')
    for n in range(1000): assert limiter.check('ip:a',f'user:{n}')>0
    assert len(limiter._touched)==2
    assert len(limiter._attempts)<=2 and len(limiter._failures)<=2 and len(limiter._locked_until)<=2


def test_rate_limiter_capacity_preserves_locks_and_reclaims_idle_records(monkeypatch):
    now=[1000]
    monkeypatch.setattr(security.time,'monotonic',lambda:now[0])
    limiter=security.RateLimiter(max_keys=2,free_failures=0,base_lock=120,max_lock=120)
    assert limiter.check('ip:a','user:a')==0
    limiter.failure('ip:a','user:a')
    assert limiter.check('ip:b')>0 and len(limiter._touched)==2
    now[0]+=70
    assert limiter.check('ip:a')>0
    now[0]+=limiter.retention+1
    assert limiter.check('ip:b')==0 and set(limiter._touched)=={'ip:b'}


def test_relogin_rotates_and_revokes_only_the_presented_session(browser):
    _,user=operator(browser)
    old=browser.cookies.get(security.settings.session_cookie)
    def request(token=None):
        headers=[] if token is None else [(b'cookie',f'{security.settings.session_cookie}={token}'.encode())]
        return Request({'type':'http','method':'POST','path':'/login/password','headers':headers,'client':('testclient',1)})
    other=security.create_session(request(),user)
    new=security.create_session(request(old),user)
    assert old!=new and security.load_session(request(old)) is None
    assert security.load_session(request(new)) and security.load_session(request(other))


def test_concurrent_passkey_counter_update_accepts_only_one(browser,monkeypatch):
    _,user=operator(browser)
    key=SoftKey()
    options,challenge=wa.registration_options(user)
    wa.finish_registration(user,key.create(json.loads(options),ORIGIN),challenge,'concurrency test')
    original_count=key.count
    challenges=[secrets.token_bytes(32),secrets.token_bytes(32)]
    credentials=[]
    for challenge in challenges:
        key.count=original_count
        credentials.append(key.get(b64u(challenge),'testserver',ORIGIN))
    verify=wa.verify_authentication_response
    barrier=threading.Barrier(2)
    def synchronized(**kwargs):
        result=verify(**kwargs)
        barrier.wait(timeout=10)
        return result
    monkeypatch.setattr(wa,'verify_authentication_response',synchronized)
    def finish(index):
        try:
            wa.finish_authentication(credentials[index],challenges[index])
            return 'accepted'
        except wa.WebAuthnError:
            return 'rejected'
        finally:
            db.connect().close()
            del db._local.conn
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(finish,range(2)))
    assert sorted(results)==['accepted','rejected']
    assert db.one('SELECT sign_count FROM credentials WHERE id=?',b64u(key.cred_id))['sign_count']==original_count+1


def test_zero_counter_authenticators_remain_supported(browser):
    _,user=operator(browser)
    key=SoftKey(counter=False)
    options,challenge=wa.registration_options(user)
    wa.finish_registration(user,key.create(json.loads(options),ORIGIN),challenge,'zero counter test')
    for _ in range(2):
        challenge=secrets.token_bytes(32)
        verified,_=wa.finish_authentication(key.get(b64u(challenge),'testserver',ORIGIN),challenge)
        assert verified['id']==user['id']
    assert db.one('SELECT sign_count FROM credentials WHERE id=?',b64u(key.cred_id))['sign_count']==0


def test_production_cookie_flags_without_exposing_values(monkeypatch):
    settings=dataclasses.replace(security.settings,dev=False,cookie_domain='example.test')
    monkeypatch.setattr(security,'settings',settings)
    response=Response()
    security.set_cookie(response,settings.session_cookie,'test-only-value',60)
    cookie=response.headers['set-cookie'].lower()
    assert 'httponly' in cookie and 'secure' in cookie and 'samesite=lax' in cookie and 'domain=example.test' in cookie
    response=Response()
    security.set_cookie(response,settings.challenge_cookie,'test-only-value',60)
    cookie=response.headers['set-cookie'].lower()
    assert 'samesite=strict' in cookie and 'domain=' not in cookie
