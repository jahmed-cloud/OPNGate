import dataclasses, hashlib, json, secrets
from urllib.parse import urlsplit

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from app import actions, db, identity, security, wa
from app.config import settings
from app.main import app
from softkey import SoftKey, b64u


@pytest.fixture
def moved(monkeypatch):
    from app import config, templating
    value=dataclasses.replace(settings, rp_id='opngate.example.test', origin='https://opngate.example.test', legacy_origin='https://waf.example.test')
    for module in (config, identity, templating):
        monkeypatch.setattr(module,'settings',value)
    return value


def request(host, origin):
    return Request({'type':'http','scheme':'https','path':'/','server':(host,443),'headers':[(b'host',host.encode()),(b'origin',origin.encode())]})


def test_only_configured_host_selects_legacy(moved):
    assert identity.for_request(request('waf.example.test',moved.legacy_origin)).rp_id=='waf.example.test'
    assert identity.for_request(request('evil.example.test',moved.legacy_origin)).rp_id==moved.rp_id
    assert identity.for_request(request('waf.example.test.evil.test',moved.legacy_origin)).rp_id==moved.rp_id
    with identity.use(identity.legacy()):
        assert security.same_origin(request('waf.example.test',moved.legacy_origin))
        assert not security.same_origin(request('waf.example.test',moved.origin))
    assert identity.current().origin==moved.origin


def test_old_credentials_are_backfilled_and_scoped(moved):
    db.init()
    user=db.run("INSERT INTO users(username,password_hash,role,webauthn_user_id,created_at) VALUES (?,?,'operator',?,?)",'migrate-'+secrets.token_hex(8),'!',secrets.token_bytes(32),db.now()).lastrowid
    row=db.one('SELECT * FROM users WHERE id=?',user)
    old,new=SoftKey(),SoftKey()
    for selected,key in ((identity.legacy(),old),(identity.primary(),new)):
        with identity.use(selected):
            opts,challenge=wa.registration_options(row)
            wa.finish_registration(row,key.create(json.loads(opts),selected.origin),challenge,'test')
    for selected,key,other in ((identity.legacy(),old,new),(identity.primary(),new,old)):
        with identity.use(selected):
            opts,challenge=wa.authentication_options(user_id=user)
            assert [c['id'] for c in json.loads(opts)['allowCredentials']]==[b64u(key.cred_id)]
            assert wa.finish_authentication(key.get(b64u(challenge),selected.rp_id,selected.origin),challenge)[0]['id']==user
            with pytest.raises(wa.WebAuthnError):
                wa.finish_authentication(other.get(b64u(challenge),selected.rp_id,selected.origin),challenge)
    db.run('UPDATE credentials SET rp_id=NULL WHERE id=?',b64u(old.cred_id))
    db.init()
    assert db.one('SELECT rp_id FROM credentials WHERE id=?',b64u(old.cred_id))['rp_id']==identity.legacy().rp_id


def test_http_identity_and_cross_origin_login(moved):
    with TestClient(app,base_url=moved.origin) as client:
        new=client.post('/auth/passkey/begin',json={},headers={'Origin':moved.origin})
        assert new.status_code==200 and new.json()['rpId']==moved.rp_id
        old=client.post(moved.legacy_origin+'/auth/passkey/begin',json={},headers={'Origin':moved.legacy_origin})
        assert old.status_code==200 and old.json()['rpId']=='waf.example.test'
        bad=client.post('/auth/passkey/begin',json={},headers={'Origin':moved.legacy_origin})
        assert bad.status_code==403
        assert 'existing passkey' in client.get('/login').text


def test_actions_cannot_be_approved_at_other_identity(moved):
    db.init()
    with identity.use(identity.legacy()):
        aid=actions.create('block_ip',{'cidr':'203.0.113.7','minutes':1},'migration-test')
    row=db.one('SELECT * FROM actions WHERE id=?',aid)
    with pytest.raises(Exception) as err:
        actions._check_identity(row)
    assert err.value.status_code==409
    with identity.use(identity.legacy()):
        actions._check_identity(row)


def test_agent_migration_requires_exact_configured_pair(tmp_path):
    import time
    import fw_agent
    from cryptography.hazmat.primitives import serialization
    from test_e2e import _signed_item
    key=SoftKey()
    pem=key.key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    trusted={b64u(key.cred_id):{'alg':key.alg,'public_key_pem':pem,'user':'operator'}}
    old={'rp_id':'waf.example.test','origin':'https://waf.example.test'}
    new={'rp_id':'opngate.example.test','origin':'https://opngate.example.test'}
    cfg={'actions':{**old,'allowed':['block_ip'],'migration_portals':[new]}}
    state=fw_agent.State(str(tmp_path/'state.json'))
    def attempt(pair,signed_pair=None):
        now=int(time.time())
        payload={'v':1,'id':secrets.token_hex(8),'type':'block_ip','params':{'cidr':'1.2.3.4','minutes':1},'created_by':'operator','created_at':now,'expires_at':now+60,**pair}
        signed_pair=signed_pair or pair
        item=_signed_item(key,payload,rp=signed_pair['rp_id'],origin=signed_pair['origin'])
        return fw_agent.verify_action(item,trusted,cfg,state)
    assert attempt(old)['origin']==old['origin']
    assert attempt(new)['origin']==new['origin']
    with pytest.raises(fw_agent.ActionRejected): attempt({**old,'origin':new['origin']})
    with pytest.raises(fw_agent.ActionRejected): attempt(new,old)
    cfg['actions']['migration_portals']=[]
    with pytest.raises(fw_agent.ActionRejected): attempt(new)
