"""Exercise real archive/state/rollback logic with disposable files and fake Docker."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile

import pytest

SPEC=importlib.util.spec_from_file_location('app_update',Path(__file__).resolve().parents[1]/'app-update.py')
module=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)
RELEASE='opngate-20261108T010203Z-1234abcd'


@pytest.fixture
def deployment(tmp_path,monkeypatch):
    root=tmp_path/'gateway'
    compose=root/'deploy/services';compose.mkdir(parents=True)
    (compose/'.env').write_text('PRIVATE=retained\n')
    (compose/'docker-compose.yml').write_text('private compose retained\n')
    (root/'portal/app').mkdir(parents=True)
    (root/'portal/app/main.py').write_text('old application\n')
    release=root/'releases'/RELEASE;release.mkdir(parents=True)
    events=[]
    def fake_run(self,*args,input=None,logfile=None):
        args=tuple(map(str,args));events.append((args,input))
        if args[1]=='compose':
            command=args[6:]
            if command[0]=='ps':return 'container-'+command[-1]+'\n'
            if command[0]=='exec':return '{"version":"test","live_age":0.5,"shipper_age":10}\n'
        elif args[1]=='inspect':
            if '.Config.Image' in args[3]:
                return 'sha256:previous|gw-services-'+args[-1].removeprefix('container-')+'|0|'+args[-1]+'\n'
            return 'true|0|'+args[-1]+'|sha256:built\n'
        elif args[1:3]==('image','inspect'):
            return 'sha256:built\n'
        return ''
    monkeypatch.setattr(module.Update,'run',fake_run)
    payload={'portal/app/main.py':b'new application\n','portal/Dockerfile':b'FROM example\n',
             'portal/requirements.txt':b'example==1\n','docs/new.md':b'new documentation\n'}
    def archive(files=None,special=None):
        path=release/'source.tgz'
        with tarfile.open(path,'w:gz') as package:
            directory=tarfile.TarInfo('portal/app');directory.type=tarfile.DIRTYPE
            package.addfile(directory)
            for name,body in (files or payload).items():
                info=tarfile.TarInfo(name);info.size=len(body);info.mode=0o644
                package.addfile(info,io.BytesIO(body))
            if special:package.addfile(special)
        return hashlib.sha256(path.read_bytes()).hexdigest()
    update=module.Update(root,RELEASE,'services',archive())
    return root,update,events,archive


def test_prepare_build_and_rollback_restore_files_and_images_without_database_restore(deployment):
    root,update,events,_=deployment
    env=(root/'deploy/services/.env').read_bytes()
    policy=(root/'deploy/services/docker-compose.yml').read_bytes()
    update.prepare()
    assert (root/'portal/app/main.py').read_text()=='old application\n'
    assert (update.directory/'source-before.tgz').exists()
    assert any('source.backup(target)' in (program or '') for _,program in events)
    update.build()
    assert (root/'portal/app/main.py').read_text()=='new application\n'
    assert (root/'docs/new.md').exists()
    update.activate();update.verify();update.rollback()
    assert (root/'portal/app/main.py').read_text()=='old application\n'
    assert not (root/'docs/new.md').exists()
    assert (root/'deploy/services/.env').read_bytes()==env
    assert (root/'deploy/services/docker-compose.yml').read_bytes()==policy
    assert not update.lock.exists()
    assert update.load()['status']=='rolled_back'
    assert any('opngate-rollback-services-portal:'+RELEASE in args for args,_ in events)
    # The only database program creates a snapshot; rollback never opens/restores it.
    assert sum('source.backup(target)' in (program or '') for _,program in events)==1


@pytest.mark.parametrize('bad',['../../outside','portal/app/../../deploy/services/.env',
    'deploy/services/.env','portal/app/.env','portal/app/key.pem','portal/app//alias.py'])
def test_unexpected_or_private_archive_paths_are_refused_before_lock_or_mutation(deployment,bad):
    root,update,_,archive=deployment
    update.checksum=archive({bad:b'bad'})
    with pytest.raises(ValueError):update.prepare()
    assert not update.lock.exists()
    assert (root/'portal/app/main.py').read_text()=='old application\n'


def test_archive_symlinks_are_not_followed(deployment):
    _,update,_,archive=deployment
    link=tarfile.TarInfo('portal/app/link.py');link.type=tarfile.SYMTYPE;link.linkname='../../deploy/services/.env'
    update.checksum=archive(special=link)
    with pytest.raises(ValueError,match='links'):update.prepare()
    assert not update.lock.exists()


def test_checksum_mismatch_never_allocates_lock(deployment):
    _,update,_,_=deployment
    update.checksum='0'*64
    with pytest.raises(ValueError,match='checksum'):update.prepare()
    assert not update.lock.exists()


def test_busy_host_lock_is_never_broken(deployment):
    _,update,_,_=deployment
    update.lock.mkdir();(update.lock/'owner').write_text('another deployment')
    with pytest.raises(FileExistsError):update.prepare()
    update.rollback()  # no state from this run: leave the other lock alone
    assert (update.lock/'owner').read_text()=='another deployment'


def test_activation_requires_verified_build(deployment):
    _,update,events,_=deployment
    update.prepare()
    with pytest.raises(RuntimeError,match='Build verification'):update.activate()
    assert not any('up' in args for args,_ in events)
    update.rollback()


def test_completed_release_can_roll_back_once_but_not_over_newer_release(deployment):
    root,update,_,_=deployment
    update.prepare();update.build();update.activate();update.finish()
    assert not update.lock.exists()
    assert json.loads(update.marker.read_text())['release']==RELEASE
    module.write_json(update.marker,{'release':'newer deployment'})
    with pytest.raises(RuntimeError,match='newer'):update.rollback()
    assert (root/'portal/app/main.py').read_text()=='new application\n'
    module.write_json(update.marker,{'release':RELEASE})
    update.rollback();update.rollback()
    assert (root/'portal/app/main.py').read_text()=='old application\n'
    assert not update.marker.exists()


def test_failed_build_restores_source_without_restarting_old_containers(deployment,monkeypatch):
    root,update,events,_=deployment
    update.prepare()
    original=module.Update.run
    def fail_build(self,*args,**kwargs):
        if 'build' in args:raise RuntimeError('simulated build failure')
        return original(self,*args,**kwargs)
    monkeypatch.setattr(module.Update,'run',fail_build)
    with pytest.raises(RuntimeError,match='simulated'):update.build()
    update.rollback()
    assert (root/'portal/app/main.py').read_text()=='old application\n'
    assert not any('up' in args for args,_ in events)


def test_readiness_refuses_old_running_image(deployment,monkeypatch):
    _,update,_,_=deployment
    update.prepare();update.build();update.activate()
    original=module.Update.run
    def old_image(self,*args,**kwargs):
        output=original(self,*args,**kwargs)
        if '.State.Running' in ' '.join(map(str,args)):
            return output.replace('sha256:built','sha256:previous')
        return output
    monkeypatch.setattr(module.Update,'run',old_image)
    monkeypatch.setattr(module.time,'sleep',lambda _:None)
    with pytest.raises(RuntimeError,match='30 checks'):update.verify()
    update.rollback()


def test_readiness_requires_activation(deployment):
    _,update,_,_=deployment
    update.prepare();update.build()
    with pytest.raises(RuntimeError,match='Activate'):update.verify()
    update.rollback()


def test_relative_application_directory_is_refused():
    with pytest.raises(ValueError,match='absolute'):
        module.Update('relative/path',RELEASE,'services')
