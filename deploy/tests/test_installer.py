"""Exercise the real deployment entrypoint with fake remote hosts, never a network."""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BASH = Path('C:/Program Files/Git/bin/bash.exe') if os.name == 'nt' else Path('/bin/sh')


def shell_path(path):
    value=str(path.resolve()).replace('\\','/')
    return '/'+value[0].lower()+value[2:] if os.name=='nt' else value


@pytest.fixture
def setup(tmp_path):
    if not BASH.exists(): pytest.skip('POSIX shell unavailable')
    root=tmp_path/'checkout'; (root/'deploy').mkdir(parents=True)
    shutil.copyfile(ROOT/'deploy/deploy.sh',root/'deploy/deploy.sh')
    (root/'portal').mkdir(); (root/'portal/example.txt').write_text('source only')
    key=tmp_path/'key with spaces';key.write_text('fake test key')
    conf=root/'deploy/deploy.conf'
    conf.write_text("DOMAIN=example.test\nFIREWALL=root@firewall.example\nEDGE=root@edge.example\nEDGE_IP=192.0.2.21\nSERVICES=root@services.example\nSERVICES_IP=192.0.2.22\nADMIN_IP=192.0.2.10\nSSH_KEY='"+shell_path(key)+"'\n",encoding='utf-8',newline='\n')
    bins=tmp_path/'bin';bins.mkdir();log=tmp_path/'ssh.log'
    scripts={
      'ssh':'''#!/bin/sh
printf 'CALL ' >> "$SSH_LOG"
printf '[%s]' "$@" >> "$SSH_LOG"
printf '\\n' >> "$SSH_LOG"
case "$*" in *"$FAIL_SSH_TARGET"*) [ -z "$FAIL_SSH_TARGET" ] || exit 7 ;; esac
case "$*" in *'docker compose ps --status running -q'*) echo 3 ;; *'docker compose ps'*) echo 'portal: running' ;; esac
exit 0
''',
      'tar':'''#!/bin/sh
[ "${FAIL_ARCHIVE:-}" != yes ] || exit 9
while [ "$#" -gt 0 ]; do
 if [ "$1" = -cf ]; then shift; : > "$1"; break; fi
 shift
done
exit 0
''',
      'curl':'#!/bin/sh\nprintf 200\n',
    }
    for name,body in scripts.items():
        p=bins/name;p.write_text(body,encoding='utf-8',newline='\n');p.chmod(0o755)
    env={**os.environ,'PATH':shell_path(bins)+':'+('/usr/bin:/mingw64/bin:/bin' if os.name=='nt' else os.environ['PATH']),
         'OPNGATE_TEST_PATH':shell_path(bins)+':/usr/bin:/mingw64/bin:/bin','OPNGATE_TEST_BIN':shell_path(bins),'DEPLOY_CONF':shell_path(conf),'SSH_LOG':shell_path(log),'FAIL_SSH_TARGET':'','MSYS2_ARG_CONV_EXCL':'*'}
    def run(command,**extra):
        runner='PATH="$OPNGATE_TEST_PATH"; export PATH; [ "$(command -v ssh)" = "$OPNGATE_TEST_BIN/ssh" ] || exit 99; script=$1; shift; . "$script"'
        script=shell_path(root/'deploy/deploy.sh')
        result=subprocess.run([str(BASH),'-c',runner,script,script,command],env={**env,**extra},text=True,capture_output=True,timeout=30)
        return result,log.read_text() if log.exists() else ''
    return root,key,run


def test_update_preserves_routes_trust_and_firewall(setup):
    root,key,run=setup
    result,log=run('update')
    assert result.returncode==0,result.stdout+result.stderr
    assert '['+shell_path(key)+']' in log
    assert '[StrictHostKeyChecking=yes]' in log
    assert 'services && docker compose build portal portal-ingest' in log
    assert 'edge && docker compose build waf-shipper' in log
    for forbidden in ('portal_rules.php','fw_agent restart','gen-key','operator_keys.json','get.docker.com','deploy/pki/out','--remove-orphans'):
        assert forbidden not in log


def test_failed_connection_stops_before_upload(setup):
    _,_,run=setup
    result,log=run('update',FAIL_SSH_TARGET='root@services.example')
    assert result.returncode!=0
    assert 'tar -xf' not in log and 'docker compose build' not in log


def test_archive_failure_is_not_reported_as_success(setup):
    _,_,run=setup
    result,log=run('update',FAIL_ARCHIVE='yes')
    assert result.returncode!=0
    assert 'nothing sent' in result.stderr
    assert 'tar -xf' not in log and 'docker compose build' not in log


def test_partial_pki_is_not_regenerated(setup):
    root,_,run=setup
    pki=root/'deploy/pki/out';pki.mkdir(parents=True)
    certificate=pki/'services.crt';certificate.write_text('existing certificate')
    result,_=run('pki')
    assert result.returncode!=0 and 'incomplete PKI' in result.stderr
    assert certificate.read_text()=='existing certificate'


def test_windows_launcher_noninteractive_requires_explicit_config(tmp_path):
    if os.name!='nt': pytest.skip('Windows launcher')
    script=ROOT/'Deploy.ps1';config=tmp_path/'absent.conf'
    result=subprocess.run(['powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File',str(script),'-Action','Configure','-NonInteractive','-NoPause','-ConfigPath',str(config)],text=True,capture_output=True,timeout=20)
    assert result.returncode!=0 and not config.exists()
    assert 'Missing' in result.stderr


def test_windows_launcher_resolves_default_config_from_its_own_directory(tmp_path):
    if os.name!='nt': pytest.skip('Windows launcher')
    script=tmp_path/'Deploy.ps1'
    shutil.copyfile(ROOT/'Deploy.ps1',script)
    result=subprocess.run(['powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File',str(script),'-Action','Configure','-NonInteractive','-NoPause'],text=True,capture_output=True,timeout=20)
    assert result.returncode!=0
    assert 'Missing' in result.stderr and 'Join-Path' not in result.stderr
    assert not (tmp_path/'deploy/deploy.conf').exists()
