#!/usr/bin/env python3
"""Remote stages for an existing compatible stack; invoked by deploy.sh.

Only public application/deployment files and scoped Compose services change.
Database snapshots are retained for recovery, never automatically restored.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import time

SERVICES = {'services': ('portal', 'portal-ingest'), 'edge': ('waf-shipper',)}
FILES = {'README.md', 'REVIEW.md', 'Deploy.ps1', 'Deploy.cmd',
         'OPNGate Security Assessment & Test Plan.md', 'portal/Dockerfile',
         'portal/requirements.txt', 'deploy/deploy.sh', 'deploy/app-update.py'}


def allowed(name):
    path = PurePosixPath(name)
    return (str(path) == name and not path.is_absolute() and '..' not in path.parts and '\\' not in name
            and not any(p in ('.git', '.venv', '__pycache__') or p.startswith('.env') for p in path.parts)
            and not name.lower().endswith(('.key', '.pem', '.crt', '.db', '.db-wal', '.db-shm', '.pyc'))
            and (name in FILES or name.startswith(('portal/app/', 'docs/'))))


def write_json(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')
    temporary.chmod(0o600)
    os.replace(temporary, path)


class Update:
    def __init__(self, root, release, role, checksum=None):
        if not re.fullmatch(r'opngate-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}', release):
            raise ValueError('Invalid release ID')
        candidate = Path(root)
        if not candidate.is_absolute():
            raise ValueError('Use a dedicated absolute application directory')
        self.root = candidate.resolve()
        if len(self.root.parts) < 3:
            raise ValueError('Use a dedicated absolute application directory')
        self.release, self.role, self.checksum = release, role, checksum
        self.directory = self.root / 'releases' / release
        self.lock = self.root / 'releases' / '.opngate-update.lock'
        self.marker = self.root / 'releases' / 'current.json'
        self.state_path = self.directory / 'state.json'
        self.compose_dir = self.root / 'deploy' / role

    def run(self, *args, input=None, logfile=None):
        command = [str(a) for a in args]
        if logfile:
            with logfile.open('a', encoding='utf-8') as output:
                result = subprocess.run(command, input=input, text=True, stdout=output, stderr=subprocess.STDOUT)
        else:
            result = subprocess.run(command, input=input, text=True, capture_output=True)
        if result.returncode:
            # Captured logs can contain operational data. Keep them on the host.
            raise RuntimeError(f'{command[0]} failed; inspect private release logs on this host')
        return result.stdout or ''

    def compose(self, *args, **kwargs):
        return self.run('docker', 'compose', '--project-directory', self.compose_dir,
                        '-f', self.compose_dir / 'docker-compose.yml', *args, **kwargs)

    def target(self, name):
        if not allowed(name):
            raise ValueError('Archive contains an unexpected/private path')
        path = self.root
        for part in PurePosixPath(name).parts:
            path = path / part
            if path.is_symlink():
                raise ValueError('Application paths must not contain symlinks')
        path.resolve().relative_to(self.root)
        return path

    def load(self):
        state = json.loads(self.state_path.read_text(encoding='utf-8'))
        if state['release'] != self.release or state['role'] != self.role:
            raise ValueError('Release state does not match this host role')
        return state

    def unlock(self):
        if self.lock.exists():
            if (self.lock / 'owner').read_text(encoding='utf-8').strip() != self.release:
                raise RuntimeError('Another deployment owns the host lock')
            (self.lock / 'owner').unlink()
            self.lock.rmdir()

    def owned(self):
        if not self.lock.exists() or (self.lock / 'owner').read_text(encoding='utf-8').strip() != self.release:
            raise RuntimeError('Deployment lock is not owned by this release')

    def prepare(self):
        for name in ('.env', 'docker-compose.yml'):
            if not (self.compose_dir / name).is_file():
                raise RuntimeError('Existing compatible stack required')
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.state_path.exists():
            raise RuntimeError('Release already prepared; use its recorded rollback command')
        archive = self.directory / 'source.tgz'
        digest = hashlib.sha256()
        with archive.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(chunk)
        digest = digest.hexdigest()
        if not self.checksum or digest != self.checksum:
            raise ValueError('Source archive checksum mismatch')
        members = []
        with tarfile.open(archive, 'r:gz') as package:
            for member in package.getmembers():
                if member.isdir():
                    continue
                self.target(member.name)
                if not member.isfile() or member.name in members:
                    raise ValueError('Archive links, special files and duplicates are refused')
                members.append(member.name)
        for required in ('portal/app/main.py', 'portal/requirements.txt', 'portal/Dockerfile'):
            if required not in members:
                raise ValueError('Incomplete application archive')
        self.lock.mkdir(mode=0o700)  # exclusive; never break another deployment's lock
        (self.lock / 'owner').write_text(self.release + '\n', encoding='utf-8')
        previous = json.loads(self.marker.read_text(encoding='utf-8')) if self.marker.exists() else None
        state = dict(release=self.release, role=self.role, checksum=digest, files=members,
                     images={}, missing=[], prepared=False, previous=previous, status='preparing')
        write_json(self.state_path, state)
        self.compose('config', '-q')
        for service in SERVICES[self.role]:
            container = self.compose('ps', '--status', 'running', '-q', service).strip().splitlines()
            if len(container) != 1:
                raise RuntimeError(f'Expected one running {service} container')
            image, tag, restarts, container_id = self.run('docker', 'inspect', '--format',
                '{{.Image}}|{{.Config.Image}}|{{.RestartCount}}|{{.Id}}', container[0]).strip().split('|')
            if not image.startswith('sha256:') or not tag:
                raise RuntimeError('Could not identify running image')
            backup = f'opngate-rollback-{self.role}-{service}:{self.release}'
            self.run('docker', 'image', 'tag', image, backup)
            state['images'][service] = dict(image=image, tag=tag, backup=backup,
                                            restarts=int(restarts), container=container_id)
        with tarfile.open(self.directory / 'source-before.tgz', 'x:gz') as backup:
            for name in members:
                path = self.target(name)
                if path.exists():
                    if not path.is_file():
                        raise ValueError('Application file conflicts with a directory')
                    backup.add(path, arcname=name, recursive=False)
                else:
                    state['missing'].append(name)
        if self.role == 'services':
            program = f'''import os,sqlite3
from app.config import settings
os.umask(0o077)
backup=settings.data_dir/{(self.release + '.db')!r}
if backup.exists(): raise SystemExit('Backup already exists')
with sqlite3.connect(f'file:{{settings.db_path}}?mode=ro',uri=True) as source:
    with sqlite3.connect(backup) as target: source.backup(target)
backup.chmod(0o600)
print('Private database backup retained')
'''
            self.compose('exec', '-T', 'portal', 'python', '-', input=program)
        state.update(prepared=True, status='prepared')
        write_json(self.state_path, state)

    def restore_archive(self, archive):
        with tarfile.open(archive, 'r:gz') as package:
            for member in package.getmembers():
                if member.isdir():
                    continue
                target = self.target(member.name)
                if not member.isfile():
                    raise ValueError('Only regular application files may be installed')
                target.parent.mkdir(parents=True, exist_ok=True)
                temporary = target.with_name('.' + target.name + '.' + self.release + '.tmp')
                with package.extractfile(member) as source, temporary.open('wb') as output:
                    shutil.copyfileobj(source, output)
                temporary.chmod(member.mode & 0o777)
                os.replace(temporary, target)

    def build(self):
        self.owned()
        state = self.load()
        if state['status'] != 'prepared':
            raise RuntimeError('Release is not ready to build')
        self.restore_archive(self.directory / 'source.tgz')
        self.compose('build', *SERVICES[self.role], logfile=self.directory / 'build.log')
        expected = {name.removeprefix('portal/'): hashlib.sha256(self.target(name).read_bytes()).hexdigest()
                    for name in state['files'] if name.startswith('portal/app/')}
        program = '''import hashlib
from pathlib import Path
from app.main import app
expected = ''' + repr(expected) + '''
assert all(hashlib.sha256(Path(name).read_bytes()).hexdigest()==digest for name,digest in expected.items())
print('Built application import and source hashes verified')
'''
        for image in state['images'].values():
            self.run('docker', 'run', '--rm', '-i', '--read-only', '--network', 'none',
                     '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', image['tag'],
                     'python', '-', input=program, logfile=self.directory / 'import.log')
            image['built_image'] = self.run('docker', 'image', 'inspect', '--format', '{{.Id}}', image['tag']).strip()
            if not image['built_image'].startswith('sha256:'):
                raise RuntimeError('Could not identify built image')
        state['status'] = 'built'
        write_json(self.state_path, state)

    def activate(self):
        self.owned()
        state = self.load()
        if state['status'] != 'built':
            raise RuntimeError('Build verification must pass before activation')
        # Persist this before calling Compose: an interrupted response can still start containers.
        state['status'] = 'activating'
        write_json(self.state_path, state)
        self.compose('up', '-d', '--no-deps', '--no-build', *SERVICES[self.role])
        state['status'] = 'active'
        write_json(self.state_path, state)

    def verify(self):
        self.owned()
        state = self.load()
        if state['status'] != 'active':
            raise RuntimeError('Activate the built release before checking readiness')
        for attempt in range(30):
            try:
                for service in SERVICES[self.role]:
                    container = self.compose('ps', '--status', 'running', '-q', service).strip()
                    if not container or '\n' in container:
                        raise RuntimeError('Container not running')
                    running, restarts, container_id, image_id = self.run('docker', 'inspect', '--format',
                        '{{.State.Running}}|{{.RestartCount}}|{{.Id}}|{{.Image}}', container).strip().split('|')
                    before = state['images'][service]
                    permitted = before['restarts'] if container_id == before['container'] else 0
                    if running != 'true' or int(restarts) > permitted or image_id != before['built_image']:
                        raise RuntimeError('Container image or restart count does not match deployment')
                if self.role == 'services':
                    program = '''import time,json,socket
from app import db,live
from app.main import app
frame=live.snapshot()
row=db.one("SELECT v FROM kv WHERE k='waf_last_seen'")
assert not frame['stale'] and frame['source']=='live'
assert row and 0 <= time.time()-int(row['v']) < 90
socket.create_connection(('portal-ingest',9444),timeout=3).close()
print(json.dumps({'version':app.version,'live_age':round(time.time()-frame['reported_at'],2),'shipper_age':round(time.time()-int(row['v']),2)}))
'''
                    print(self.compose('exec', '-T', 'portal', 'python', '-', input=program).strip())
                print(self.role + ': readiness passed')
                return
            except RuntimeError:
                if attempt == 29:
                    raise RuntimeError('Readiness failed after 30 checks') from None
                time.sleep(2)

    def finish(self):
        self.owned()
        state = self.load()
        if state['status'] != 'active':
            raise RuntimeError('Release not active')
        state['status'] = 'complete'
        write_json(self.state_path, state)
        write_json(self.marker, dict(release=self.release, checksum=state['checksum']))
        self.unlock()

    def rollback(self):
        # A failed prepare may have left no state or may belong to another run.
        if not self.state_path.exists():
            if self.lock.exists() and (self.lock / 'owner').read_text(encoding='utf-8').strip() == self.release:
                self.unlock()
            return
        state = self.load()
        if state['status'] == 'rolled_back':
            self.unlock()
            return
        if state['status'] == 'complete':
            current = json.loads(self.marker.read_text(encoding='utf-8')) if self.marker.exists() else {}
            if current.get('release') != self.release:
                raise RuntimeError('Refusing rollback over a newer deployment')
            self.lock.mkdir(mode=0o700)
            (self.lock / 'owner').write_text(self.release + '\n', encoding='utf-8')
        self.owned()
        if state['prepared']:
            self.restore_archive(self.directory / 'source-before.tgz')
            for name in state['missing']:
                self.target(name).unlink(missing_ok=True)
            for image in state['images'].values():
                self.run('docker', 'image', 'tag', image['backup'], image['tag'])
            if state['status'] in ('activating', 'active', 'complete'):
                self.compose('up', '-d', '--no-deps', '--no-build', *SERVICES[self.role])
            if state['previous'] is None:
                self.marker.unlink(missing_ok=True)
            else:
                write_json(self.marker, state['previous'])
        state['status'] = 'rolled_back'
        write_json(self.state_path, state)
        self.unlock()
        print(self.role + ': previous source/images restored; database left current')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('prepare', 'build', 'activate', 'verify', 'finish', 'rollback'))
    parser.add_argument('root')
    parser.add_argument('release')
    parser.add_argument('role', choices=SERVICES)
    parser.add_argument('--sha256')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        import fcntl  # deployment targets are Linux; OS releases this lock after a killed SSH process
        update = Update(args.root, args.release, args.role, args.sha256)
        update.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        with (update.directory / 'operation.lock').open('a') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError('Another stage is still running; wait before retrying recovery') from None
            getattr(update, args.stage)()
    except (OSError, ValueError, RuntimeError, KeyError, tarfile.TarError) as error:
        print(f'{args.role} {args.stage}: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
