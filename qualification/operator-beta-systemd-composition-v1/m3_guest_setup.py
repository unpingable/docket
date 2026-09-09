#!/usr/bin/env python3
"""Prepare only an enrolled disposable M3 guest; never start application units."""
import hashlib
import json
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path('/opt/constellation-m3')
TARGET_PARENT = pathlib.Path('/var/lib/constellation-m3')
BACKUP = pathlib.Path('/mnt/constellation-m3-backup')
WHEEL_SHA = '6abbd3e82c731c8e531714466acd5d87b5e88ac3243465337ba71d68e23ae7e3'


def writer_unit(role):
    commands = {'main': 'run --ingest-interval 0 --scan-interval 0', 'discovery': 'discover-stream --backstop-interval 0'}
    if role not in commands:
        raise ValueError('unknown enrolled writer role')
    return ('[Unit]\nDescription=M3 disposable held writer ' + role + '\n'
        '[Service]\nType=simple\nUser=root\nGroup=root\nRestart=no\n'
        'Environment=PYTHONPATH=/opt/constellation-m3/labelwatch/src:/opt/constellation-m3/websockets.whl\n'
        'Environment=JETSTREAM_URL=ws://127.0.0.1:9\n'
        'ExecStart=/usr/bin/python3 -m labelwatch.cli --db /var/lib/constellation-m3/run/source.sqlite ' + commands[role] + '\n'
        'WorkingDirectory=/opt/constellation-m3/labelwatch\n'
        'TimeoutStopSec=15\n[Install]\nWantedBy=multi-user.target\n')


def setup(revision):
    if os.geteuid() != 0 or len(revision) != 40 or any(c not in '0123456789abcdef' for c in revision):
        raise RuntimeError('root and exact source revision required')
    if TARGET_PARENT.exists() or BACKUP.exists() or not (ROOT / 'labelwatch').is_dir():
        raise RuntimeError('not a fresh pre-enrolled source fixture')
    if hashlib.sha256((ROOT / 'websockets.whl').read_bytes()).hexdigest() != WHEEL_SHA:
        raise RuntimeError('exact universal wheel differs')
    for path in (ROOT, *ROOT.rglob('*')):
        metadata = path.lstat()
        if path.is_symlink() or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise RuntimeError('source/import chain is not root-owned without shared writes')
    TARGET_PARENT.mkdir(mode=0o700)
    BACKUP.mkdir(mode=0o700)
    subprocess.run(['mount', '-t', 'tmpfs', '-o', 'size=64M,mode=0700,nodev,nosuid,noexec', 'm3-fixture-backup', str(BACKUP)], check=True)
    assert BACKUP.stat().st_dev != TARGET_PARENT.stat().st_dev
    environment = dict(os.environ, PYTHONPATH=str(ROOT / 'labelwatch/src'))
    initialized = subprocess.run(['/usr/bin/python3', str(ROOT / 'labelwatch/scripts/m3_fixture_enrollment.py'), 'initialize', '--target', str(TARGET_PARENT / 'run'), '--backup', str(BACKUP), '--revision', revision], env=environment, capture_output=True, timeout=30)
    (TARGET_PARENT / 'initialize.stdout').write_bytes(initialized.stdout)
    (TARGET_PARENT / 'initialize.stderr').write_bytes(initialized.stderr)
    if initialized.returncode:
        raise RuntimeError('fixture initialization failed; retain paths and mount for inspection')
    units = {}
    for role in ('main', 'discovery'):
        name = 'labelwatch-m3-' + role + '.service'
        path = pathlib.Path('/etc/systemd/system') / name
        text = writer_unit(role)
        with path.open('x') as output:
            output.write(text)
        path.chmod(0o644)
        units[name] = hashlib.sha256(text.encode()).hexdigest()
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    (TARGET_PARENT / 'SETUP.json').write_text(json.dumps({'schema': 'constellation.m3-guest-setup/v1', 'source_revision': revision, 'units': units, 'writers_started': False, 'authority_granted': False, 'backup': str(BACKUP), 'separate_device': True, 'backup_power_loss_durability': 'NOT_QUALIFIED_TMPFS_FIXTURE', 'service_accounts': 'ROOT_FIXTURE_NOT_RESTRICTED_PRODUCTION', 'upstream_acquisition': 'DISABLED_OR_REFUSED_LOOPBACK'}, sort_keys=True) + '\n')


if __name__ == '__main__':
    setup(sys.argv[1])
