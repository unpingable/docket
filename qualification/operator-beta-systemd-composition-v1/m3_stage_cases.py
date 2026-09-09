#!/usr/bin/env python3
"""Finite stage qualification cases, each one admitted once through AG/Docket.

This is a guest test producer, not a recovery controller. Nonzero helper exits
are retained, never retried. A separate checker must decide qualification.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess

import m3_guest_route as route

STAGE_CUTS = ('before_started', 'after_started', 'before_terminal', 'after_terminal',
              'after_backup_sync', 'after_restore_sync', 'after_staging_sync')
CASES = ('normal-stage', 'temporary-space', 'source-before-cut',
         'backup-not-restore', 'compaction-failure', *('cut-' + cut for cut in STAGE_CUTS))


def execute_command(output, label, command):
    result = subprocess.run(command, capture_output=True, timeout=40,
                            env=dict(os.environ, PYTHONPATH=str(route.ROOT / 'labelwatch/src')))
    for suffix, value in [('stdout', result.stdout), ('stderr', result.stderr),
                          ('exit', (str(result.returncode) + '\n').encode())]:
        with (output / (label + '.' + suffix)).open('xb') as stream:
            stream.write(value)
    if result.returncode:
        raise RuntimeError(label + ' failed; retained occurrence must be inspected, not restarted')
    return result.stdout


def mutate_closed_source(source):
    """Finish the fixture-only WAL transaction before establishing its byte cut."""
    connection = sqlite3.connect(source)
    try:
        if connection.execute("UPDATE maintenance_types SET value=8 WHERE key='int'").rowcount != 1:
            raise RuntimeError('exact single-row fixture seed differs')
        connection.commit()
        checkpoint = connection.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()
        if checkpoint[0] != 0 or checkpoint[1] != checkpoint[2]:
            raise RuntimeError('fixture seed checkpoint incomplete')
    finally:
        connection.close()


def seed(case, fixture, mountpoint):
    source = fixture / 'source.sqlite'
    evidence = {'case': case, 'source_sha256_before': hashlib.sha256(source.read_bytes()).hexdigest()}
    if case == 'source-before-cut':
        mutate_closed_source(source)
    elif case == 'compaction-failure':
        with (fixture / 'staging.sqlite').open('xb') as stream:
            stream.write(b'EXCLUSIVE_DESTINATION_MUST_REMAIN_UNCHANGED\n')
    elif case == 'temporary-space':
        # Only our fresh 4MiB tmpfs may be filled, never a general host/guest FS.
        stat = os.statvfs(mountpoint)
        if not os.path.ismount(mountpoint) or stat.f_blocks * stat.f_frsize > 4 * 1024 * 1024:
            raise RuntimeError('bounded dedicated target filesystem required')
        count = max(0, stat.f_bavail * stat.f_frsize - 8192)
        with (mountpoint / 'qualification-space-reservation').open('xb') as stream:
            while count:
                block = min(count, 65536)
                stream.write(b'X' * block)
                count -= block
            stream.flush()
            os.fsync(stream.fileno())
        remaining = os.statvfs(mountpoint).f_bavail * os.statvfs(mountpoint).f_frsize
        if remaining >= source.stat().st_size + 4096:
            raise RuntimeError('insufficient-space seed not established')
        evidence['remaining_bytes'] = remaining
    evidence['source_sha256_after_seed'] = hashlib.sha256(source.read_bytes()).hexdigest()
    return evidence


def run(case, revision):
    if case not in CASES or os.geteuid() != 0:
        raise ValueError('closed fixture case and root guest enrollment required')
    if len(revision) != 40 or any(c not in '0123456789abcdef' for c in revision):
        raise ValueError('exact application revision required')
    parent = route.DATA / 'stage-cases'
    parent.mkdir(mode=0o700, exist_ok=True)
    output = parent / case
    output.mkdir(mode=0o700)  # existing occurrence is never resumed/reissued here
    mountpoint = output / 'target-fs'
    mountpoint.mkdir(mode=0o700)
    execute_command(output, 'mount', ['mount', '-t', 'tmpfs', '-o',
                    'size=4M,mode=0700,nodev,nosuid,noexec', 'm3-' + case, str(mountpoint)])
    backup = Path('/mnt/constellation-m3-backup') / ('stage-' + case)
    backup.mkdir(mode=0o700)
    execute_command(output, 'mount-backup', ['mount', '-t', 'tmpfs', '-o',
                    'size=8M,mode=0700,nodev,nosuid,noexec', 'm3-backup-' + case, str(backup)])
    fixture = mountpoint / 'operation'
    generator = str(route.ROOT / 'labelwatch/scripts/m3_fixture_enrollment.py')
    execute_command(output, 'initialize', ['/usr/bin/python3', generator, 'initialize',
                    '--target', str(fixture), '--backup', str(backup), '--revision', revision])
    command = ['/usr/bin/python3', generator, 'seal', '--target', str(fixture),
               '--action', 'stage', '--source-root', str(route.ROOT / 'labelwatch'),
               '--python', str(Path('/usr/bin/python3').resolve())]
    if case.startswith('cut-'):
        command += ['--interruption-cut', case[4:]]
    if case == 'backup-not-restore':
        command += ['--qualification-restore-substitution']
    candidate = json.loads(execute_command(output, 'seal', command))
    (output / 'SEED.json').write_bytes(route.canonical(seed(case, fixture, mountpoint)))
    candidate_path = Path(candidate['step']).parent / 'candidate.json'
    code = route.execute(candidate_path, output / 'admitted-step', None)
    # This records producer termination, not qualified maintenance completion.
    # Keep filesystem, source, backup, journal, unit and custody untouched.
    (output / 'PRODUCER.json').write_bytes(route.canonical({
        'schema': 'constellation.m3-stage-case-producer/v1', 'case': case,
        'application_revision': revision, 'candidate': str(candidate_path),
        'driver_exit': code, 'terminal_claim': 'AWAITING_INDEPENDENT_CHECK',
        'next': 'inspect retained occurrence; no automatic retry or cleanup',
        'mountpoint': str(mountpoint), 'backup': str(backup)}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', choices=CASES, required=True)
    parser.add_argument('--revision', required=True)
    args = parser.parse_args()
    run(args.case, args.revision)
