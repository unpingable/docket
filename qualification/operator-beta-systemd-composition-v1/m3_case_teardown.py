#!/usr/bin/env python3
"""Stop only exact recorded M3 case units, then archive/unmount its tmpfs.

Separate explicit operator qualification step, never automatic recovery or retry.
Do not invoke until the independent in-guest checker has recorded its result.
"""
import argparse
import hashlib
from pathlib import Path
import os
import subprocess
import tarfile

import m3_guest_route as route
from m3_case_check import read, require


def stop_established(record):
    state = record.get('state', {})
    if record.get('state_exit') != 0 or state.get('ActiveState') != 'inactive' or state.get('SubState') != 'dead' or state.get('MainPID') != '0':
        return False
    return ((record['exit'] == 0 and state.get('LoadState') == 'loaded') or
            (record['exit'] in (0, 5) and state.get('LoadState') == 'not-found'))


def stop_unit(unit):
    try:
        observed = subprocess.run(['systemctl', 'stop', unit], capture_output=True, timeout=20)
    except (subprocess.TimeoutExpired, OSError) as error:
        return {'unit': unit, 'exit': None, 'state_exit': None,
            'disposition': 'STOP_NOT_ESTABLISHED', 'error': str(error)}
    record = {'unit': unit, 'exit': observed.returncode,
        'stdout': observed.stdout.decode(errors='replace'), 'stderr': observed.stderr.decode(errors='replace')}
    try:
        query = subprocess.run(['systemctl', 'show', unit, '--property=LoadState',
            '--property=ActiveState', '--property=SubState', '--property=MainPID'], capture_output=True, timeout=10)
    except (subprocess.TimeoutExpired, OSError) as error:
        record.update(state_exit=None, disposition='STOP_NOT_ESTABLISHED', error=str(error))
        return record
    record.update(state_exit=query.returncode, state_stdout=query.stdout.decode(errors='replace'),
        state_stderr=query.stderr.decode(errors='replace'))
    record['state'] = dict(line.split('=', 1) for line in record['state_stdout'].splitlines() if '=' in line)
    record['disposition'] = ('STOPPED_OR_ALREADY_ABSENT_OBSERVED' if stop_established(record)
        else 'STOP_NOT_ESTABLISHED')
    return record


def teardown(directory):
    directory = Path(directory)
    require(os.geteuid() == 0 and directory == directory.resolve() and directory.is_relative_to(route.DATA), 'exact guest case root required')
    read(directory / 'INDEPENDENT-CHECK.json')
    result = directory / 'TEARDOWN.json'
    require(not result.exists(), 'teardown already has a terminal record')
    writer_file = directory / 'writer-enrollment/WRITERS.json'
    units = []
    if writer_file.exists():
        units += [item['unit'] for item in read(writer_file)['writers'].values()]
    producer = read(directory / 'PRODUCER.json')
    candidates = [producer['candidate']] if 'candidate' in producer else [item['candidate'] for item in producer['actions'] if 'candidate' in item]
    units += [read(path)['unit'] for path in candidates]
    stopped = []
    for unit in units:
        require(unit.startswith(('labelwatch-m3-', 'labelwatch-relief-')) and '/' not in unit and unit.endswith('.service'), 'unrecognized case unit')
        observation = stop_unit(unit)
        stopped.append(observation)
        if not stop_established(observation):
            result.write_bytes(route.canonical({'status': 'STOP_INCOMPLETE_RETAINED', 'units': stopped}))
            raise RuntimeError('scoped stop incomplete; no archive/unmount attempted')
    # SIGSTOP cases are deliberately not resumed into ingestion. systemd's
    # bounded stop escalates to kill under its existing service policy.
    mountpoint = directory / 'target-fs'
    backup = Path(producer.get('backup', '/mnt/constellation-m3-backup/' + producer['case']))
    require(backup.is_relative_to(Path('/mnt/constellation-m3-backup')), 'backup path outside fixture mount')
    archive = directory / 'retained-filesystems.tar'
    with tarfile.open(archive, 'x') as stream:
        stream.add(mountpoint, arcname='target', recursive=True)
        stream.add(backup, arcname='backup', recursive=True)
    # The producer never erases backup or source records. The archive preserves
    # content; it does not preserve inode custody for any resumed authority.
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    unmounted = subprocess.run(['umount', str(mountpoint)], capture_output=True, timeout=15)
    backup_unmounted = subprocess.run(['umount', str(backup)], capture_output=True, timeout=15)
    result.write_bytes(route.canonical({'status': 'SCOPED_STOP_AND_ARCHIVE' if unmounted.returncode == backup_unmounted.returncode == 0 else 'UNMOUNT_INCOMPLETE_RETAINED',
        'units': stopped, 'archive_sha256': digest, 'archive': str(archive), 'unmount_exit': unmounted.returncode,
        'backup_unmount_exit': backup_unmounted.returncode, 'backup_archived': str(backup), 'recovery_authority': 'NONE_ARCHIVE_DOES_NOT_PRESERVE_LIVE_INODE_CUSTODY'}))
    require(unmounted.returncode == backup_unmounted.returncode == 0, 'mount remains for inspection')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    teardown(args.directory)
