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
        observed = subprocess.run(['systemctl', 'stop', unit], capture_output=True, timeout=20)
        stopped.append({'unit': unit, 'exit': observed.returncode, 'stdout': observed.stdout.decode(errors='replace'), 'stderr': observed.stderr.decode(errors='replace')})
        if observed.returncode:
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
