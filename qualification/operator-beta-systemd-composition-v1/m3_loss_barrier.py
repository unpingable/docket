#!/usr/bin/env python3
"""Finite qualification rendezvous for actual companion-process loss.

This never creates an issuance, resumes a helper, or interprets owner disposition.
The separately enrolled fixture observes an exact process exit and releases only
the paused qualification wrapper. Owner-state qualification belongs to the
independent checker and existing AG/Docket reconciliation interfaces.
"""
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import time

CUTS = ('ag-consumed-before-accept', 'docket-reserved-before-executor',
        'executor-completed-before-reply', 'docket-settled-before-ag-poll',
        'ag-settled-before-export')
LOSS_ACTIONS = ('stage', 'replace', 'verify-installed', 'verify-service', 'cleanup',
                'release', 'rollback-pre-ingest', 'reconcile-cleanup')


def case_inventory():
    result = {'loss-' + action + '-' + cut: (action, cut, False)
        for action in LOSS_ACTIONS for cut in CUTS}
    result['loss-cleanup-expired-before-accept'] = ('cleanup', CUTS[0], True)
    return result


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def retain(path, value):
    with Path(path).open('xb') as stream:
        stream.write(canonical(value))
        stream.flush()
        os.fsync(stream.fileno())
    descriptor = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def identity(pid):
    if type(pid) is not int or pid <= 1:
        raise ValueError('exact positive fixture process required')
    raw = Path('/proc', str(pid), 'stat').read_text()
    # comm can contain spaces or parentheses; fields after its final ')' start
    # at field3. starttime is field22, index19 in this suffix.
    fields = raw.rsplit(')', 1)[1].split()
    return {'pid': pid, 'start_ticks': int(fields[19])}


def arrive(directory, cut, companion, owner_observation):
    directory = Path(directory)
    if cut not in CUTS or identity(companion['pid']) != companion:
        raise ValueError('closed cut and exact live enrolled companion required')
    if directory.resolve(strict=True) != directory or not directory.is_dir():
        raise ValueError('physical enrolled barrier directory required')
    record = {'schema': 'constellation.m3-companion-loss-barrier/v1', 'cut': cut,
        'companion': companion, 'observer': identity(os.getpid()),
        'owner_observation': owner_observation,
        'semantics': 'OBSERVATION_ONLY_REQUIRES_INDEPENDENT_OWNER_REOPEN',
        'next': 'EXACT_COMPANION_EXIT_THEN_RELEASE_THIS_EXISTING_WRAPPER_NO_NEW_DELIVERY'}
    retain(directory / 'ARRIVED.json', record)
    return record


def release_identity(record):
    return hashlib.sha256(canonical(record)).hexdigest()


def await_release(directory, record, seconds=60):
    if not 0 < seconds <= 60:
        raise ValueError('finite qualification barrier budget required')
    deadline = time.monotonic() + seconds
    release = Path(directory) / 'RELEASE.json'
    while time.monotonic() < deadline:
        if release.exists():
            if release.is_symlink() or release.stat().st_size > 4096:
                raise ValueError('bounded regular exact release required')
            expected = {'barrier_sha256': release_identity(record),
                'companion': record['companion'], 'observed_exit': True}
            if release.read_bytes() != canonical(expected):
                raise ValueError('release does not bind this exact barrier')
            return
        time.sleep(min(.01, max(0, deadline - time.monotonic())))
    raise TimeoutError('companion-loss barrier expired; no resumed wrapper execution')


def terminate_and_release(directory, record, expected_companion):
    """Caller must enroll this exact local fixture process before invoking.

    pidfd pins the process; start ticks protect against selecting a later PID
    reuse. This is an explicit qualification action, never recovery policy.
    """
    if record['companion'] != expected_companion:
        raise ValueError('barrier differs from separately enrolled companion')
    descriptor = os.pidfd_open(expected_companion['pid'])
    try:
        if identity(expected_companion['pid']) != expected_companion:
            raise ValueError('fixture process identity changed')
        signal.pidfd_send_signal(descriptor, signal.SIGKILL)
        if not select.select([descriptor], [], [], 5)[0]:
            raise TimeoutError('exact companion exit not observed; wrapper remains paused')
        result = {'barrier_sha256': release_identity(record),
            'companion': expected_companion, 'observed_exit': True}
        retain(Path(directory) / 'COMPANION-EXIT.json', result)
        retain(Path(directory) / 'RELEASE.json', result)
        return result
    finally:
        os.close(descriptor)
