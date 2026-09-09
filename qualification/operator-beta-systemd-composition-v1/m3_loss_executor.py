#!/usr/bin/python3
"""Enrolled fixture wrapper around the unchanged, pinned real AG executor.

Docket binds this wrapper as its executor program for this explicit loss fixture.
The wrapper/import tree is root-enrolled. It is not the normal production adapter
and does not assert that Docket authenticates Python imports. No fallback/retry.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from m3_case_check import read
from m3_loss_barrier import arrive, await_release, retain

AG = '/usr/libexec/agent-governor-ng/ag-effectd'
AG_SHA = '7c45c79de452ab838cf79575872b0797eafbe27c7904b113e560967d11eef75e'
DOCKET = '/usr/libexec/constellation-operator-beta/docket'
DATA = Path('/var/lib/constellation-m3')


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ('plan-id', 'execute', 'reconcile'):
        raise ValueError('fixed executor operation and plan required')
    if hashlib.sha256(Path(AG).read_bytes()).hexdigest() != AG_SHA:
        raise ValueError('real executor differs from enrolled image')
    if sys.argv[1] != 'execute':
        os.execv(AG, [AG, *sys.argv[1:]])
    path = Path(os.environ['CONSTELLATION_M3_CONTROLLER_LOSS'])
    if os.geteuid() != 0 or path.resolve(strict=True) != path or not path.is_relative_to(DATA):
        raise ValueError('root disposable guest and physical fixture config required')
    config = read(path)
    if set(config) != {'schema', 'cut'} or config['schema'] != 'constellation.m3-controller-loss-config/v1':
        raise ValueError('closed fixture config required')
    raw = sys.stdin.buffer.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError('bounded actual dispatch required')
    dispatch = json.loads(raw)
    directory = path.parent
    registered = read(directory / 'COMPANION.json')
    companion = {key: registered[key] for key in ('pid', 'start_ticks')}
    inspected = subprocess.run([DOCKET, 'governed-loop', 'inspect', '--state',
        str(directory.parent / 'custody/occurrence/docket-state'), '--issuance', registered['issuance']],
        capture_output=True, timeout=10)
    if inspected.returncode:
        raise ValueError('committed Docket custody not observable at executor boundary')
    owner = json.loads(inspected.stdout)
    if owner['record']['custody']['attempt'] != dispatch['attempt']:
        raise ValueError('observed custody differs from actual executor dispatch')
    observation = {'dispatch': dispatch, 'docket_inspection': owner,
        'real_executor_deliveries_before_barrier': 0,
        'ag_attempt_store_present_before_execution': Path(read(sys.argv[2])['attempt_store']).exists(),
        'wrapper_transport_invocation': 'PRESENT_NOT_CLAIMED_ABSENT'}
    if config['cut'] == 'docket-reserved-before-executor':
        record = arrive(directory, config['cut'], companion, observation)
        await_release(directory, record)
    # Exclusive marker plus actual subprocess result: no second execute route.
    retain(directory / 'REAL-EXECUTOR-DELIVERY.json', {'dispatch_sha256': hashlib.sha256(raw).hexdigest(),
        'claim': 'SINGLE_INVOCATION_INTENT_NOT_YET_AN_EXECUTION_RESULT'})
    result = subprocess.run([AG, *sys.argv[1:]], input=raw, capture_output=True, timeout=40)
    retain(directory / 'REAL-EXECUTOR-RESULT.json', {'exit': result.returncode,
        'stdout': result.stdout.decode(), 'stderr': result.stderr.decode(),
        'stdout_sha256': hashlib.sha256(result.stdout).hexdigest()})
    if config['cut'] == 'executor-completed-before-reply':
        if result.returncode:
            raise ValueError('real executor did not complete expected positive cut')
        observation['real_executor_deliveries_before_barrier'] = 1
        observation['real_executor_outcome'] = json.loads(result.stdout)
        record = arrive(directory, config['cut'], companion, observation)
        await_release(directory, record)
    sys.stdout.buffer.write(result.stdout)
    sys.stderr.buffer.write(result.stderr)
    return result.returncode


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print('M3 loss fixture refused: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
