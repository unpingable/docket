#!/usr/bin/env python3
"""Closed sequential M3 guest qualification batch; no retries or recovery engine.

The host must enroll exact producer/checker source trees before invoking this
inside its disposable VM. Failure retains the current case for reconciliation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from m3_vm_inputs import APP_HEAD, NQ_BINARY_SHA
import m3_guest_route as route
from m3_stage_cases import CASES
from m3_later_cases import cases


def inventory():
    return [('stage', name) for name in CASES] + [('later', name) for name in sorted(cases())]


def retain(path, value):
    with path.open('xb') as stream:
        stream.write(route.canonical(value))
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_DIRECTORY | os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def call(command, output, label, timeout):
    with (output / (label + '.stdout')).open('xb') as stdout, (output / (label + '.stderr')).open('xb') as stderr:
        try:
            result = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=timeout,
                env=dict(os.environ, PYTHONPATH='/opt/constellation-m3/labelwatch/src:/opt/constellation-m3/websockets.whl'))
            code = result.returncode
        except subprocess.TimeoutExpired:
            code = 'OUTCOME_UNKNOWN_TIMEOUT_NO_RETRY'
    retain(output / (label + '.exit.json'), {'exit': code})
    if code != 0:
        raise RuntimeError(label + ' incomplete; retain current case, no new invocation')


def run(checker, expected_checker_sha):
    if os.geteuid() != 0 or checker.resolve(strict=True) != checker:
        raise ValueError('root disposable guest and physical checker required')
    if hashlib.sha256(checker.read_bytes()).hexdigest() != expected_checker_sha:
        raise ValueError('independent checker identity differs')
    if hashlib.sha256(Path('/usr/bin/nq').read_bytes()).hexdigest() != NQ_BINARY_SHA:
        raise ValueError('actual guest native image differs')
    output = route.DATA / 'matrix'
    output.mkdir(mode=0o700)
    plan = inventory()
    retain(output / 'PLAN.json', {'cases': plan, 'application': APP_HEAD,
        'checker_sha256': expected_checker_sha, 'authority': 'NONE',
        'case_timeout_seconds': 900, 'total_budget_seconds': 7200})
    started = time.monotonic()
    try:
        for index, (kind, name) in enumerate(plan):
            if time.monotonic() - started >= 7200:
                raise RuntimeError('finite matrix budget exhausted')
            record = output / f'{index:02d}-{kind}-{name}'
            record.mkdir()
            retain(record / 'STARTED.json', {'kind': kind, 'case': name, 'next': 'single producer invocation'})
            producer = Path(__file__).parent / ('m3_stage_cases.py' if kind == 'stage' else 'm3_later_cases.py')
            command = [sys.executable, str(producer), '--case', name, '--revision', APP_HEAD]
            if kind == 'later':
                command += ['--nq', '/usr/bin/nq', '--nq-sha256', NQ_BINARY_SHA]
            call(command, record, 'producer', 900)
            case = route.DATA / (kind + '-cases') / name
            call([sys.executable, str(checker), str(case), '--nq', '/usr/bin/nq', '--nq-sha256', NQ_BINARY_SHA], record, 'checker', 90)
            checked = json.loads((record / 'checker.stdout').read_bytes())
            retain(case / 'INDEPENDENT-CHECK.json', checked)
            # A foreign-operation donor is a separately created actual case and
            # must be stopped/archived too, before declaring case teardown done.
            donor = case / 'DONOR.json'
            targets = []
            if donor.exists():
                donor_path = Path(json.loads(donor.read_bytes())['directory'])
                retain(donor_path / 'INDEPENDENT-CHECK.json', checked['foreign_donor'])
                targets.append(donor_path)
            targets.append(case)
            for ordinal, target in enumerate(targets):
                call([sys.executable, str(Path(__file__).parent / 'm3_case_teardown.py'), str(target)],
                    record, 'teardown-' + str(ordinal), 90)
            retain(record / 'COMPLETED.json', {'case': name, 'checked': True, 'scoped_teardown': True})
        retain(output / 'RESULT.json', {'disposition': 'FINITE_CASE_CHECKS_COMPLETED', 'count': len(plan),
            'independent_final_review': 'REQUIRED', 'production': 'NOT_RUN'})
    except Exception as error:
        retain(output / 'REFUSAL.json', {'reason': str(error), 'next': 'inspect retained existing case; do not rerun matrix'})
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checker', type=Path, required=True)
    parser.add_argument('--checker-sha256', required=True)
    arguments = parser.parse_args()
    run(arguments.checker, arguments.checker_sha256)
