#!/usr/bin/env python3
"""Closed controller-loss batch, separate occurrence and budget from ordinary61."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time

import m3_vm_inputs as inputs
from m3_guest_matrix import call, retain
from m3_case_check import read, require, native_reexecution

SCHEMA = 'constellation.m3-controller-loss-vm-result/v1'
HOST_RELATIVE = 'qualification/operator-beta-systemd-composition-v1/run_m3_controller_two_vm.py'
ROOT = Path('/var/lib/constellation-m3')
DRIVER = Path('/usr/libexec/constellation-operator-beta/m3-composition-driver')


def inventory():
    from m3_loss_barrier import case_inventory
    names = sorted(case_inventory())
    require(len(names) == 41 and len(set(names)) == 41, 'closed 41-case controller inventory required')
    return names


def driver_digest(receipt):
    raw = Path(receipt).read_bytes()
    require(hashlib.sha256(raw).hexdigest() == inputs.PINS['driver_receipt'], 'driver receipt pin differs')
    rows = json.loads(raw)['results']
    require(len(rows) == 2 and rows[0] == rows[1] and rows[0]['package_sha256'] == inputs.PINS['driver_package'],
        'two-build driver receipt differs')
    return rows[0]['binary_sha256']


def run(checker, checker_sha):
    require(os.geteuid() == 0 and checker.resolve(strict=True) == checker, 'root guest physical checker required')
    require(hashlib.sha256(checker.read_bytes()).hexdigest() == checker_sha, 'checker differs')
    driver_sha = driver_digest('/home/betaoperator/m3-driver-receipt.json')
    require(hashlib.sha256(DRIVER.read_bytes()).hexdigest() == driver_sha, 'installed driver differs')
    require(hashlib.sha256(Path('/usr/bin/nq').read_bytes()).hexdigest() == inputs.NQ_BINARY_SHA, 'installed native image differs')
    output = ROOT / 'controller-matrix'
    output.mkdir(mode=0o700)
    names = inventory()
    retain(output / 'PLAN.json', {'schema': SCHEMA, 'cases': names, 'application': inputs.APP_HEAD,
        'driver_sha256': driver_sha, 'checker_sha256': checker_sha, 'authority': 'NONE', 'total_budget_seconds': 7200})
    begun = time.monotonic()
    try:
        for index, name in enumerate(names):
            require(time.monotonic() - begun < 7200, 'controller matrix budget exhausted')
            record = output / f'{index:02d}-{name}'
            record.mkdir()
            retain(record / 'STARTED.json', {'case': name, 'next': 'single controller-loss occurrence'})
            base = Path(__file__).parent
            call([sys.executable, str(base / 'm3_controller_loss_case.py'), '--case', name,
                '--revision', inputs.APP_HEAD, '--nq', '/usr/bin/nq', '--nq-sha256', inputs.NQ_BINARY_SHA], record, 'producer', 900)
            case = ROOT / 'later-cases' / name
            call([sys.executable, str(checker), str(case), '--driver', str(DRIVER), '--driver-sha256', driver_sha,
                '--nq', '/usr/bin/nq', '--nq-sha256', inputs.NQ_BINARY_SHA], record, 'checker', 90)
            checked = read(record / 'checker.stdout')
            retain(case / 'INDEPENDENT-CHECK.json', checked)
            call([sys.executable, str(base / 'm3_case_teardown.py'), str(case)], record, 'teardown', 90)
            retain(record / 'COMPLETED.json', {'case': name, 'checked': True, 'scoped_teardown': True})
        retain(output / 'RESULT.json', {'schema': SCHEMA, 'count': 41,
            'disposition': 'CONTROLLER_CASE_CHECKS_COMPLETED', 'independent_final_review': 'REQUIRED'})
    except Exception as error:
        retain(output / 'REFUSAL.json', {'reason': str(error), 'next': 'inspect original case; no new invocation'})
        raise


def check_matrix(root, binary=None):
    from run_m3_two_vm import check_teardown
    # App-owned checker must supply this pure retained-owner reopening seam.
    # Missing capability refuses; booleans alone never qualify controller loss.
    from m3_controller_loss_check import check_retained_owner
    root = Path(root)
    directory = root / 'controller-matrix'
    require(read(directory / 'RESULT.json') == {'schema': SCHEMA, 'count': 41,
        'disposition': 'CONTROLLER_CASE_CHECKS_COMPLETED', 'independent_final_review': 'REQUIRED'}, 'wrong controller terminal')
    require(not (directory / 'REFUSAL.json').exists(), 'controller matrix refused')
    plan = read(directory / 'PLAN.json')
    require(plan['driver_sha256'] == driver_digest(root.parents[1] / 'input/m3-driver-receipt.json'),
        'controller plan driver differs from retained admitted receipt')
    require(plan['schema'] == SCHEMA and plan['cases'] == inventory() and plan['application'] == inputs.APP_HEAD,
        'controller inventory/source differs')
    for index, name in enumerate(inventory()):
        record, case = directory / f'{index:02d}-{name}', root / 'later-cases' / name
        require(read(record / 'COMPLETED.json') == {'case': name, 'checked': True, 'scoped_teardown': True}, 'incomplete controller case')
        for command in ('producer', 'checker', 'teardown'):
            require(read(record / (command + '.exit.json')) == {'exit': 0}, 'controller command incomplete')
        checked = read(case / 'INDEPENDENT-CHECK.json')
        require(checked == read(record / 'checker.stdout') and checked['case'] == name,
            'controller check identity differs')
        require(checked['qualification'] == 'SCOPED_CONTROLLER_LOSS_CHECKS_REQUIRE_INDEPENDENT_REVIEW'
            and checked['new_effect_authority'] == 'NONE', 'controller check stronger scope')
        owner = check_retained_owner(case)
        require(owner['case'] == name and owner['enrolled_driver_sha256'] == plan['driver_sha256']
            and owner['owner_correspondence'] == 'RETAINED_RECORDS_ONLY_NOT_FRESH_STORE_OBSERVATION'
            and owner['new_effect_authority'] == 'NONE', 'controller retained owner/driver differs')
        check_teardown(case)
        if binary is not None:
            actual = native_reexecution(case, binary, inputs.NQ_BINARY_SHA)
            for item in actual:
                item['path'] = str(ROOT / Path(item['path']).relative_to(root))
            require(actual == checked['native_reexecution'], 'controller native replay differs')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checker', type=Path, required=True)
    parser.add_argument('--checker-sha256', required=True)
    args = parser.parse_args()
    run(args.checker, args.checker_sha256)
