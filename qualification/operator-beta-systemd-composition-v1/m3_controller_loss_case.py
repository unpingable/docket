#!/usr/bin/python3
"""Closed M3 companion-loss case, no new issuance/retry after exact child exit."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from unittest.mock import patch

import m3_guest_route as route
from m3_case_check import read
from m3_later_cases import Case, PREVIOUS, application
from m3_loss_barrier import case_inventory, identity, retain, terminate_and_release

DRIVER = '/usr/libexec/constellation-operator-beta/m3-composition-driver'
DOCKET = '/usr/libexec/constellation-operator-beta/docket'
WRAPPER = '/opt/constellation-m3/producer/qualification/operator-beta-systemd-composition-v1/m3_loss_executor.py'


class LossCase(Case):
    def run(self):
        action, cut, expired = case_inventory()[self.name]
        for previous in PREVIOUS[action]:
            if previous == 'writers':
                self.start_writers()
            elif previous == 'cleanup-cut':
                self.admit('cleanup', 'after_cleanup_unlink', prerequisite=False)
            else:
                self.admit(previous)
        original_run = subprocess.run
        selected = self.output / f'{len(self.actions):02d}-{action}'
        observed = []

        def interrupt(command, *arguments, **keywords):
            if not command or str(command[0]) != DRIVER or Path(command[3]) != selected / 'custody':
                return original_run(command, *arguments, **keywords)
            directory = selected / 'controller-loss'
            directory.mkdir(mode=0o700)
            retain(directory / 'CONFIG.json', {'schema': 'constellation.m3-controller-loss-config/v1', 'cut': cut})
            env = dict(os.environ, CONSTELLATION_M3_CONTROLLER_LOSS=str(directory / 'CONFIG.json'))
            # Only this exact directly launched child is enrolled for termination.
            child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
            companion = identity(child.pid)
            retain(directory / 'ENROLLED-COMPANION.json', {'companion': companion,
                'executable': DRIVER, 'sha256': hashlib.sha256(Path(DRIVER).read_bytes()).hexdigest()})
            deadline = time.monotonic() + 55
            while not (directory / 'ARRIVED.json').exists():
                if child.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('expected durable loss barrier not reached; retain existing occurrence')
                time.sleep(.01)
            record = read(directory / 'ARRIVED.json')
            if record['cut'] != cut or record['companion'] != companion:
                raise ValueError('arrived cut/process differs from separately enrolled child')
            if expired:
                # Use actual elapsed time on the already admitted cleanup cut;
                # do not rewrite timestamps or regenerate its receipt.
                time.sleep(31)
            terminate_and_release(directory, record, companion)
            stdout, stderr = child.communicate(timeout=5)
            if child.returncode != -9:
                raise ValueError('actual companion termination differs')
            observed.append(directory)
            return subprocess.CompletedProcess(command, child.returncode, stdout, stderr)

        with patch.object(subprocess, 'run', side_effect=interrupt):
            self.admit(action, prerequisite=False)
        if len(observed) != 1:
            raise RuntimeError('actual expected companion loss not observed')
        directory = observed[0]
        registered = read(directory / 'COMPANION.json')
        # Orphaned existing transport may finish. Poll only its existing owner
        # record; never invoke accept or execute again. Cut1 has no acceptance.
        if cut != 'ag-consumed-before-accept':
            deadline = time.monotonic() + 45
            while True:
                queried = original_run([DOCKET, 'governed-loop', 'inspect', '--state',
                    str(selected / 'custody/occurrence/docket-state'), '--issuance', registered['issuance']],
                    capture_output=True, timeout=10)
                if queried.returncode == 0 and json.loads(queried.stdout)['record']['status'] in ('settled', 'indeterminate'):
                    break
                if time.monotonic() >= deadline:
                    break
                time.sleep(.05)
            retain(directory / 'DOCKET-BEFORE-RECOVERY-QUERY.json', {
                'exit': queried.returncode, 'stdout': queried.stdout.decode(),
                'stderr': queried.stderr.decode(), 'retry_or_new_execution': 'NOT_REQUESTED'})
            if queried.returncode == 0:
                retain(directory / 'DOCKET-BEFORE-RECOVERY.json', json.loads(queried.stdout))
        recovery = original_run([DRIVER, '--recover-existing', DOCKET, WRAPPER,
            str(selected / 'custody'), registered['issuance']], capture_output=True, timeout=30)
        retain(directory / 'RECOVERY-RESULT.json', {'exit': recovery.returncode,
            'stdout': recovery.stdout.decode(), 'stderr': recovery.stderr.decode()})
        if recovery.returncode:
            raise RuntimeError('existing-owner recovery refused; retained, no replacement campaign')
        helper, _ = application()
        retain(self.output / 'RECOVERY-OBSERVATION.json', helper.reconcile(self.base))
        retain(self.output / 'PRODUCER.json', {'schema': 'constellation.m3-controller-loss-case/v1',
            'case': self.name, 'action': action, 'cut': cut, 'expired_cleanup': expired,
            'actions': self.actions, 'barrier_directory': str(directory),
            'writers': self.writers,
            'terminal_claim': 'AWAITING_INDEPENDENT_OWNER_AND_APPLICATION_CHECK',
            'teardown': 'NOT_RUN_RETAINED_CASE_ONLY'})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', choices=sorted(case_inventory()), required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--nq', type=Path, required=True)
    parser.add_argument('--nq-sha256', required=True)
    args = parser.parse_args()
    LossCase(args.case, args.revision, args.nq, args.nq_sha256).run()
