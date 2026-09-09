#!/usr/bin/env python3
"""Closed M3 guest qualification matrix; never a runtime workflow engine.

Each selected case creates a new disposable operation. Previously issued actions
are never retried. Runtime findings are retained for a separate read-only checker.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

import m3_guest_route as route
import m3_guest_setup as setup
from m3_stage_cases import mutate_closed_source

PREVIOUS = {
    'stage': [], 'replace': ['stage'], 'verify-installed': ['stage', 'replace'],
    'verify-service': ['stage', 'replace', 'writers'],
    'cleanup': ['stage', 'replace', 'writers', 'verify-service'],
    'release': ['stage', 'replace', 'writers', 'verify-service', 'cleanup'],
    'rollback-pre-ingest': ['stage', 'replace'],
    'reconcile-cleanup': ['stage', 'replace', 'writers', 'verify-service', 'cleanup-cut'],
}


def cases():
    result = {
        'normal': ('release', None), 'equal-count-content': ('verify-service', None),
        'pathname-recovery': ('rollback-pre-ingest', None),
        'writer-start-failure': ('verify-service', None),
        'post-start-verification': ('verify-service', None),
        'post-write-stale-rollback': ('release', None),
        'unknown-resumption': ('release', 'after_release_record'),
        'cleanup-no-margin': ('release', None),
        'duplicate-concurrent': ('stage', None), 'concurrent-lock': ('stage', None),
        'fact-enactment-disagreement': ('release', None),
        'cleanup-missing-receipt': ('cleanup', None),
        'cleanup-stale-receipt': ('cleanup', None),
        'cleanup-substituted-receipt': ('cleanup', None),
        'cleanup-foreign-operation-receipt': ('cleanup', None),
    }
    for action in PREVIOUS:
        if action == 'stage':
            continue  # stage producer owns these seven cases
        for cut in ('before_started', 'after_started', 'before_terminal', 'after_terminal'):
            result[action + '-' + cut] = (action, cut)
    for action, cuts in [('replace', ('after_original_rename', 'after_replacement_rename')),
                         ('cleanup', ('after_cleanup_authorized', 'before_cleanup_unlink', 'after_cleanup_unlink')),
                         ('release', ('after_release_record',))]:
        for cut in cuts:
            result[action + '-' + cut] = (action, cut)
    return result


def application():
    sys.path.insert(0, str(route.ROOT / 'labelwatch/src'))
    from labelwatch import maintenance_step, maintenance_hold
    return maintenance_step, maintenance_hold


def command(output, label, args, *, required=True, timeout=40):
    try:
        result = subprocess.run(args, capture_output=True, timeout=timeout,
            env=dict(os.environ, PYTHONPATH=str(route.ROOT / 'labelwatch/src')))
        stdout, stderr, code = result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired as error:
        stdout, stderr, code = error.stdout or b'', error.stderr or b'', 'NOT_OBSERVABLE_TIMEOUT'
    for suffix, value in [('stdout', stdout), ('stderr', stderr), ('exit', (str(code) + '\n').encode())]:
        with (output / (label + '.' + suffix)).open('xb') as stream:
            stream.write(value)
    if required and code != 0:
        raise RuntimeError(label + ': prerequisite failed; retain occurrence, no retry')
    return stdout, code


class Case:
    def __init__(self, name, revision, nq, nq_sha):
        from m3_loss_barrier import case_inventory
        if (name not in cases() and name not in case_inventory()
                and name != 'cleanup-foreign-operation-receipt-donor') or os.geteuid() != 0:
            raise ValueError('closed guest case and root enrollment required')
        if len(revision) != 40 or any(c not in '0123456789abcdef' for c in revision) or len(nq_sha) != 64 or any(c not in '0123456789abcdef' for c in nq_sha):
            raise ValueError('exact source and native image pins required')
        self.name, self.revision, self.nq, self.nq_sha = name, revision, nq, nq_sha
        self.output = route.DATA / 'later-cases' / name
        self.output.parent.mkdir(mode=0o700, exist_ok=True)
        self.output.mkdir(mode=0o700)
        self.mount = self.output / 'target-fs'
        self.mount.mkdir(mode=0o700)
        command(self.output, 'mount', ['mount', '-t', 'tmpfs', '-o', 'size=4M,mode=0700,nodev,nosuid,noexec', 'm3-' + name, str(self.mount)])
        self.backup = Path('/mnt/constellation-m3-backup') / name
        self.backup.mkdir(mode=0o700)
        command(self.output, 'mount-backup', ['mount', '-t', 'tmpfs', '-o', 'size=8M,mode=0700,nodev,nosuid,noexec', 'm3-backup-' + name, str(self.backup)])
        self.fixture = self.mount / 'operation'
        self.generator = route.ROOT / 'labelwatch/scripts/m3_fixture_enrollment.py'
        command(self.output, 'initialize', ['/usr/bin/python3', str(self.generator), 'initialize', '--target', str(self.fixture), '--backup', str(self.backup), '--revision', revision])
        self.base = json.loads((self.fixture / 'fixture-base.json').read_bytes())
        if name == 'cleanup-no-margin':
            # Fixture budget is fixed before any step is sealed. Leave room for
            # actual refusal evidence while requiring a larger operating margin.
            self.base['operating_margin'] = 32768
            (self.fixture / 'fixture-base.json').write_bytes(route.canonical(self.base))
        self.previous, self.staged, self.pre_receipt = None, None, None
        self.actions, self.writers, self.paused = [], None, []

    def capture(self, phase, label, margin=None):
        output = self.output / label
        args = ['/usr/bin/python3', str(route.ROOT / 'labelwatch/scripts/m3_fixture_capture.py'),
                '--fixture', str(self.fixture), '--staged', str(self.staged),
                '--output', str(output), '--nq', str(self.nq), '--nq-sha256', self.nq_sha,
                '--phase', phase, '--acquisition-budget-seconds', '20']
        if phase == 'post':
            args += ['--pre-ingest-receipt', str(self.pre_receipt)]
        if margin is not None:
            args += ['--required-free-bytes', str(margin)]
        command(self.output, label, args, timeout=45)
        return output

    def admit(self, action, cut=None, *, prerequisite=True, cleanup_override=None):
        number = len(self.actions)
        label = f'{number:02d}-{action}'
        args = ['/usr/bin/python3', str(self.generator), 'seal', '--target', str(self.fixture),
                '--action', action, '--source-root', str(route.ROOT / 'labelwatch'), '--python', str(Path('/usr/bin/python3').resolve())]
        if self.previous is not None:
            args += ['--previous', str(self.previous)]
        if cut:
            args += ['--interruption-cut', cut]
        raw, code = command(self.output, label + '-seal', args, required=prerequisite)
        if code != 0:
            self.actions.append({'action': action, 'cut': cut, 'seal_exit': code, 'status': 'NOT_ADMITTED'})
            return None
        candidate = json.loads(raw)
        if self.name == 'cleanup-no-margin' and action == 'release':
            stat = os.statvfs(self.mount)
            if not os.path.ismount(self.mount) or stat.f_blocks * stat.f_frsize > 4 * 1024 * 1024:
                raise RuntimeError('bounded dedicated filesystem required')
            remaining = max(0, stat.f_bavail * stat.f_frsize - 16384)
            with (self.mount / 'final-margin-reservation').open('xb') as stream:
                while remaining:
                    size = min(remaining, 65536)
                    stream.write(b'X' * size)
                    remaining -= size
                stream.flush()
                os.fsync(stream.fileno())
        cleanup = None
        if action == 'cleanup':
            if self.pre_receipt is None:
                self.pre_receipt = self.capture('pre', label + '-pre') / 'pre-receipt.json'
            cleanup = self.capture('cleanup', label + '-native')
            if cleanup_override == 'missing':
                # Keep original capture, remove only the selected input by using
                # an absent sibling; this is an intake refusal, not missing facts.
                cleanup = self.output / 'absent-cleanup-input'
            elif cleanup_override == 'stale':
                # Wait for the actual admitted currentness to expire, do not
                # edit/re-sign timestamps or fabricate a historical receipt.
                time.sleep(31)
            elif cleanup_override == 'substituted':
                copied = self.output / 'substituted-cleanup-input'
                shutil.copytree(cleanup, copied)
                request = json.loads((copied / 'cleanup-request.json').read_bytes())
                request['required_free_bytes'] = 1  # closed request must reject misplaced field
                (copied / 'cleanup-request.json').write_bytes(route.canonical(request))
                cleanup = copied
            elif cleanup_override == 'foreign':
                donor = Case('cleanup-foreign-operation-receipt-donor', self.revision, self.nq, self.nq_sha)
                donor.run()
                cleanup = donor.capture('cleanup', 'foreign-native')
                if json.loads((cleanup / 'cleanup-receipt.json').read_bytes())['disposition'] != 'ESTABLISHED':
                    raise RuntimeError('fresh foreign-operation prerequisite was not established')
                (self.output / 'DONOR.json').write_bytes(route.canonical({'directory': str(donor.output), 'receipt': str(cleanup / 'cleanup-receipt.json')}))
        destination = self.output / label
        candidate_path = Path(candidate['step']).parent / 'candidate.json'
        error = None
        try:
            code = route.execute(candidate_path, destination, cleanup)
        except (OSError, ValueError, RuntimeError) as failure:
            code, error = 'INTAKE_REFUSED_OR_OUTCOME_UNKNOWN', str(failure)
        record = {'action': action, 'cut': cut, 'candidate': str(candidate_path),
                  'evidence': str(destination), 'driver_exit': code, 'error': error}
        self.actions.append(record)
        (self.output / (label + '-occurrence.json')).write_bytes(route.canonical(record))
        terminal = Path(candidate['expected_result'])
        if terminal.exists():
            result = json.loads(terminal.read_bytes())
            if result['step_sha256'] != candidate['step_sha256'] or result['action'] != action:
                raise RuntimeError('helper completion belongs to another step')
            self.previous = terminal
            if action == 'stage':
                self.staged = terminal
        elif action == 'cleanup' and cut == 'after_cleanup_unlink':
            self.previous = terminal.with_name(candidate['step_sha256'] + '.started.json')
        elif prerequisite:
            raise RuntimeError('required helper completion absent; no continuation')
        return candidate

    def start_writers(self, failing=False):
        self.writers = setup.enroll_case_writers(self.fixture, self.output / 'writer-enrollment', failing)
        for role, item in self.writers.items():
            command(self.output, 'writer-start-' + role, ['systemctl', 'start', item['unit']], required=not (failing and role == 'main'), timeout=15)
        helper, hold = application()
        ready = hold.paths(self.base['source'])[0].parent / 'ready'
        observed = {}
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            for role, item in self.writers.items():
                records = list(ready.glob(role + '-*.ready.json'))
                if len(records) != 1:
                    continue
                value, _ = helper.read_record(records[0])
                pid = int(subprocess.check_output(['systemctl', 'show', item['unit'], '--property=MainPID', '--value'], text=True).strip())
                if value['pid'] == pid and hold.process_start_ticks(pid) == value['start_ticks']:
                    observed[role] = value
            if len(observed) == (1 if failing else 2):
                break
            time.sleep(0.05)
        for role, item in self.writers.items():
            command(self.output, 'writer-state-' + role, ['systemctl', 'show', item['unit'], '--property=ActiveState', '--property=SubState', '--property=Result', '--property=ExecMainStatus', '--property=MainPID', '--property=NRestarts'])
            command(self.output, 'writer-journal-' + role, ['journalctl', '--no-pager', '-u', item['unit'], '--output=cat'])
        (self.output / 'WRITER-READINESS.json').write_bytes(route.canonical(observed))
        if set(observed) != ({'discovery'} if failing else {'main', 'discovery'}):
            raise RuntimeError('exact expected writer readiness not established')

    def mutate(self):
        mutate_closed_source(self.base['source'])

    def run(self):
        action, cut = ('verify-service', None) if self.name.endswith('-donor') else cases()[self.name]
        for previous in PREVIOUS[action]:
            if previous == 'writers':
                self.start_writers(self.name == 'writer-start-failure')
            elif previous == 'cleanup-cut':
                self.admit('cleanup', 'after_cleanup_unlink', prerequisite=False)
            else:
                self.admit(previous)
        if self.name in ('equal-count-content', 'post-start-verification'):
            self.mutate()
        if self.name == 'pathname-recovery':
            original = Path(self.base['original'])
            saved = original.with_name('retained-original.sqlite')
            original.rename(saved)
            shutil.copyfile(saved, original)
        if self.name == 'unknown-resumption':
            _, hold = application()
            for value in json.loads((self.output / 'WRITER-READINESS.json').read_bytes()).values():
                if hold.process_start_ticks(value['pid']) != value['start_ticks']:
                    raise RuntimeError('writer process changed before pause')
                os.kill(value['pid'], signal.SIGSTOP)
                self.paused.append(value)
            (self.output / 'PAUSED.json').write_bytes(route.canonical({'state': 'PAUSED_NOT_EXECUTING', 'processes': self.paused}))
        lock = None
        if self.name == 'concurrent-lock':
            lock = open(self.fixture / 'journal/lock', 'a+b')
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        override = {'cleanup-missing-receipt': 'missing', 'cleanup-stale-receipt': 'stale', 'cleanup-substituted-receipt': 'substituted', 'cleanup-foreign-operation-receipt': 'foreign'}.get(self.name)
        try:
            self.admit(action, cut, prerequisite=False, cleanup_override=override)
        finally:
            if lock is not None:
                lock.close()
        if self.name in ('normal', 'fact-enactment-disagreement', 'post-write-stale-rollback'):
            helper, _ = application()
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if helper.reconcile(self.base)['post_release_generation_observed']:
                    break
                time.sleep(0.05)
            else:
                raise RuntimeError('actual post-release generation not observed')
            margin = (os.statvfs(self.mount).f_bavail * os.statvfs(self.mount).f_frsize + 1) if self.name == 'fact-enactment-disagreement' else None
            self.capture('post', 'post', margin)
            if self.name == 'post-write-stale-rollback':
                self.admit('rollback-pre-ingest', prerequisite=False)
        helper, _ = application()
        (self.output / 'RECOVERY-OBSERVATION.json').write_bytes(route.canonical(helper.reconcile(self.base)))
        (self.output / 'PRODUCER.json').write_bytes(route.canonical({'schema': 'constellation.m3-later-case-producer/v1',
            'case': self.name, 'revision': self.revision, 'nq_sha256': self.nq_sha,
            'actions': self.actions, 'terminal_claim': 'AWAITING_INDEPENDENT_CHECK',
            'paused': self.paused, 'teardown': 'NOT_RUN_RETAINED_CASE_ONLY'}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', choices=sorted(cases()), required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--nq', type=Path, required=True)
    parser.add_argument('--nq-sha256', required=True)
    args = parser.parse_args()
    Case(args.case, args.revision, args.nq, args.nq_sha256).run()
