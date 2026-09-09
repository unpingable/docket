#!/usr/bin/env python3
"""Fixed local-VM cold-cohort qualification, not a deployment controller.

Each invocation is an explicitly ordered fixture step. Phase records describe
completed commands; they confer no authority and never trigger automatic retry.
"""
import hashlib
import json
import os
import pathlib
import pwd
import shutil
import subprocess
import sys
import time
from day_two_restore import logical_manifest

ROOT = pathlib.Path('/var/lib/nq/m4-cold')
CONFIG = pathlib.Path('/etc/nq/nq.toml')
OLD_BINARY = '03778e0e9ea19366c920c98d041436d30f92b83abf0745766ef446c811e65cd9'
NEW_BINARY = 'a672ef6aad196e989989a62bb0281e81a8918be8d824fe1caf94913505822427'
OLD_PACKAGE = '0fd1ce9e1be48b56ba5e526993a94c4682499bb9dbd9304dffd4500c01603636'
NEW_PACKAGE = '8c41c2b4d320770c6a04b09649b4c229fb00e86f64689c3c2f3f1c2a4d4e3019'


def digest(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def main(mode):
    assert os.geteuid() == 0
    account = pwd.getpwnam('nq')
    if mode == 'prepare':
        assert not ROOT.exists() and not CONFIG.exists()
        ROOT.mkdir(mode=0o700)
        os.chown(ROOT, account.pw_uid, account.pw_gid)
    records = []

    def save(name, value):
        path = ROOT / name
        pending = ROOT / (name + '.writing')
        with pending.open('x') as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, path)
        directory_fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    def call(label, argv, expected=0):
        result = subprocess.run(argv, capture_output=True, timeout=120)
        (ROOT / (label + '.stdout')).write_bytes(result.stdout)
        (ROOT / (label + '.stderr')).write_bytes(result.stderr)
        records.append({'case': label, 'exit': result.returncode})
        save(mode + '-commands.json', records)
        assert result.returncode == expected, (label, result.returncode, result.stderr[:4096])
        return result.stdout

    def nq(label, args, binary='/usr/bin/nq'):
        return call(label, ['runuser', '-u', 'nq', '--', binary, '--config', str(CONFIG), '--json', *args])

    def inactive(label):
        value = call(label, ['systemctl', 'show', 'nqd.service', '--property=ActiveState', '--value'])
        assert value.strip() == b'inactive'

    def stop(label):
        call(label, ['systemctl', 'stop', 'nqd.service'])
        inactive(label + '-inactive')

    def phase(expected):
        assert json.loads((ROOT / 'CHECKPOINT.json').read_text())['phase'] == expected
        inactive(mode + '-initial-inactive')

    def checkpoint(value, interrupt=False):
        record = {'phase': value, 'binary_sha256': digest('/usr/bin/nq'), 'service': 'STOPPED', 'automatic_resume': False}
        save('CHECKPOINT-' + value + '.json', record)
        save('CHECKPOINT.json', record)
        if interrupt:
            # Deterministic supervisor-loss boundary after a completed durable
            # step. No package operation is interrupted in the middle.
            os._exit(23)

    def install(package, expected_package, expected_binary, label):
        assert digest(package) == expected_package
        call(label, ['dpkg', '-i', package])
        assert digest('/usr/bin/nq') == expected_binary
        inactive(label + '-inactive')

    def config(store, admissions, watchers=False):
        if watchers:
            content = pathlib.Path('/etc/nq/operator-beta.toml').read_text()
            content = content.replace('/var/lib/nq/operator-beta.sqlite', str(store))
            content = content.replace('/var/lib/nq/operator-beta-admissions', str(admissions))
            content = content.replace('/run/nq/operator-beta.sock', '/run/nq/nqd.sock')
        else:
            content = 'schema="nq.config.v1"\ndatabase_path=' + json.dumps(str(store)) + '\nsocket_path="/run/nq/nqd.sock"\nadmissions_dir=' + json.dumps(str(admissions)) + '\nhelper_runtime_dir="/run/nq/helpers"\nwatchers=[]\n'
        CONFIG.write_text(content)
        os.chown(CONFIG, 0, account.pw_gid)
        CONFIG.chmod(0o640)

    def ready(label):
        deadline = time.monotonic() + 20
        attempt = 0
        while time.monotonic() < deadline:
            attempt += 1
            result = subprocess.run(['curl', '--max-time', '2', '--fail', '--silent', '--show-error', '--unix-socket', '/run/nq/nqd.sock', 'http://localhost/v3/status'], capture_output=True, timeout=3)
            (ROOT / f'{label}-{attempt}.stdout').write_bytes(result.stdout)
            (ROOT / f'{label}-{attempt}.stderr').write_bytes(result.stderr)
            if result.returncode == 0:
                assert json.loads(result.stdout)['schema'] == 'nq.status_snapshot.v3'
                return
            time.sleep(0.1)
        raise RuntimeError('no successful fresh owner response')

    try:
        if mode == 'prepare':
            stop('prepare-stop')
            assert digest('/home/betaoperator/m4-old-store.sqlite') == 'e6a442e199449093c105b85f1882a31b2ea64cf70d61b7f1a72e7635bdb7e153'
            shutil.copyfile('/home/betaoperator/m4-old-store.sqlite', ROOT / 'old.sqlite')
            os.chown(ROOT / 'old.sqlite', account.pw_uid, account.pw_gid)
            (ROOT / 'old.sqlite').chmod(0o600)
            install('/home/betaoperator/m4-old-nq.deb', OLD_PACKAGE, OLD_BINARY, 'old-install')
            config(ROOT / 'old.sqlite', ROOT / 'old-admissions')
            nq('old-config', ['config', 'check'])
            call('old-start', ['systemctl', 'start', 'nqd.service'])
            ready('old-ready')
            stop('old-stop')
            nq('old-archive', ['admin', 'archive', '--destination', str(ROOT / 'old-archive')])
            nq('old-archive-verify', ['admin', 'archive-verify', str(ROOT / 'old-archive')], str(ROOT / 'old-archive/bin/nq'))
            checkpoint('OLD_ARCHIVED', interrupt=True)
        elif mode == 'inspect':
            inactive('inspect-inactive')
            state = json.loads((ROOT / 'CHECKPOINT.json').read_text())
            assert digest('/usr/bin/nq') == state['binary_sha256']
            save('INSPECT-' + state['phase'] + '.json', {'phase': state['phase'], 'binary_matches': True, 'service_inactive': True, 'next_action_requires_explicit_step': True})
        elif mode in ('cut-one', 'cut-two'):
            phase('OLD_ARCHIVED' if mode == 'cut-one' else 'OLD_ROLLBACK_VERIFIED')
            install('/home/betaoperator/nq-ng.deb', NEW_PACKAGE, NEW_BINARY, mode + '-install')
            cohort = ROOT / mode
            cohort.mkdir(mode=0o700)
            os.chown(cohort, account.pw_uid, account.pw_gid)
            config(cohort / 'nq.sqlite', cohort / 'admissions', watchers=True)
            manifest = json.loads((ROOT / 'old-archive/ARCHIVE.json').read_text())['manifest_sha256']
            nq(mode + '-init', ['init', '--legacy-manifest-digest', manifest])
            assert (cohort / 'admissions').is_dir()
            assert not list((cohort / 'admissions').iterdir())
            save(mode + '-baseline.json', logical_manifest(cohort / 'nq.sqlite'))
            checkpoint('NEW_ONE_PREACTIVATION' if mode == 'cut-one' else 'NEW_TWO_PREACTIVATION', interrupt=True)
        elif mode == 'rollback':
            phase('NEW_ONE_PREACTIVATION')
            assert logical_manifest(ROOT / 'cut-one/nq.sqlite') == json.loads((ROOT / 'cut-one-baseline.json').read_text())
            assert not list((ROOT / 'cut-one/admissions').iterdir())
            install('/home/betaoperator/m4-old-nq.deb', OLD_PACKAGE, OLD_BINARY, 'rollback-old-install')
            nq('rollback-absent-restore', ['restore', str(ROOT / 'old-archive/db/nq.db'), str(ROOT / 'rollback.sqlite')])
            assert logical_manifest(ROOT / 'rollback.sqlite') == logical_manifest(ROOT / 'old-archive/db/nq.db')
            config(ROOT / 'rollback.sqlite', ROOT / 'rollback-admissions')
            nq('rollback-reopen', ['status', 'export'])
            call('rollback-start', ['systemctl', 'start', 'nqd.service'])
            ready('rollback-ready')
            stop('rollback-stop')
            checkpoint('OLD_ROLLBACK_VERIFIED')
        elif mode == 'post-cut':
            phase('NEW_TWO_PREACTIVATION')
            # Host performed fresh owner admission/execution through the
            # existing constrained helper launcher, not this fixture script.
            assert list((ROOT / 'cut-two/admissions').iterdir())
            assert logical_manifest(ROOT / 'cut-two/nq.sqlite') != json.loads((ROOT / 'cut-two-baseline.json').read_text())
            checkpoint('POST_CUT_FORWARD_ONLY', interrupt=True)
        elif mode == 'finish':
            phase('POST_CUT_FORWARD_ONLY')
            assert digest('/usr/bin/nq') == NEW_BINARY
            # Retain both cohorts. Do not issue any old restore after new work.
            nq('forward-status', ['status', 'export'])
            nq('forward-backup', ['backup', str(ROOT / 'forward-backup.sqlite')])
            config(ROOT / 'cut-two/nq.sqlite', ROOT / 'cut-two/admissions')
            # Service-readiness test only: fresh admission/diagnostic above was
            # one-shot. Do not silently start scheduled collection here.
            call('forward-start', ['systemctl', 'start', 'nqd.service'])
            ready('forward-ready')
            stop('forward-stop')
            nq('final-old-archive-verify', ['admin', 'archive-verify', str(ROOT / 'old-archive')], str(ROOT / 'old-archive/bin/nq'))
            save('RESULT.json', {'schema': 'constellation.m4.cold_cohort_fixture.v1', 'disposition': 'COLD_COHORT_VM_DEMONSTRATED', 'old_binary_sha256': OLD_BINARY, 'new_binary_sha256': NEW_BINARY, 'fresh_admission': True, 'preactivation_rollback': 'EXACT_OLD_BINARY_AND_ROWS_REOPENED', 'post_cut_rollback': 'NOT_EXECUTED_FORWARD_ONLY', 'interruption_scope': 'PROCESS_EXIT_AFTER_COMPLETED_STEPS_NOT_MID_DPKG', 'history_authorizes_effects': False, 'human_trial': 'NOT_RUN'})
            CONFIG.unlink()
        else:
            raise ValueError('unknown fixed qualification step')
    except BaseException:
        stop_result = subprocess.run(['systemctl', 'stop', 'nqd.service'], capture_output=True, timeout=90)
        save(mode + '-FAILURE.json', {'completed_commands': records, 'stop_exit': stop_result.returncode, 'automatic_resume': False})
        print((ROOT / (mode + '-FAILURE.json')).read_text(), file=sys.stderr)
        raise


if __name__ == '__main__':
    main(sys.argv[1])
