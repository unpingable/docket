#!/usr/bin/env python3
"""Fixed disposable-VM day-two procedure; run as root, never a host installer.

Requires the existing composition fixture's store and absent default config.
The service has zero scheduled watchers: it serves existing evidence only.
All lifecycle operations use the packaged owner entrypoints.
"""
import hashlib
import json
import os
import pathlib
import pwd
import subprocess
import sys
import time
from day_two_restore import logical_manifest

ROOT = pathlib.Path('/var/lib/nq/m4-day-two')
CONFIG = pathlib.Path('/etc/nq/nq.toml')
STORE = pathlib.Path('/var/lib/nq/operator-beta.sqlite')


def main():
    if os.geteuid() != 0 or not STORE.is_file() or CONFIG.exists() or ROOT.exists():
        raise RuntimeError('not a fresh enrolled disposable composition fixture')
    ROOT.mkdir(mode=0o700)
    account = pwd.getpwnam('nq')
    os.chown(ROOT, account.pw_uid, account.pw_gid)
    records = []

    def call(name, argv, success=True):
        result = subprocess.run(argv, capture_output=True, timeout=90)
        (ROOT / (name + '.stdout')).write_bytes(result.stdout)
        (ROOT / (name + '.stderr')).write_bytes(result.stderr)
        records.append({'case': name, 'exit': result.returncode})
        if (result.returncode == 0) != success:
            raise RuntimeError(f'{name}: unexpected exit {result.returncode}')
        return result.stdout

    def nq(name, args, success=True):
        return call(name, ['runuser', '-u', 'nq', '--', '/usr/bin/nq', '--config', str(CONFIG), '--json', *args], success)

    config = ('schema = "nq.config.v1"\n'
              'database_path = "/var/lib/nq/operator-beta.sqlite"\n'
              'socket_path = "/run/nq/nqd.sock"\n'
              'admissions_dir = "/var/lib/nq/operator-beta-admissions"\n'
              'helper_runtime_dir = "/run/nq/helpers"\n'
              'watchers = []\n').encode()

    def install_config(content):
        CONFIG.write_bytes(content)
        os.chown(CONFIG, 0, account.pw_gid)
        CONFIG.chmod(0o640)

    def active(name):
        state = call(name, ['systemctl', 'show', 'nqd.service', '--property=ActiveState', '--value'])
        assert state.strip() == b'active'

    def stopped(name):
        call(name, ['systemctl', 'stop', 'nqd.service'])
        state = call(name + '-state', ['systemctl', 'show', 'nqd.service', '--property=ActiveState', '--value'])
        assert state.strip() == b'inactive'

    def ready(name):
        # A pathname or Type=simple start is not a responding owner API.
        deadline = time.monotonic() + 20
        attempt = 0
        while time.monotonic() < deadline:
            attempt += 1
            result = subprocess.run(['curl', '--max-time', '2', '--fail', '--silent', '--show-error', '--unix-socket', '/run/nq/nqd.sock', 'http://localhost/v3/status'], capture_output=True, timeout=3)
            label = name + '-' + str(attempt)
            (ROOT / (label + '.stdout')).write_bytes(result.stdout)
            (ROOT / (label + '.stderr')).write_bytes(result.stderr)
            records.append({'case': label, 'exit': result.returncode})
            if result.returncode == 0:
                response = json.loads(result.stdout)
                assert response['schema'] == 'nq.status_snapshot.v3'
                return response
            time.sleep(0.1)
        raise RuntimeError(name + ': no successful fresh owner status response')

    try:
        stopped('initial-stop')
        install_config(config)
        nq('valid-config', ['config', 'check'])
        call('start', ['systemctl', 'start', 'nqd.service'])
        active('active-first')
        ready('inspect-first')
        call('restart', ['systemctl', 'restart', 'nqd.service'])
        active('active-after-restart')
        ready('inspect-after-restart')
        stopped('maintenance-stop')
        nq('backup', ['backup', str(ROOT / 'backup.sqlite')])
        nq('restore', ['restore', str(ROOT / 'backup.sqlite'), str(ROOT / 'restored.sqlite')])
        backup_manifest = logical_manifest(ROOT / 'backup.sqlite')
        assert logical_manifest(ROOT / 'restored.sqlite') == backup_manifest
        nq('restore-existing-refused', ['restore', str(ROOT / 'backup.sqlite'), str(ROOT / 'restored.sqlite')], False)
        # Verify using the actual owner against the restored store. This does
        # not restore an AG spend ledger or grant permission to repeat work.
        restored_config = config.replace(str(STORE).encode(), str(ROOT / 'restored.sqlite').encode())
        install_config(restored_config)
        nq('restored-status', ['status', 'export'])
        nq('already-current-upgrade', ['admin', 'upgrade', '--backup-directory', str(ROOT / 'upgrade-backups')])
        install_config(b'schema = [invalid\n')
        call('invalid-start-refused', ['systemctl', 'start', 'nqd.service'], False)
        call('invalid-start-unit-result', ['systemctl', 'show', 'nqd.service', '--property=Result', '--property=ExecMainStatus', '--property=ExecStartPre'])
        call('invalid-start-journal', ['journalctl', '--no-pager', '-u', 'nqd.service', '--output=short-iso', '-n', '100'])
        # Stop cancels the packaged Restart=on-failure loop. No automatic
        # repair or unknown state is reclassified as a successful start.
        stopped('invalid-config-stop')
        install_config(restored_config)
        call('reset-failed', ['systemctl', 'reset-failed', 'nqd.service'])
        nq('recovery-config-check', ['config', 'check'])
        call('recovery-start', ['systemctl', 'start', 'nqd.service'])
        active('recovery-active')
        ready('inspect-recovery')
        stopped('final-stop')
        call('journal', ['journalctl', '--no-pager', '-u', 'nqd.service', '--output=short-iso', '-n', '200'])
        result = {'schema': 'constellation.m4.day_two_fixture.v1', 'disposition': 'DAY_TWO_PROCEDURE_DEMONSTRATED', 'cases': records, 'service': 'nqd.service', 'scheduled_watchers': 0, 'upgrade': 'ALREADY_CURRENT_ONLY', 'binary_upgrade': 'NOT_RUN', 'restored_history_authorizes_effects': False, 'human_operator_trial': 'NOT_RUN', 'restored_typed_row_manifest': backup_manifest, 'source_store_sha256_after': hashlib.sha256(STORE.read_bytes()).hexdigest()}
        (ROOT / 'RESULT.json').write_text(json.dumps(result, sort_keys=True) + '\n')
        CONFIG.unlink()
    except BaseException:
        stop = subprocess.run(['systemctl', 'stop', 'nqd.service'], capture_output=True, timeout=90)
        interrupted = json.dumps({'disposition': 'RETAIN_AND_INSPECT_NO_AUTOMATIC_RESUME', 'completed_commands': records, 'stop_exit': stop.returncode}) + '\n'
        (ROOT / 'INTERRUPTED.json').write_text(interrupted)
        # SSH's existing host log retains this bounded failure record even
        # when systemd later stops the producer's guest process group.
        print(interrupted, file=sys.stderr)
        journal = subprocess.run(['journalctl', '--no-pager', '-u', 'nqd.service', '-n', '100'], capture_output=True, timeout=30)
        sys.stderr.buffer.write(journal.stdout[:65536])
        raise


if __name__ == '__main__':
    main()
