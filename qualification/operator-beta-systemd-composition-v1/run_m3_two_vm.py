#!/usr/bin/env python3
"""M3-only extension of the existing two-VM composition qualification lifecycle."""
import ast
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

import run_composed_two_vm as composition
import m3_vm_inputs as inputs
from m3_case_check import read, native_reexecution
from m3_guest_matrix import inventory

HERE = Path(__file__).resolve().parent
# Frozen checker descendant fills these; producer records its actual subject.
PRODUCER_HEAD = 'UNFROZEN'
PRODUCER_TREE = 'UNFROZEN'
M3_ROOT = '/var/lib/constellation-m3'
MAX_ARCHIVE = 512 * 1024 * 1024
MATRIX_UNIT = 'constellation-m3-matrix.service'
HOST_RELATIVE = 'qualification/operator-beta-systemd-composition-v1/run_m3_two_vm.py'


def require(value, reason):
    if not value:
        raise ValueError(reason)


def source_fact(root, expected):
    root = Path(root)
    require(root.resolve(strict=True) == root, 'physical source tree required')
    head = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
    require(head == expected and len(expected) == 40, 'source revision differs')
    require(not subprocess.check_output(['git', '-C', str(root), 'status', '--porcelain']), 'source tree dirty')
    tree = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD^{tree}'], text=True).strip()
    return {'head': head, 'tree': tree}


def checker_contract(producer_root, checker_root, producer_head, checker_head):
    """B may change only the two producer pins; every imported source is A's."""
    source = source_fact(producer_root, producer_head)
    checker = source_fact(checker_root, checker_head)
    require(producer_root != checker_root, 'separate checker tree required')
    changed = subprocess.check_output(['git', '-C', str(checker_root), 'diff', '--name-only',
        producer_head, checker_head], text=True).splitlines()
    require(changed == [HOST_RELATIVE], 'checker differs outside exact host pins')
    candidate = (checker_root / HOST_RELATIVE).read_text()
    parsed = ast.parse(candidate)
    values = {node.targets[0].id: ast.literal_eval(node.value) for node in parsed.body
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id in ('PRODUCER_HEAD', 'PRODUCER_TREE')}
    require(values == {'PRODUCER_HEAD': source['head'], 'PRODUCER_TREE': source['tree']}, 'checker producer pins differ')
    for name, value in values.items():
        candidate = candidate.replace(name + " = '" + value + "'", name + " = 'UNFROZEN'")
    require(candidate == (producer_root / HOST_RELATIVE).read_text(), 'checker source differs beyond two literal pins')
    return source, checker


def archive_source(root, head, destination):
    with destination.open('xb') as stream:
        subprocess.run(['git', '-C', str(root), 'archive', '--format=tar', head], stdout=stream, check=True)
    return composition.sha256(destination)


def extract(archive, destination):
    require(archive.is_file() and not archive.is_symlink() and archive.stat().st_size <= MAX_ARCHIVE, 'bounded regular M3 archive required')
    destination.mkdir(mode=0o700)
    with tarfile.open(archive, 'r:') as stream:
        members = stream.getmembers()
        require(0 < len(members) <= 30000 and sum(item.size for item in members) <= MAX_ARCHIVE, 'M3 archive limit')
        names = set()
        for item in members:
            relative = Path(item.name.removeprefix('./'))
            require(not relative.is_absolute() and '..' not in relative.parts and str(relative) not in names,
                    'ambiguous M3 archive path')
            require(item.isfile() or item.isdir(), 'M3 archive nonregular entry')
            names.add(str(relative))
        stream.extractall(destination, filter='data')


def producer_class(nq):
    parent = composition.producer_class(nq)
    class M3Producer(parent):
        m3_started = False

        def state(self, phase, next_action, **facts):
            facts.update(schema='constellation.m3-vm-recovery/v1', campaign='OPERATOR-BETA-M3-FIXTURE',
                expected_terminal_records=['M3-RESULT.json + M3-ARTIFACTS.json',
                    'or REFUSAL.json + RECOVERY.json + bounded M3-FAILURE-CAPTURE.json when reachable; no automatic retry'])
            super().state(phase, next_action, **facts)

        def preflight(self):
            facts = super().preflight()
            facts['m3_inputs'] = inputs.verify({'nq_package': self.args.nq_deb, 'nq_receipt': self.args.nq_receipt,
                'driver_package': self.args.driver_deb, 'driver_receipt': self.args.driver_receipt,
                'composition_package': self.args.composition_deb, 'composition_receipt': self.args.composition_receipt,
                'websockets': self.args.websockets})
            facts['m3_sources'] = {'application': source_fact(self.args.app_source, inputs.APP_HEAD),
                'producer': source_fact(HERE.parents[1], self.args.composition_subject),
                'checker': source_fact(self.args.checker_source, self.args.checker_subject)}
            checker_contract(HERE.parents[1], self.args.checker_source,
                self.args.composition_subject, self.args.checker_subject)
            require(shutil.disk_usage(self.output.parent).free > 25769803776, 'global 24GiB floor')
            return facts

        def create_run(self, facts):
            super().create_run(facts)
            manifest = {'schema': 'constellation.m3-source-custody/v1', 'sources': facts['m3_sources'], 'archives': {}}
            for role, root, head in [('application', self.args.app_source, inputs.APP_HEAD),
                    ('producer', HERE.parents[1], self.args.composition_subject),
                    ('checker', self.args.checker_source, self.args.checker_subject)]:
                name = 'm3-' + role + '.tar'
                manifest['archives'][name] = archive_source(root, head, self.output / 'input' / name)
                require(source_fact(root, head) == facts['m3_sources'][role], 'source changed during archival')
            for name, role, source in [('driver.deb', 'driver_package', self.args.driver_deb),
                    ('websockets.whl', 'websockets', self.args.websockets),
                    ('driver-receipt.json', 'driver_receipt', self.args.driver_receipt),
                    ('nq-receipt.json', 'nq_receipt', self.args.nq_receipt)]:
                destination = self.output / 'input' / ('m3-' + name)
                shutil.copyfile(source, destination)
                manifest['archives'][destination.name] = composition.sha256(destination)
                require(manifest['archives'][destination.name] == inputs.PINS[role], 'copied M3 input changed')
            manifest['premise'] = 'FROZEN_GIT_ARCHIVE_AND_ROOT_ENROLLED_IMPORT_CUSTODY_NOT_AUTHENTICATED_REMOTE_ATTESTATION'
            self.m3_custody = manifest
            nq.atomic_write(self.output / 'evidence/m3-source-custody.json', nq.canonical(manifest) + b'\n', 0o400)

        def install_m3_inputs(self, target):
            files = [self.output / 'input' / name for name in self.m3_custody['archives']]
            self.scp_to(target, files, '/home/betaoperator/')
            checks = ''.join(digest + '  /home/betaoperator/' + name + '\n' for name, digest in self.m3_custody['archives'].items())
            command = 'set -eu; printf %s ' + shlex.quote(checks) + ' | sha256sum -c -; '
            command += 'sudo mkdir /opt/constellation-m3 /opt/constellation-m3/labelwatch /opt/constellation-m3/producer /opt/constellation-m3/checker; '
            for role, directory in [('application', 'labelwatch'), ('producer', 'producer'), ('checker', 'checker')]:
                command += f'sudo tar --no-same-owner -xf /home/betaoperator/m3-{role}.tar -C /opt/constellation-m3/{directory}; '
            command += 'sudo cp /home/betaoperator/m3-websockets.whl /opt/constellation-m3/websockets.whl; '
            command += 'sudo chmod -R go-w /opt/constellation-m3; sudo dpkg -i /home/betaoperator/m3-driver.deb; '
            command += 'sudo python3 /opt/constellation-m3/producer/qualification/operator-beta-systemd-composition-v1/m3_guest_setup.py ' + inputs.APP_HEAD
            self.ssh(target, command)
            self.complete_phase('m3_inputs_enrolled', 'run finite M3 batch after completed ordinary composition/reboot witness')

        def teardown(self, control, target):
            try:
                self.m3_then_teardown(control, target)
            except Exception as error:
                self.capture_failure(target, error)
                raise

        def capture_failure(self, target, cause):
            """Best-effort bounded observation, never quiescence/recovery authority.

            Default host systemd control-group teardown can stop QEMU on exit.
            Preserve reachable bytes first; never promise continuing live guests.
            This collection has its own <=150s bound after the run deadline.
            """
            record = {'schema': 'constellation.m3-failure-capture/v1', 'cause': str(cause),
                'state': 'NOT_OBSERVABLE', 'live_guest_after_host_exit': 'NOT_ESTABLISHED',
                'content_cut': 'BEST_EFFORT_CONCURRENT_OBSERVATION_NOT_QUALIFIED_SNAPSHOT',
                'actions': 'READ_ONLY_CAPTURE_NO_UNIT_STOP_NO_RETRY', 'commands': []}
            output = self.output / 'evidence/m3-failure'
            try:
                output.mkdir(mode=0o700)
                commands = [('owner-state', 'sudo systemctl show ' + MATRIX_UNIT +
                    ' -p InvocationID -p MainPID -p ActiveState -p SubState -p ExecMainStatus; '
                    'sudo journalctl -u ' + MATRIX_UNIT + ' --no-pager -n 200'),
                    ('archive', "sudo sh -c 'test ! -e /home/betaoperator/m3-failure.tar || exit 2; "
                    "ulimit -f 1048576; timeout 40 tar -cf /home/betaoperator/m3-failure.tar "
                    "-C / var/lib/constellation-m3 mnt/constellation-m3-backup; "
                    "code=$?; chmod 0400 /home/betaoperator/m3-failure.tar; exit $code'")]
                for label, command in commands:
                    with (output / (label + '.stdout')).open('xb') as stdout, (output / (label + '.stderr')).open('xb') as stderr:
                        observed = subprocess.run(target.ssh_base() + [command], stdout=stdout, stderr=stderr, timeout=50)
                    record['commands'].append({'label': label, 'exit': observed.returncode})
                with (output / 'retained-partial.tar').open('xb') as stream, (output / 'copy.stderr').open('xb') as stderr:
                    observed = subprocess.run(target.ssh_base() +
                        ['sudo head -c ' + str(MAX_ARCHIVE) + ' /home/betaoperator/m3-failure.tar'],
                        stdout=stream, stderr=stderr, timeout=50)
                record['commands'].append({'label': 'copy', 'exit': observed.returncode})
                record['state'] = ('PARTIAL_BYTES_RETAINED_NOT_TERMINAL_QUALIFICATION'
                    if observed.returncode == 0 and (output / 'retained-partial.tar').stat().st_size > 0
                    else 'NOT_OBSERVABLE_RETAINED_COLLECTION_ATTEMPTS')
                record['archive_sha256'] = composition.sha256(output / 'retained-partial.tar')
            except Exception as error:
                record['collection_error'] = str(error)
            finally:
                nq.atomic_write(self.output / 'M3-FAILURE-CAPTURE.json', nq.canonical(record) + b'\n', 0o400)

        def m3_then_teardown(self, control, target):
            # The ordinary witness is complete. Do not inherit M4 day-two/cold
            # hooks; this distinct derivative executes only M3 before teardown.
            self.m3_started = True
            # Backup tmpfs and held writer enrollment must follow the ordinary
            # reboot; creating them in install_inputs would lose the mount cut.
            self.install_m3_inputs(target)
            checker = '/opt/constellation-m3/checker/qualification/operator-beta-systemd-composition-v1/m3_case_check.py'
            checker_sha = composition.sha256(self.args.checker_source / 'qualification/operator-beta-systemd-composition-v1/m3_case_check.py')
            batch = '/opt/constellation-m3/producer/qualification/operator-beta-systemd-composition-v1/m3_guest_matrix.py'
            self.state('m3_matrix_starting', 'start exactly one guest systemd batch; never retry')
            self.ssh(target, 'sudo systemd-run --unit=' + MATRIX_UNIT + ' --property=Type=exec --property=RemainAfterExit=yes '
                '--property=RuntimeMaxSec=8100 /usr/bin/python3 ' + batch + ' --checker ' + checker + ' --checker-sha256 ' + checker_sha)
            initial = None
            deadline = time.monotonic() + 8100
            while True:
                observed = self.ssh(target, 'sudo systemctl show ' + MATRIX_UNIT + ' -p InvocationID -p MainPID -p ActiveState -p SubState -p ExecMainStatus')
                state = dict(line.split('=', 1) for line in observed.stdout.decode().splitlines())
                if initial is None:
                    initial = state['InvocationID']
                    require(len(initial) == 32, 'guest batch invocation identity absent')
                require(state['InvocationID'] == initial, 'guest batch invocation changed')
                self.state('m3_matrix_running', 'inspect existing batch; no restart', m3_guest_process=state)
                if state['SubState'] == 'exited' or state['ActiveState'] in ('failed', 'inactive'):
                    require(state['SubState'] == 'exited' and state['ExecMainStatus'] == '0', 'M3 batch failed; capture original state without retry')
                    break
                require(time.monotonic() < deadline, 'M3 batch wait expired; capture original state without retry')
                time.sleep(5)
            # Backup root contains the unused setup fixture plus per-case mounts
            # already archived/unmounted by the checked batch. Preserve it too.
            self.ssh(target, 'set -eu; sudo systemctl stop labelwatch-m3-main.service labelwatch-m3-discovery.service; '
                'sudo tar -cf /var/lib/constellation-m3/setup-backup.tar -C /mnt/constellation-m3-backup .; '
                'sudo umount /mnt/constellation-m3-backup; '
                'sudo tar -cf /home/betaoperator/m3-evidence.tar -C /var/lib/constellation-m3 .; '
                'sudo chown betaoperator:betaoperator /home/betaoperator/m3-evidence.tar; chmod 0400 /home/betaoperator/m3-evidence.tar')
            archive = self.output / 'evidence/m3-evidence.tar'
            self.scp_from(target, '/home/betaoperator/m3-evidence.tar', archive)
            extract(archive, self.output / 'evidence/m3')
            check_matrix(self.output / 'evidence/m3')
            self.ssh(target, 'set -eu; sudo systemctl stop ' + MATRIX_UNIT + '; sudo dpkg -r constellation-m3-driver; '
                'sudo dpkg -r ' + composition.COMPOSITION_PACKAGE_NAME + '; '
                'sudo rm -rf /var/lib/constellation-operator-beta-composition; '
                'test ! -e /usr/libexec/constellation-operator-beta/m3-composition-driver')
            self.complete_phase('m3_matrix_checked_and_retained', 'perform existing NQ package and VM teardown')
            nq.Producer.teardown(self, control, target)

        def terminate_guests(self):
            if self.m3_started:
                self.state('m3_failed_no_explicit_guest_termination', 'inspect captured state; host service may stop guests on exit; no retry')
                return
            super().terminate_guests()

        def seal(self):
            key = self.output / 'runtime/id_ed25519'
            if key.exists():
                key.unlink()
            result = {'schema': 'constellation.m3-governed-vm-result/v1', 'run_id': self.run_id,
                'producer': self.input_facts['m3_sources']['producer'], 'checker': self.input_facts['m3_sources']['checker'],
                'disposition': 'FINITE_GOVERNED_FIXTURE_MATRIX_COMPLETED', 'count': len(inventory()),
                'completed_at': nq.utc_now(), 'production': 'NOT_RUN', 'deployment': 'NOT_RUN',
                'controller_loss': 'NOT_RUN_SEPARATE_GATE', 'independent_review': 'REQUIRED',
                'retained_guest_files': 'STOPPED_CASE_CONTENT_ARCHIVES_NOT_LIVE_INODE_CUSTODY',
                'teardown_scope': 'CASE_UNITS_STOPPED_MOUNTS_ARCHIVED_AND_UNMOUNTED_PACKAGES_REMOVED_GUESTS_OFF;SOURCE_AND_UNIT_FILES_REMAIN_IN_OFFLINE_GUEST_DISKS'}
            self.last_completed = 'sealed'
            self.state('sealed', 'independent M3 evidence reopening', terminal_disposition=result['disposition'])
            manifest = make_manifest(self.output)
            nq.atomic_write(self.output / 'M3-ARTIFACTS.json', nq.canonical(manifest) + b'\n', 0o400)
            result['manifest_sha256'] = composition.sha256(self.output / 'M3-ARTIFACTS.json')
            nq.atomic_write(self.output / 'M3-RESULT.json', nq.canonical(result) + b'\n', 0o400)
    return M3Producer


def make_manifest(root):
    files = []
    for path in sorted(root.rglob('*')):
        require(not path.is_symlink(), 'manifest refuses symlink')
        if path.is_file() and path.relative_to(root).as_posix() not in {'M3-RESULT.json', 'M3-ARTIFACTS.json'}:
            files.append({'path': str(path.relative_to(root)), 'bytes': path.stat().st_size, 'sha256': composition.sha256(path)})
    return {'schema': 'constellation.m3-vm-manifest/v1', 'files': files}


def check_teardown(case):
    teardown = read(case / 'TEARDOWN.json')
    require(teardown['status'] == 'SCOPED_STOP_AND_ARCHIVE' and teardown['unmount_exit'] == teardown['backup_unmount_exit'] == 0, 'case teardown incomplete')
    require(all(item['exit'] == 0 for item in teardown['units']), 'recorded unit stop incomplete')
    require(composition.sha256(case / 'retained-filesystems.tar') == teardown['archive_sha256'], 'retained case bytes differ')


def check_matrix(root, binary=None):
    result = read(root / 'matrix/RESULT.json')
    require(result == {'disposition': 'FINITE_CASE_CHECKS_COMPLETED', 'count': len(inventory()),
        'independent_final_review': 'REQUIRED', 'production': 'NOT_RUN'}, 'matrix is incomplete')
    require(not (root / 'matrix/REFUSAL.json').exists(), 'matrix also records refusal')
    plan = read(root / 'matrix/PLAN.json')
    require(plan['cases'] == [list(item) for item in inventory()] and plan['application'] == inputs.APP_HEAD,
        'case plan differs from closed inventory')
    for index, (kind, name) in enumerate(inventory()):
        occurrence = root / 'matrix' / f'{index:02d}-{kind}-{name}'
        case = root / (kind + '-cases') / name
        completed = read(occurrence / 'COMPLETED.json')
        require(completed == {'case': name, 'checked': True, 'scoped_teardown': True}, 'case completion differs')
        require(read(occurrence / 'producer.exit.json') == {'exit': 0}, 'producer did not finish')
        require(read(occurrence / 'checker.exit.json') == {'exit': 0}, 'checker did not finish')
        checked = read(occurrence / 'checker.stdout')
        require(checked == read(case / 'INDEPENDENT-CHECK.json') and checked['case'] == name, 'case checker correspondence differs')
        require(checked['maintenance_qualification'] == 'CASE_CHECKS_COMPLETED_INDEPENDENT_REVIEW_STILL_REQUIRED', 'case check incomplete')
        targets = [(case, checked)]
        donor = case / 'DONOR.json'
        if donor.exists():
            recorded = Path(read(donor)['directory'])
            require(recorded == Path(M3_ROOT) / 'later-cases/cleanup-foreign-operation-receipt-donor', 'donor outside fixed case')
            target = root / recorded.relative_to(M3_ROOT)
            require(read(target / 'INDEPENDENT-CHECK.json') == checked['foreign_donor'], 'donor checker differs')
            targets.insert(0, (target, checked['foreign_donor']))
        for ordinal, (target, observation) in enumerate(targets):
            require(read(occurrence / ('teardown-' + str(ordinal) + '.exit.json')) == {'exit': 0}, 'teardown command failed')
            check_teardown(target)
            if binary is not None:
                actual = native_reexecution(target, binary, inputs.NQ_BINARY_SHA)
                for item in actual:
                    item['path'] = str(Path(M3_ROOT) / Path(item['path']).relative_to(root))
                require(actual == observation['native_reexecution'], 'native retained replay differs')


def check_run(root, nq):
    require(root.resolve(strict=True) == root and root.is_dir(), 'physical run root required')
    result = read(root / 'M3-RESULT.json')
    require(result['schema'] == 'constellation.m3-governed-vm-result/v1', 'not an M3 terminal')
    require(result['producer'] == {'head': PRODUCER_HEAD, 'tree': PRODUCER_TREE}, 'checker not bound to exact producer')
    require(source_fact(HERE.parents[1], result['checker']['head']) == result['checker'], 'exact checker source differs')
    require(result['disposition'] == 'FINITE_GOVERNED_FIXTURE_MATRIX_COMPLETED' and result['count'] == len(inventory()), 'wrong M3 terminal')
    require(result['production'] == result['deployment'] == 'NOT_RUN' and result['independent_review'] == 'REQUIRED'
        and result['controller_loss'] == 'NOT_RUN_SEPARATE_GATE', 'stronger scope asserted')
    manifest = root / 'M3-ARTIFACTS.json'
    require(composition.sha256(manifest) == result['manifest_sha256'], 'manifest identity differs')
    require(json.loads(manifest.read_bytes()) == make_manifest(root), 'physical inventory changed')
    with tempfile.TemporaryDirectory(prefix='m3-evidence-reopen.') as temporary:
        unpacked = Path(temporary) / 'evidence'
        extract(root / 'evidence/m3-evidence.tar', unpacked)
        require(make_manifest(unpacked) == make_manifest(root / 'evidence/m3'), 'archive/extracted evidence differ')
    custody = read(root / 'evidence/m3-source-custody.json')
    require(custody['sources']['producer'] == result['producer'] and custody['sources']['checker'] == result['checker']
        and custody['sources']['application']['head'] == inputs.APP_HEAD, 'source custody differs')
    for name, digest in custody['archives'].items():
        require(Path(name).name == name and composition.sha256(root / 'input' / name) == digest, 'source archive/input differs')
    for role, expected in [('producer', PRODUCER_HEAD), ('checker', result['checker']['head'])]:
        with tempfile.TemporaryDirectory(prefix='m3-source-reopen.') as temporary:
            require(archive_source(HERE.parents[1], expected, Path(temporary) / 'source.tar')
                == custody['archives']['m3-' + role + '.tar'], 'Git source/archive correspondence differs')
    for name, role in [('m3-driver.deb', 'driver_package'), ('m3-websockets.whl', 'websockets'),
            ('m3-driver-receipt.json', 'driver_receipt'), ('m3-nq-receipt.json', 'nq_receipt')]:
        require(composition.sha256(root / 'input' / name) == inputs.PINS[role], 'accepted copied input differs')
    nq_package = root / 'input/nq-ng_amd64.deb'
    require(composition.sha256(nq_package) == inputs.PINS['nq_package'], 'native package differs')
    with tempfile.TemporaryDirectory(prefix='m3-native-reopen.') as temporary:
        nq.run(['dpkg-deb', '-x', str(nq_package), temporary])
        check_matrix(root / 'evidence/m3', Path(temporary) / 'usr/bin/nq')
    composition.verify_composition_chain(root, result, nq)
    composition.verify_nq_and_teardown(root, result, nq)
    print('M3_VM_EVIDENCE_REOPENED_NOT_PRODUCTION')


def main():
    parser = composition.parser()
    run = parser._subparsers._group_actions[0].choices['run']
    for name in ('nq-receipt', 'driver-deb', 'driver-receipt', 'websockets', 'app-source', 'checker-source'):
        run.add_argument('--' + name, type=Path, required=True)
    run.add_argument('--checker-subject', required=True)
    args = parser.parse_args()
    nq = composition.load_module('nq_m3_lifecycle', args.nq_harness)
    composition.exact_repository(args.nq_harness, composition.NQ_HEAD, composition.NQ_TREE, nq)
    if args.command == 'check-run':
        check_run(args.path, nq)
    elif args.command == 'check-refusal':
        raise ValueError('M3 refusal requires retained guest/process reconciliation; no automatic recovery')
    else:
        producer_class(nq)(args).execute()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('M3 VM refused: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
