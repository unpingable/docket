#!/usr/bin/env python3
"""One exact enrolled M3 step through AG/Docket, never a retry controller."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path('/opt/constellation-m3')
DATA = Path('/var/lib/constellation-m3')
CUTS = ('before_started', 'after_started', 'before_terminal', 'after_terminal',
        'after_original_rename', 'after_replacement_rename', 'after_backup_sync',
        'after_restore_sync', 'after_staging_sync', 'before_cleanup_unlink',
        'after_cleanup_unlink', 'after_cleanup_authorized', 'after_release_record')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode() + b'\n'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def unit_name(candidate):
    sha = candidate['step_sha256']
    if not isinstance(sha, str) or len(sha) != 64 or any(c not in '0123456789abcdef' for c in sha):
        raise ValueError('exact lowercase step digest required')
    cut = candidate['qualification_interruption']
    restore = candidate['qualification_restore_substitution']
    if (cut is not None and cut not in CUTS) or type(restore) is not bool or (cut and restore):
        raise ValueError('unknown or conflicting qualification mode')
    if restore and candidate['action'] != 'stage':
        raise ValueError('restore substitution requires stage')
    suffix = '-q-' + cut if cut else '-q-restore-substitution' if restore else ''
    return 'labelwatch-relief-' + candidate['step_sha256'] + suffix + '.service'


def enrolled_unit(candidate):
    if candidate['unit'] != unit_name(candidate):
        raise ValueError('sealed qualification unit identity differs')
    path = Path(candidate['step']).parent / candidate['unit']
    raw = path.read_bytes()
    if digest(raw) != candidate['unit_sha256']:
        raise ValueError('generated unit bytes differ')
    # The application producer already sealed the qualification entrypoint.
    # Never alter command arguments or fragment bytes after that seal.
    return raw


def validate_candidate(candidate, step_raw):
    step = json.loads(step_raw)
    if (candidate['schema'] != 'labelwatch.m3-enrollment-candidate/v1'
            or step['schema'] != 'labelwatch.sqlite-relief-step/v1'
            or candidate['action'] != step['action']
            or candidate['source_revision'] != step['revision']
            or candidate['status'] != 'NOT_ENROLLED_NOT_AUTHORIZED'
            or digest(step_raw) != candidate['step_sha256']
            or candidate['unit'] != unit_name(candidate)):
        raise ValueError('candidate metadata differs from exact hashed step')
    if (Path(candidate['labelwatch_source']) != ROOT / 'labelwatch'
            or candidate['python'] != str(Path('/usr/bin/python3').resolve())
            or not Path(step['source']).is_relative_to(DATA)):
        raise ValueError('unrecognized source/interpreter/fixture target enrollment')
    if Path(candidate['expected_result']) != Path(step['journal']) / (candidate['step_sha256'] + '.completed.json'):
        raise ValueError('candidate terminal path differs from hashed step journal')
    command = candidate['python'] + ' -m labelwatch.maintenance_step'
    cut = candidate['qualification_interruption']
    if cut:
        command = candidate['python'] + ' ' + str(ROOT / 'labelwatch/qualification/m3-admission/interrupted_step.py')
    if candidate['qualification_restore_substitution']:
        command = candidate['python'] + ' ' + str(ROOT / 'labelwatch/qualification/m3-admission/restore_substitution_step.py')
    command += ' --step ' + candidate['step'] + ' --expected-sha256 ' + candidate['step_sha256']
    if cut:
        command += ' --cut ' + cut
    expected = ('[Unit]\nDescription=M3 exact enrolled fixture step\n'
        '[Service]\nType=oneshot\nUser=root\nGroup=root\nRestart=no\n'
        'TimeoutStartSec=25\nEnvironment=PYTHONPATH=' + str(ROOT / 'labelwatch/src') + '\n'
        'ExecStart=' + command + '\n[Install]\nWantedBy=multi-user.target\n').encode()
    if enrolled_unit(candidate) != expected:
        raise ValueError('sealed unit does not execute the exact enrolled step/mode')
    return step


def bind_cleanup_request(step, request):
    held = request['held_request']
    required = {'operation': step['operation'], 'source': step['source'], 'original': step['original'],
                'application_revision': step['revision'], 'original_identity': step['source_identity'],
                'expected_cut_sha256': digest(canonical(step['expected']).rstrip(b'\n')), 'phase': 'pre_ingest'}
    if any(held.get(key) != value for key, value in required.items()) or request['backup'] != step['backup'] or request['restore'] != step['restore']:
        raise ValueError('native cleanup request belongs to another step/operation/cut')
    ready = {role: json.loads(Path(path).read_bytes()) for role, path in step['ready_records'].items()}
    expected_writers = {role: {key: value[key] for key in ('pid', 'start_ticks')} for role, value in ready.items()}
    hold = {'schema': 'labelwatch.maintenance-hold/v1', 'operation': step['operation'], 'database': step['source'],
            'manifest_sha256': required['expected_cut_sha256'], 'application_revision': step['revision']}
    if set(ready) != {'main', 'discovery'}:
        raise ValueError('both exact writer roles required')
    for role, value in ready.items():
        if (set(value) != {'schema', 'operation', 'role', 'pid', 'start_ticks', 'hold_sha256', 'verification_sha256'}
                or value['schema'] != 'labelwatch.held-writer-ready/v1' or value['operation'] != step['operation']
                or value['role'] != role or value['hold_sha256'] != digest(canonical(hold).rstrip(b'\n'))
                or value['verification_sha256'] != required['expected_cut_sha256']):
            raise ValueError('readiness record belongs to another operation/role/hold/cut')
    if held['writer_identities'] != expected_writers or request['expected_hold_sha256'] != digest(canonical(hold).rstrip(b'\n')):
        raise ValueError('native cleanup writer/hold enrollment differs')
    current = step
    stage = replacement = None
    binding = digest(canonical({key: value for key, value in step.items() if key not in {'action', 'predecessor', 'predecessor_sha256', 'ready_records'}}).rstrip(b'\n'))
    for _ in range(4):
        previous_raw = Path(current['predecessor']).read_bytes()
        previous = json.loads(previous_raw)
        if digest(previous_raw) != current['predecessor_sha256'] or previous['operation'] != step['operation'] or previous['binding_sha256'] != binding:
            raise ValueError('cleanup predecessor custody differs')
        if replacement is None:
            replacement = previous['detail']['replacement']['identity']
        if previous['action'] == 'stage':
            stage = previous
            break
        input_path = Path(step['source']).parent / 'enrollment-candidates' / previous['step_sha256'] / 'step.json'
        raw = input_path.read_bytes()
        if digest(raw) != previous['step_sha256']:
            raise ValueError('predecessor input identity differs')
        current = json.loads(raw)
    if stage is None:
        raise ValueError('bounded exact staging predecessor absent')
    if (held['replacement_device'] != replacement['device'] or held['replacement_inode'] != replacement['inode']
            or request['backup_identity'] != stage['detail']['backup']['backup']['identity']
            or request['restore_identity'] != stage['detail']['backup']['restored']['identity']):
        raise ValueError('native copy/replacement identities differ from stage/service evidence')


def execute(candidate_path, output, cleanup):
    if os.geteuid() != 0 or output.exists():
        raise RuntimeError('requires root fixture enrollment and absent evidence destination')
    for path in (candidate_path, output, *((cleanup,) if cleanup else ())):
        if path != path.resolve() or not path.is_relative_to(DATA) or path == DATA:
            raise ValueError('physical path outside enrolled fixture data root')
    candidate = json.loads(candidate_path.read_bytes())
    step_raw = Path(candidate['step']).read_bytes()
    step = validate_candidate(candidate, step_raw)
    entry_raw = None
    if step['action'] == 'stage':
        entry_raw = (Path(step['source']).parent / 'entry-diagnosis.json').read_bytes()
        entry = json.loads(entry_raw)
        if (entry['schema'] != 'labelwatch.m3-entry-diagnosis/v1' or entry['entry_disposition'] != 'NEED_ESTABLISHED'
                or entry['unknowns'] != [] or entry['facts']['main']['identity'] != step['source_identity']
                or entry['facts']['sqlite']['freelist_count'] < entry['policy']['minimum_freelist_pages']):
            raise ValueError('observed entry need differs from exact staged source/policy')
    raw_unit = enrolled_unit(candidate)
    subject = 'sha256:' + digest(canonical({'schema': 'constellation.m3-subject/v1', 'operation': step['operation'], 'source': step['source'], 'revision': step['revision']}))
    scope = 'sha256:' + digest(canonical({'schema': 'constellation.m3-scope/v1', 'action': candidate['action'], 'step_sha256': candidate['step_sha256'], 'unit': candidate['unit'], 'unit_sha256': digest(raw_unit)}))
    enrollment = {'schema': 'constellation.m3-driver-enrollment/v1', 'action': candidate['action'], 'unit': candidate['unit'], 'step_sha256': candidate['step_sha256'], 'subject': subject, 'scope': scope, 'receipt': None, 'receipt_id': None, 'request': None}
    enrollment.update(qualification_interruption=candidate['qualification_interruption'], qualification_restore_substitution=candidate['qualification_restore_substitution'])
    enrollment['step'] = candidate['step']
    if candidate['action'] == 'cleanup':
        if cleanup is None:
            raise ValueError('cleanup requires actual native source/request/receipt')
        receipt = json.loads((cleanup / 'cleanup-receipt.json').read_bytes())
        request = json.loads((cleanup / 'cleanup-request.json').read_bytes())
        bind_cleanup_request(step, request)
        if receipt['request'] != request:
            raise ValueError('native receipt request differs from enrolled request')
        enrollment.update(receipt=str(cleanup / 'cleanup-receipt.json'), receipt_id=receipt['receipt_id'], request=request)
    elif cleanup is not None:
        raise ValueError('native cleanup receipt attached to another action')
    enrollment_raw = canonical(enrollment)
    output.mkdir(mode=0o700)
    unit_path = Path('/etc/systemd/system') / candidate['unit']
    with unit_path.open('xb') as stream:
        stream.write(raw_unit)
        stream.flush()
        os.fsync(stream.fileno())
    unit_path.chmod(0o644)
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    for kind in ('ActiveState', 'UnitFileState'):
        observed = subprocess.check_output(['systemctl', 'show', candidate['unit'], '--property=' + kind, '--value'], text=True).strip()
        if observed != {'ActiveState': 'inactive', 'UnitFileState': 'disabled'}[kind]:
            raise ValueError('unit is not fresh inactive/disabled')
    enrollment_path = output / 'enrollment.json'
    enrollment_path.write_bytes(enrollment_raw)
    enrollment_path.chmod(0o400)
    (output / 'enrolled-unit.service').write_bytes(raw_unit)
    if entry_raw is not None:
        (output / 'entry-diagnosis.json').write_bytes(entry_raw)
        (output / 'entry-binding.json').write_bytes(canonical({'entry_sha256': digest(entry_raw),
            'policy_sha256': digest(canonical(entry['policy']).rstrip(b'\n')), 'claim': 'FIXTURE_ENTRY_EVIDENCE_NOT_NATIVE_QUALIFICATION_OR_AUTHORITY'}))
    (output / 'ENROLLMENT.json').write_bytes(canonical({'candidate': str(candidate_path), 'unit_sha256': digest(raw_unit), 'cut': candidate['qualification_interruption'], 'restore_substitution': candidate['qualification_restore_substitution'], 'step_sha256': candidate['step_sha256'], 'admission_basis': 'NATIVE_CLEANUP_RECEIPT' if cleanup else 'DEVELOPMENTAL_FIXTURE_ONLY', 'fragment_custody': 'ROOT_ENROLLED_NOT_MEASURED_BY_AG'}))
    args = ['/usr/libexec/constellation-operator-beta/m3-composition-driver', '/usr/libexec/constellation-operator-beta/docket', '/usr/libexec/agent-governor-ng/ag-effectd', str(output / 'custody'), 'm3-' + candidate['step_sha256'][:40], Path('/etc/machine-id').read_text().strip(), candidate['unit'], subject, scope, str(enrollment_path), digest(enrollment_raw)]
    try:
        result = subprocess.run(args, capture_output=True, timeout=90)
        (output / 'driver.stdout').write_bytes(result.stdout)
        (output / 'driver.stderr').write_bytes(result.stderr)
        (output / 'driver.exit').write_text(str(result.returncode) + '\n')
        code = result.returncode
    except subprocess.TimeoutExpired as error:
        (output / 'driver.stdout').write_bytes(error.stdout or b'')
        (output / 'driver.stderr').write_bytes(error.stderr or b'')
        (output / 'driver.exit').write_text('NOT_OBSERVABLE_TIMEOUT\n')
        (output / 'UNKNOWN.json').write_bytes(canonical({'state': 'OUTCOME_UNKNOWN', 'next': 'inspect existing Docket/systemd occurrence; no new invocation authorized'}))
        code = 1
    for label, command in (
        ('unit-state', ['systemctl', 'show', candidate['unit'], '--property=ActiveState', '--property=SubState', '--property=Result', '--property=ExecMainStatus', '--property=NRestarts', '--property=InvocationID']),
        ('unit-journal', ['journalctl', '--no-pager', '-u', candidate['unit'], '--output=cat']),
    ):
        captured = subprocess.run(command, capture_output=True, timeout=15)
        (output / (label + '.stdout')).write_bytes(captured.stdout)
        (output / (label + '.stderr')).write_bytes(captured.stderr)
        (output / (label + '.exit')).write_text(str(captured.returncode) + '\n')
    # No restart, reset-failed, reissue or cleanup here, including nonzero exit.
    # The checker joins Docket settlement, actual helper terminal/cut and native
    # observations; driver exit alone is never a maintenance success claim.
    return code


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cleanup', type=Path)
    args = parser.parse_args()
    raise SystemExit(execute(args.candidate, args.output, args.cleanup))
