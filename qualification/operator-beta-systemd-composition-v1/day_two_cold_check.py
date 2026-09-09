"""Read-only reopening of cold-cohort qualification evidence; no VM actions."""
import hashlib
import json
import pathlib
import tarfile
import tempfile
from day_two_restore import logical_manifest

OLD_BINARY = '03778e0e9ea19366c920c98d041436d30f92b83abf0745766ef446c811e65cd9'
NEW_BINARY = 'a672ef6aad196e989989a62bb0281e81a8918be8d824fe1caf94913505822427'
EXPECTED_STEPS = [('prepare', 23), ('inspect', 0), ('cut-one', 23), ('inspect', 0), ('rollback', 0), ('cut-two', 23), ('inspect', 0), ('post-cut', 23), ('inspect', 0), ('finish', 0)]


def verify_steps(returns, nq):
    if returns != [{'step': step, 'exit': code} for step, code in EXPECTED_STEPS]:
        raise nq.Refusal('cold-cohort completed interruption/inspection sequence differs')


def verify_manifests(manifests, first_baseline, second_baseline, nq):
    if manifests['old-archive/db/nq.db'] != manifests['rollback.sqlite']:
        raise nq.Refusal('old rollback changed typed rows or schema')
    if manifests['cut-one/nq.sqlite'] != first_baseline:
        raise nq.Refusal('preactivation cohort changed before rollback')
    if manifests['cut-two/nq.sqlite'] == second_baseline or manifests['cut-two/nq.sqlite'] != manifests['forward-backup.sqlite']:
        raise nq.Refusal('post-cut forward history is absent or not preserved')


def verify(path, nq, owner_json_record):
    evidence = path / 'evidence'
    here = pathlib.Path(__file__).resolve().parent
    for name in ('day_two_cold.py', 'day_two_cold_guest.py', 'day_two_restore.py'):
        if (path / 'input' / name).read_bytes() != (here / name).read_bytes():
            raise nq.Refusal('cold-cohort retained source differs from exact checker cohort')
    for name, digest in (
        ('m4-old-nq.deb', '0fd1ce9e1be48b56ba5e526993a94c4682499bb9dbd9304dffd4500c01603636'),
        ('nq-ng_amd64.deb', '8c41c2b4d320770c6a04b09649b4c229fb00e86f64689c3c2f3f1c2a4d4e3019'),
        ('m4-old-store.sqlite', 'e6a442e199449093c105b85f1882a31b2ea64cf70d61b7f1a72e7635bdb7e153'),
    ):
        if hashlib.sha256((path / 'input' / name).read_bytes()).hexdigest() != digest:
            raise nq.Refusal('cold-cohort input package/store identity mismatch')
    returns = nq.load_json_artifact(evidence / 'cold-step-returns.json', 'cold steps')
    if set(returns) != {'steps'}:
        raise nq.Refusal('cold step record is not closed')
    verify_steps(returns['steps'], nq)
    admission = owner_json_record(evidence / 'cold-fresh-admission.json', 'cold admission', nq)
    diagnostic = nq.load_json_artifact(evidence / 'cold-fresh-diagnostic.json', 'cold diagnostic')
    nq.verify_diagnostic_artifact(diagnostic, profile='nq.http_endpoint', condition='unresolved', instance='http-restart', bindings=nq.load_json_artifact(evidence / 'bindings.json', 'bindings'))
    with tarfile.open(evidence / 'cold-cohort-private.tar', 'r:') as archive:
        members = {}
        for member in archive.getmembers():
            name = member.name.removeprefix('./')
            if name in members or member.issym() or member.islnk() or '..' in pathlib.PurePosixPath(name).parts:
                raise nq.Refusal('cold archive has ambiguous member custody')
            members[name] = member

        def raw(name):
            member = members[name]
            if not member.isfile() or member.size > 64 * 1024 * 1024:
                raise nq.Refusal('cold evidence member exceeds bound or is not regular')
            return archive.extractfile(member).read()

        def record(name):
            def unique(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise nq.Refusal('cold evidence has duplicate JSON fields')
                    result[key] = value
                return result
            return json.loads(raw(name), object_pairs_hook=unique)

        for phase, binary in (
            ('OLD_ARCHIVED', OLD_BINARY), ('NEW_ONE_PREACTIVATION', NEW_BINARY),
            ('OLD_ROLLBACK_VERIFIED', OLD_BINARY), ('NEW_TWO_PREACTIVATION', NEW_BINARY),
            ('POST_CUT_FORWARD_ONLY', NEW_BINARY),
        ):
            expected = {'phase': phase, 'binary_sha256': binary, 'service': 'STOPPED', 'automatic_resume': False}
            if record('CHECKPOINT-' + phase + '.json') != expected:
                raise nq.Refusal('cold-cohort checkpoint identity disagrees')
            if phase != 'OLD_ROLLBACK_VERIFIED' and record('INSPECT-' + phase + '.json') != {'phase': phase, 'binary_matches': True, 'service_inactive': True, 'next_action_requires_explicit_step': True}:
                raise nq.Refusal('cold-cohort interruption was not independently inspected')
        for mode, required in (
            ('prepare', {'old-install', 'old-start', 'old-stop', 'old-archive', 'old-archive-verify'}),
            ('cut-one', {'cut-one-install', 'cut-one-init'}),
            ('rollback', {'rollback-old-install', 'rollback-absent-restore', 'rollback-reopen', 'rollback-start', 'rollback-stop'}),
            ('cut-two', {'cut-two-install', 'cut-two-init'}),
            ('finish', {'forward-status', 'forward-backup', 'forward-start', 'forward-stop', 'final-old-archive-verify'}),
        ):
            commands = record(mode + '-commands.json')
            if not required <= {item['case'] for item in commands} or any(item['exit'] != 0 for item in commands):
                raise nq.Refusal('cold owner command evidence incomplete or failed')
        if hashlib.sha256(raw('old-archive/bin/nq')).hexdigest() != OLD_BINARY:
            raise nq.Refusal('preserved historical verifier identity differs')
        for name in ('old-archive-verify.stdout', 'final-old-archive-verify.stdout'):
            verified = record(name)
            if verified.get('grants_authority') is not False or any(verified.get(key) is not True for key in ('integrity_verified', 'historical_database_verified', 'historical_admitted_report_semantics_verified', 'historical_diagnostic_artifact_semantics_verified', 'historical_evaluation_refusal_semantics_verified', 'historical_status_semantics_verified')):
                raise nq.Refusal('old owner did not establish historical semantic reopening')
        lock = record('cut-two/admissions/http-restart.json')
        if admission != {'outcome': 'activated', 'instance_id': 'http-restart', 'admission_id': lock['admission_id'], 'binding_digest': nq.sha256_bytes(nq.canonical(lock)), 'lock_path': '/var/lib/nq/m4-cold/cut-two/admissions/http-restart.json', 'previous_lock_archived': False}:
            raise nq.Refusal('fresh admission is not bound to the retained active lock')
        if lock['profile'] != {'id': 'nq.http_endpoint', 'version': 1, 'digest': nq.PROFILE_DIGESTS['nq.http_endpoint']}:
            raise nq.Refusal('fresh admission profile differs')
        with tempfile.TemporaryDirectory(prefix='m4-cold-check-') as temporary:
            manifests = {}
            for index, name in enumerate(('old-archive/db/nq.db', 'rollback.sqlite', 'cut-one/nq.sqlite', 'cut-two/nq.sqlite', 'forward-backup.sqlite')):
                if name + '-wal' in members and members[name + '-wal'].size:
                    raise nq.Refusal('standalone cold snapshot still has a nonempty WAL')
                target = pathlib.Path(temporary) / str(index)
                target.write_bytes(raw(name))
                manifests[name] = logical_manifest(target)
            verify_manifests(manifests, record('cut-one-baseline.json'), record('cut-two-baseline.json'), nq)
        if record('RESULT.json') != owner_json_record(evidence / 'cold-cohort-result.json', 'cold result', nq):
            raise nq.Refusal('cold public and retained procedure results disagree')
        if record('RESULT.json') != {'schema': 'constellation.m4.cold_cohort_fixture.v1', 'disposition': 'COLD_COHORT_VM_DEMONSTRATED', 'old_binary_sha256': OLD_BINARY, 'new_binary_sha256': NEW_BINARY, 'fresh_admission': True, 'preactivation_rollback': 'EXACT_OLD_BINARY_AND_ROWS_REOPENED', 'post_cut_rollback': 'NOT_EXECUTED_FORWARD_ONLY', 'interruption_scope': 'PROCESS_EXIT_AFTER_COMPLETED_STEPS_NOT_MID_DPKG', 'history_authorizes_effects': False, 'human_trial': 'NOT_RUN'}:
            raise nq.Refusal('cold procedure claim exceeds the checked scope')
