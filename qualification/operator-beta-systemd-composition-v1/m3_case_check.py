#!/usr/bin/env python3
"""Read-only M3 occurrence checks. A driver exit is not maintenance success.

Run inside the retained guest namespace (or an exactly reconstructed read-only
path tree). This joins owner records; it does not issue recovery permissions.
"""
import argparse
import hashlib
import json
import os
import fcntl
import stat
import subprocess
import sys
import sqlite3
from pathlib import Path


def read(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError('bounded regular record required')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('duplicate field')
            value[key] = item
        return value
    return json.loads(path.read_bytes(), object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unit_state(path):
    result = {}
    for line in Path(path).read_text().splitlines():
        key, separator, value = line.partition('=')
        require(separator and key not in result, 'ambiguous systemd properties')
        result[key] = value
    return result


def custody(directory, candidate):
    directory = Path(directory)
    enrolled = read(directory / 'enrollment.json')
    raw = (directory / 'enrolled-unit.service').read_bytes()
    require(hashlib.sha256(raw).hexdigest() == candidate['unit_sha256'], 'unit fragment changed after seal')
    require(enrolled['unit'] == candidate['unit'] and enrolled['step_sha256'] == candidate['step_sha256'], 'enrollment differs from candidate')
    root = directory / 'custody'
    issuance, accepted, settled = (read(root / name) for name in ('issuance.json', 'docket-custody.json', 'docket-settlement.json'))
    replay = read(root / 'ag-replay.json')
    require(all(replay[key] == 1 for key in ('ag_spends', 'docket_attempts', 'settlements')), 'not one spend/attempt/settlement')
    require(issuance['issuance'] == accepted['issuance'] == settled['issuance'], 'issuance correspondence differs')
    require(accepted['attempt'] == settled['attempt'], 'attempt correspondence differs')
    require(read(root / 'duplicate-custody.json') == accepted, 'actual duplicate acceptance differs from original custody')
    inspection = read(root / 'docket-inspection.json')
    require(inspection['record']['status'] == 'settled', 'owner query is not settled')
    outcome = read(root / 'executor-outcome.json')
    require(outcome['receipt'] == settled['receipt'], 'executor receipt differs from settlement')
    require(issuance['subject'] == enrolled['subject'] and issuance['scope'] == enrolled['scope'], 'subject/scope correspondence differs')
    state = unit_state(directory / 'unit-state.stdout')
    require(state.get('NRestarts') == '0', 'unexpected systemd retry')
    require(bool(state.get('InvocationID')), 'actual unit invocation absent')
    return state, settled


def check_step(candidate_path, directory):
    candidate = read(candidate_path)
    step_path = Path(candidate['step'])
    require(hashlib.sha256(step_path.read_bytes()).hexdigest() == candidate['step_sha256'], 'step bytes differ')
    step = read(step_path)
    require(candidate['action'] == step['action'], 'candidate action differs')
    state, settlement = custody(directory, candidate)
    if step['action'] == 'stage':
        entry = read(Path(directory) / 'entry-diagnosis.json')
        binding = read(Path(directory) / 'entry-binding.json')
        require(hashlib.sha256((Path(directory) / 'entry-diagnosis.json').read_bytes()).hexdigest() == binding['entry_sha256'], 'entry bytes differ from retained admission evidence')
        require(hashlib.sha256(json.dumps(entry['policy'], sort_keys=True, separators=(',', ':')).encode()).hexdigest() == binding['policy_sha256'], 'entry policy identity differs')
        require(entry['entry_disposition'] == 'NEED_ESTABLISHED' and entry['facts']['main']['identity'] == step['source_identity'], 'entry observation belongs to another source')
        require(entry['facts']['sqlite']['freelist_count'] >= entry['policy']['minimum_freelist_pages'] > 0, 'entry freelist threshold not established')
        require(entry['facts']['wal']['state'] == entry['facts']['shm']['state'] == 'OBSERVED_ABSENT' and entry['unknowns'] == [], 'entry quiescent acquisition is incomplete')
    sha = candidate['step_sha256']
    started = Path(step['journal']) / (sha + '.started.json')
    terminal = Path(candidate['expected_result'])
    cut = candidate['qualification_interruption']
    restore = candidate['qualification_restore_substitution']
    if cut or restore:
        markers = []
        for line in (Path(directory) / 'unit-journal.stdout').read_text().splitlines():
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if isinstance(value, dict) and value.get('step_sha256') == sha:
                markers.append(value)
        if cut:
            require(state.get('ExecMainStatus') == '77', 'actual cut exit77 absent')
            require(any(row.get('schema') == 'labelwatch.m3-interruption-fixture/v1' and row.get('cut') == cut and row.get('result') == 'INTENTIONAL_PROCESS_EXIT_NO_CLEANUP' for row in markers), 'exact cut marker absent')
            require(started.exists() == (cut != 'before_started'), 'STARTED presence disagrees with cut')
            require(terminal.exists() == (cut == 'after_terminal'), 'terminal presence disagrees with cut')
        else:
            require(state.get('ExecMainStatus') == '78', 'actual restored substitution refusal absent')
            require(any(row.get('schema') == 'labelwatch.m3-restored-substitution/v1' and row.get('restored_path') == step['restore'] for row in markers), 'actual restored substitution marker absent')
            require(not terminal.exists(), 'restored substitution incorrectly completed')
    elif terminal.exists():
        result = read(terminal)
        require(result['step_sha256'] == sha and result['action'] == step['action'], 'terminal belongs to another step')
        require(result['resource_relief'] == 'NOT_ESTABLISHED', 'helper claims unwarranted factual success')
        require(state.get('ExecMainStatus') == '0', 'helper completion and process disposition disagree')
    else:
        require(state.get('ExecMainStatus') not in (None, '0'), 'no helper completion and no observed refusal')
    return {'step_sha256': sha, 'action': step['action'], 'cut': cut,
            'helper_completed': terminal.exists(), 'docket_outcome': settlement['outcome'],
            'claim': 'OCCURRENCE_CORRESPONDENCE_ONLY_NOT_RESOURCE_RELIEF'}


def check_case(directory):
    directory = Path(directory)
    producer = read(directory / 'PRODUCER.json')
    results = []
    if producer['schema'] == 'constellation.m3-stage-case-producer/v1':
        results.append(check_step(producer['candidate'], directory / 'admitted-step'))
    else:
        for occurrence in producer['actions']:
            if occurrence.get('status') == 'NOT_ADMITTED':
                require(occurrence['seal_exit'] != 0, 'not-admitted case has successful seal')
                continue
            evidence = Path(occurrence['evidence'])
            if occurrence['driver_exit'] == 'INTAKE_REFUSED_OR_OUTCOME_UNKNOWN':
                # Explicitly do not pass an ambiguous launch as a refusal.
                require(not (evidence / 'custody').exists(), 'intake exception may have crossed dispatch boundary')
                results.append({'action': occurrence['action'], 'claim': 'LOCAL_INTAKE_REFUSED_NO_DRIVER_CUSTODY'})
            else:
                if producer['case'].startswith('cleanup-') and producer['case'].endswith('-receipt') and occurrence['action'] == 'cleanup':
                    state = unit_state(evidence / 'unit-state.stdout')
                    require(state.get('ActiveState') == 'inactive' and state.get('NRestarts') == '0' and not state.get('InvocationID'), 'refused cleanup actually invoked systemd')
                    root = evidence / 'custody'
                    if root.exists():
                        replay = read(root / 'admission-refusal-replay.json')
                        require(replay['ag_spends'] == 0 and replay['docket_attempts'] == 0, 'refusal crossed admission boundary')
                    results.append({'action': 'cleanup', 'claim': 'REFUSED_WITHOUT_EXECUTION'})
                else:
                    results.append(check_step(occurrence['candidate'], evidence))
    postconditions = check_postconditions(directory, producer)
    return {'schema': 'constellation.m3-case-correspondence-check/v1',
            'case': producer['case'], 'occurrences': results,
            'postconditions': postconditions,
            'maintenance_qualification': 'NATIVE_RECEIPT_REEXECUTION_AND_INDEPENDENT_REVIEW_PENDING'}


def check_postconditions(directory, producer):
    name = producer['case']
    if producer['schema'] == 'constellation.m3-stage-case-producer/v1':
        candidate = read(producer['candidate'])
        step = read(candidate['step'])
        seed = read(directory / 'SEED.json')
        source_sha = hashlib.sha256(Path(step['source']).read_bytes()).hexdigest()
        require(source_sha == seed['source_sha256_after_seed'], 'stage altered enrolled source bytes')
        require(not Path(step['original']).exists(), 'stage installed/replaced original')
        cut = candidate['qualification_interruption']
        expected = {
            'normal-stage': (True, True, True), 'temporary-space': (False, False, False),
            'source-before-cut': (False, False, False), 'backup-not-restore': (True, True, False),
            'compaction-failure': (True, True, True),
            'before_started': (False, False, False), 'after_started': (False, False, False),
            'after_backup_sync': (True, False, False), 'after_restore_sync': (True, True, False),
            'after_staging_sync': (True, True, True), 'before_terminal': (True, True, True),
            'after_terminal': (True, True, True),
        }[cut or name]
        require(tuple(Path(step[key]).exists() for key in ('backup', 'restore', 'staging')) == expected,
                'retained files disagree with exact stage case')
        if name == 'compaction-failure':
            require(Path(step['staging']).read_bytes() == b'EXCLUSIVE_DESTINATION_MUST_REMAIN_UNCHANGED\n', 'exclusive staging specimen overwritten')
        sys.path.insert(0, '/opt/constellation-m3/labelwatch/src')
        from labelwatch.maintenance_artifacts import verify_closed
        from labelwatch.maintenance_manifest import VerificationRefused
        for key, present in zip(('backup', 'restore', 'staging'), expected):
            if not present or (key == 'staging' and name == 'compaction-failure'):
                continue
            if key == 'restore' and name == 'backup-not-restore':
                try:
                    verify_closed(Path(step[key]), revision=step['revision'], expected=step['expected'])
                except VerificationRefused:
                    pass
                else:
                    raise ValueError('actual restored-content verification did not refuse')
            else:
                verify_closed(Path(step[key]), revision=step['revision'], expected=step['expected'])
        return {'source_unchanged_after_seed': True, 'installed': False, 'retained_copy_presence': expected}
    recovery = read(directory / 'RECOVERY-OBSERVATION.json')
    if producer['actions'] and producer['actions'][-1].get('cut'):
        last = producer['actions'][-1]
        candidate = read(last['candidate'])
        step = read(candidate['step'])
        expected_presence, held = cut_postcondition(last['action'], last['cut'])
        actual = tuple(Path(step[key]).exists() for key in ('source', 'original', 'staging'))
        require(actual == expected_presence, 'actual source/original/staging state disagrees with interruption cut')
        require(recovery['write_hold'] is held, 'hold/release disposition disagrees with interruption cut')
        original_location = 'source' if last['action'] == 'rollback-pre-ingest' and last['cut'] in ('before_terminal', 'after_terminal') else 'original'
        if Path(step[original_location]).exists():
            info = Path(step[original_location]).stat()
            require(info.st_dev == step['source_identity']['device'] and info.st_ino == step['source_identity']['inode'], 'retained original inode custody differs')
    expected = {
        'pathname-recovery': 'IDENTITY_UNRESOLVED_KEEP_STOPPED',
        'post-write-stale-rollback': 'FORWARD_RECOVERY_ONLY',
        'unknown-resumption': 'INDETERMINATE_WRITE_RESUMPTION_KEEP_STOPPED',
    }.get(name)
    if expected:
        require(recovery['disposition'] == expected, 'recovery disposition does not match actual case')
    if name == 'unknown-resumption':
        require(read(directory / 'PAUSED.json')['state'] == 'PAUSED_NOT_EXECUTING', 'paused writer testimony missing')
        require(recovery['post_release_generation_observed'] is False, 'unexpected resumed writes')
    if name in ('normal', 'post-write-stale-rollback', 'fact-enactment-disagreement'):
        require(recovery['post_release_generation_observed'] is True, 'real resumed generation absent')
        receipt = read(directory / 'post/post-receipt.json')
        # Exact native reexecution is a separate mandatory checker phase; these
        # owner-produced values are not a signature or substitute for replay.
        require(receipt.get('schema') == 'nq.labelwatch-relief-qualification/v1', 'unexpected native post profile')
    if name == 'writer-start-failure':
        state = unit_state(directory / 'writer-state-main.stdout')
        require(state['ActiveState'] == 'failed' and state['ExecMainStatus'] != '0' and state['NRestarts'] == '0', 'real failed writer start/no-retry not established')
        require('main' not in read(directory / 'WRITER-READINESS.json'), 'failed writer has admitted readiness')
        require(producer['actions'][-1].get('status') == 'NOT_ADMITTED', 'unready service was admitted')
    if name == 'cleanup-no-margin':
        require(recovery['write_hold'] is True and recovery['artifacts']['original']['presence'] == 'ABSENT', 'cleanup/hold/resource ordering differs')
    if name in ('equal-count-content', 'post-start-verification', 'pathname-recovery', 'concurrent-lock', 'cleanup-no-margin'):
        candidate = read(producer['actions'][-1]['candidate'])
        require(not Path(candidate['expected_result']).exists(), 'negative case incorrectly completed')
        if name in ('equal-count-content', 'post-start-verification'):
            step = read(candidate['step'])
            connection = sqlite3.connect('file:' + step['source'] + '?mode=ro', uri=True)
            try:
                require(connection.execute("SELECT value FROM maintenance_types WHERE key='int'").fetchone() == (8,), 'actual content substitution absent')
                require(connection.execute('SELECT COUNT(*) FROM maintenance_types').fetchone() == (5,), 'row count unexpectedly changed')
            finally:
                connection.close()
    return {'recovery_disposition': recovery['disposition'], 'post_release_generation_observed': recovery['post_release_generation_observed']}


def cut_postcondition(action, cut):
    early = cut in ('before_started', 'after_started')
    if action == 'replace':
        if early:
            return (True, False, True), True
        if cut == 'after_original_rename':
            return (False, True, True), True
        return (True, True, False), True
    if action == 'rollback-pre-ingest':
        return ((True, True, False) if early else (True, False, True)), True
    if action == 'cleanup':
        original = early or cut in ('after_cleanup_authorized', 'before_cleanup_unlink')
        return (True, original, False), True
    if action == 'reconcile-cleanup':
        return (True, False, False), True
    if action == 'release':
        return (True, False, False), early
    if action in ('verify-installed', 'verify-service'):
        return (True, True, False), True
    raise ValueError('unknown later-action cut')


def native_reexecution(directory, binary, expected_sha):
    """Re-evaluate retained exact source/request with a pinned modern image."""
    original = os.open(binary, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    sealed = os.memfd_create('m3-native-checker', os.MFD_ALLOW_SEALING)
    try:
        info = os.fstat(original)
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 1024 * 1024 * 1024, 'bounded native regular image required')
        digest = hashlib.sha256()
        while True:
            data = os.read(original, 1024 * 1024)
            if not data:
                break
            digest.update(data)
            view = memoryview(data)
            while view:
                view = view[os.write(sealed, view):]
        require(digest.hexdigest() == expected_sha, 'native checker image differs')
        fcntl.fcntl(sealed, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        results = []
        for source in sorted(set(Path(directory).glob('*/**/*-source.json'))):
            phase = source.name.removesuffix('-source.json')
            if phase not in ('pre', 'post', 'cleanup') or 'substituted-cleanup-input' in source.parts:
                continue
            request = source.with_name(phase + '-request.json')
            receipt = source.with_name(phase + '-receipt.json')
            expected = read(receipt)
            command = 'labelwatch-cleanup' if phase == 'cleanup' else 'labelwatch-relief'
            result = subprocess.run(['/proc/self/fd/' + str(sealed), command, '--source', str(source), '--request', str(request)],
                                    pass_fds=(sealed,), capture_output=True, timeout=10)
            require(result.returncode == 0, 'native reexecution refused retained input')
            require(json.loads(result.stdout) == expected, 'native receipt differs on actual reexecution')
            results.append({'path': str(receipt), 'disposition': expected['disposition'], 'claim': expected['claim']})
        name = read(Path(directory) / 'PRODUCER.json')['case']
        if name in ('normal', 'post-write-stale-rollback', 'fact-enactment-disagreement'):
            post = [item for item in results if item['path'] == str(Path(directory) / 'post/post-receipt.json')]
            require(len(post) == 1, 'postcondition replay absent')
            require(post[0]['claim'] == 'resource_relief_postcondition', 'wrong postcondition claim')
            require(post[0]['disposition'] == ('REFUTED' if name == 'fact-enactment-disagreement' else 'ESTABLISHED'), 'native final disposition differs from qualification case')
        return results
    finally:
        os.close(original)
        os.close(sealed)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--nq', type=Path, required=True)
    parser.add_argument('--nq-sha256', required=True)
    args = parser.parse_args()
    checked = check_case(args.directory)
    checked['native_reexecution'] = native_reexecution(args.directory, args.nq, args.nq_sha256)
    donor = args.directory / 'DONOR.json'
    if donor.exists():
        donor_path = Path(read(donor)['directory'])
        checked['foreign_donor'] = check_case(donor_path)
        checked['foreign_donor']['native_reexecution'] = native_reexecution(donor_path, args.nq, args.nq_sha256)
        receipt = read(read(donor)['receipt'])
        require(receipt['disposition'] == 'ESTABLISHED', 'foreign donor was not an established factual prerequisite')
    checked['maintenance_qualification'] = 'CASE_CHECKS_COMPLETED_INDEPENDENT_REVIEW_STILL_REQUIRED'
    print(json.dumps(checked, sort_keys=True))
