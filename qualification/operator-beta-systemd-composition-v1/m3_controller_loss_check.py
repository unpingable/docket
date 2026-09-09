#!/usr/bin/python3
"""Reopen exact owner state and actual application facts after companion loss.

No accept, new authorization, helper start, release, cleanup, or retry controls.
Existing owner inspection/reconciliation may coordinate SQLite files; this does
not claim arbitrary stores are opened without filesystem coordination.
"""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from m3_case_check import read, require, cut_postcondition, native_reexecution
from m3_loss_barrier import case_inventory, release_identity
from m3_loss_executor import AG, AG_SHA, DOCKET


def run_json(command, data=None):
    result = subprocess.run(command, input=data, capture_output=True, timeout=20)
    require(result.returncode == 0, 'owner query/reconciliation refused')
    return json.loads(result.stdout)


def application_expected(action, cut):
    # Fixture initialization enrolls the hold before any AG issuance. Losing
    # the companion before stage does not remove that existing write hold.
    if action == 'stage':
        return (True, False, cut != 'ag-consumed-before-accept'), True
    return cut_postcondition(action, 'before_started' if cut == 'ag-consumed-before-accept' else 'after_terminal')


def owner_states(recovery, cut):
    before = ('dispatched' if cut == 'docket-settled-before-ag-poll' else
        'settled_observation_required' if cut == 'ag-settled-before-export' else 'authorization_consumed')
    require(set(recovery['before']['state']) == {before}, 'actual pre-recovery AG state differs from cut')
    allowed_after = ({'authorization_consumed'} if cut == 'ag-consumed-before-accept' else
        {'settled_observation_required', 'reconciliation_required'} if cut in
        ('docket-reserved-before-executor', 'executor-completed-before-reply') else {'settled_observation_required'})
    require(len(recovery['after']['state']) == 1 and set(recovery['after']['state']) <= allowed_after,
        'actual post-recovery AG state differs')
    require(recovery['replay_before']['ag_spends'] == recovery['replay_after']['ag_spends'] == 1, 'spend was lost or repeated')
    require(recovery['execution_capability'] == 'RECONCILIATION_ONLY_NO_SIGNER_NO_ACCEPT_ISSUANCE', 'recovery has execution capability')
    if cut == 'ag-consumed-before-accept':
        require(recovery['recovery']['result'] == 'issuance_not_accepted', 'absence not established by owner')
        require(recovery['before'] == recovery['after'], 'not-accepted recovery advanced authority')
        require(recovery['replay_after']['docket_attempts'] == recovery['replay_after']['settlements'] == 0, 'unaccepted issuance crossed custody')
    else:
        settled = 'settled_observation_required' in recovery['after']['state']
        require(recovery['replay_after']['docket_attempts'] == 1 and
            recovery['replay_after']['settlements'] == (1 if settled else 0),
            'actual known/indeterminate owner counts differ')


def check_retained_owner(directory):
    """Offline correspondence only; no claim of fresh guest/store observation."""
    directory = Path(directory)
    producer = read(directory / 'PRODUCER.json')
    action, cut, expired = case_inventory()[producer['case']]
    require((producer['action'], producer['cut'], producer['expired_cleanup']) ==
        (action, cut, expired), 'closed retained case differs')
    guest_root = Path('/var/lib/constellation-m3/later-cases') / producer['case']
    last = producer['actions'][-1]
    require(last['action'] == action and last['driver_exit'] == -9, 'retained selected action/exit differs')
    relative = Path(last['evidence']).relative_to(guest_root)
    require(len(relative.parts) == 1 and relative.name not in ('.', '..'), 'retained evidence is not the direct enrolled action')
    evidence = directory / relative
    require(Path(producer['barrier_directory']) == Path(last['evidence']) / 'controller-loss', 'retained barrier path differs')
    barrier = evidence / 'controller-loss'
    arrived, enrolled = read(barrier / 'ARRIVED.json'), read(barrier / 'ENROLLED-COMPANION.json')
    require(arrived['cut'] == cut and arrived['companion'] == enrolled['companion'], 'retained cut/process differs')
    expected_exit = {'barrier_sha256': release_identity(arrived), 'companion': enrolled['companion'], 'observed_exit': True}
    require(read(barrier / 'COMPANION-EXIT.json') == read(barrier / 'RELEASE.json') == expected_exit,
        'retained pidfd exit/release binding differs')
    result = read(barrier / 'RECOVERY-RESULT.json')
    require(result['exit'] == 0, 'retained recovery refused')
    recovery = json.loads(result['stdout'])
    owner_states(recovery, cut)
    issuance = read(barrier / 'COMPANION.json')['issuance']
    require(recovery['expected_issuance'] == issuance, 'retained recovery names another issuance')
    if cut != 'ag-consumed-before-accept':
        owner = read(barrier / 'DOCKET-BEFORE-RECOVERY.json')
        require(owner['record']['issuance']['issuance'] == issuance, 'retained Docket query names another issuance')
    return {'case': producer['case'], 'cut': cut, 'enrolled_driver_sha256': enrolled['sha256'],
        'issuance': issuance, 'owner_correspondence': 'RETAINED_RECORDS_ONLY_NOT_FRESH_STORE_OBSERVATION',
        'new_effect_authority': 'NONE'}


def check(directory, driver, driver_sha, nq, nq_sha):
    directory = Path(directory)
    retained = check_retained_owner(directory)
    require(retained['enrolled_driver_sha256'] == driver_sha, 'retained driver enrollment differs')
    require(hashlib.sha256(Path(driver).read_bytes()).hexdigest() == driver_sha, 'exact native driver image differs')
    require(hashlib.sha256(Path(AG).read_bytes()).hexdigest() == AG_SHA, 'exact real AG image differs')
    producer = read(directory / 'PRODUCER.json')
    action, cut, expired = case_inventory()[producer['case']]
    require((producer['action'], producer['cut'], producer['expired_cleanup']) == (action, cut, expired), 'closed case mapping differs')
    last = producer['actions'][-1]
    require(last['action'] == action and last['driver_exit'] == -9, 'actual companion did not exit at selected action')
    evidence = Path(last['evidence'])
    barrier = Path(producer['barrier_directory'])
    require(barrier == evidence / 'controller-loss' and barrier.is_relative_to(directory), 'foreign barrier directory')
    arrived = read(barrier / 'ARRIVED.json')
    enrolled = read(barrier / 'ENROLLED-COMPANION.json')
    require(arrived['cut'] == cut and arrived['companion'] == enrolled['companion'], 'cut/process enrollment differs')
    require(enrolled['sha256'] == driver_sha, 'enrolled companion image differs from checker input')
    expected_exit = {'barrier_sha256': release_identity(arrived), 'companion': enrolled['companion'], 'observed_exit': True}
    require(read(barrier / 'COMPANION-EXIT.json') == read(barrier / 'RELEASE.json') == expected_exit, 'exact pidfd exit/release correspondence differs')
    wrapper = '/opt/constellation-m3/producer/qualification/operator-beta-systemd-composition-v1/m3_loss_executor.py'
    saved = read(barrier / 'RECOVERY-RESULT.json')
    require(saved['exit'] == 0, 'owner recovery did not complete')
    recovered = json.loads(saved['stdout'])
    owner_states(recovered, cut)
    issuance = read(barrier / 'COMPANION.json')['issuance']
    reopened = run_json([str(driver), '--inspect-existing', DOCKET, wrapper, str(evidence / 'custody'), issuance])
    require(reopened['inspection_only'] is True and reopened['before'] == reopened['after'] == recovered['after'], 'actual owner reopening disagrees')
    require(reopened['replay_after'] == recovered['replay_after'], 'actual replay cardinality changed')
    candidate = read(last['candidate'])
    step = read(candidate['step'])
    require(hashlib.sha256(Path(candidate['step']).read_bytes()).hexdigest() == candidate['step_sha256'], 'actual operation step differs')
    started = Path(step['journal']) / (candidate['step_sha256'] + '.started.json')
    terminal = Path(candidate['expected_result'])
    if cut == 'ag-consumed-before-accept':
        require(not started.exists() and not terminal.exists() and not (barrier / 'REAL-EXECUTOR-DELIVERY.json').exists(), 'unaccepted action produced helper/executor evidence')
    else:
        require(started.is_file() and terminal.is_file(), 'already admitted helper did not complete')
        require(read(terminal)['step_sha256'] == candidate['step_sha256'], 'helper terminal differs')
        owner = run_json([DOCKET, 'governed-loop', 'inspect', '--state', str(evidence / 'custody/occurrence/docket-state'), '--issuance', issuance])
        settled = recovered['after']['state'].get('settled_observation_required')
        if settled is not None:
            require(owner['record']['status'] == 'settled' and owner['record']['settlement'] == settled['settlement'], 'Docket/AG exact settlement differs')
        else:
            require(owner['record']['status'] in ('accepted', 'indeterminate') and
                owner['record'].get('settlement') is None, 'indeterminate owner state fabricated settlement')
        dispatch = {'attempt': owner['record']['custody']['attempt'], 'marker': owner['record']['custody']['executor_marker'],
            'work_schema': owner['record']['issuance']['work_schema'], 'work': owner['record']['issuance']['work'],
            'subject': owner['record']['issuance']['subject'], 'scope': owner['record']['issuance']['scope']}
        actual_effect = run_json([AG, 'reconcile', str(evidence / 'custody/occurrence/systemd-plan-v2.json')], json.dumps(dispatch).encode())
        if settled is not None:
            require(actual_effect['receipt'] == owner['record']['settlement']['receipt'], 'real AG effect store differs from Docket settlement')
        require(read(barrier / 'REAL-EXECUTOR-RESULT.json')['exit'] == 0, 'real executor did not complete')
    if cut == 'docket-reserved-before-executor':
        observed = arrived['owner_observation']
        require(observed['ag_attempt_store_present_before_execution'] is False and observed['real_executor_deliveries_before_barrier'] == 0, 'absence of real executor/effect before cut not established')
        require(observed['docket_inspection']['record']['custody']['attempt'] == observed['dispatch']['attempt'], 'reservation/dispatch differs')
    if cut == 'executor-completed-before-reply':
        require(arrived['owner_observation']['real_executor_deliveries_before_barrier'] == 1, 'effect-before-reply cut not established')
        require(arrived['owner_observation']['real_executor_outcome'] == actual_effect, 'retained exact effect before reply differs')
    if cut == 'ag-settled-before-export':
        require(not (evidence / 'custody/composition-result.json').exists(), 'post-settlement export cut not reached')
    if cut == 'docket-settled-before-ag-poll':
        at_cut = read(barrier / 'DOCKET-AT-DISPATCH-RETURN.json')
        require(at_cut['record']['status'] == 'settled' and
            at_cut['record']['settlement'] == owner['record']['settlement'],
            'named settled Docket cut not established before AG poll')
    if expired:
        request = read(evidence / 'enrollment.json')['request']
        receipt = read(read(evidence / 'enrollment.json')['receipt'])
        source = json.loads(receipt['source_utf8'])
        stamp = datetime.fromisoformat(source['currentness_started_at'].replace('Z', '+00:00')).timestamp() * 1000
        require(recovered['observed_at_unix_ms'] >= stamp + request['maximum_currentness_age_seconds'] * 1000, 'actual cleanup expiry not reached')
    sys.path.insert(0, '/opt/constellation-m3/labelwatch/src')
    from labelwatch.maintenance_artifacts import verify_closed
    from labelwatch.maintenance_step import reconcile
    from labelwatch.maintenance_hold import process_start_ticks
    writer_observations = {}
    if action in ('verify-service', 'cleanup', 'release', 'reconcile-cleanup'):
        require(set(producer['writers']) == {'main', 'discovery'}, 'required writer enrollment absent')
        ready = read(directory / 'WRITER-READINESS.json')
        require(set(ready) == {'main', 'discovery'} and len({item['pid'] for item in ready.values()}) == 2,
            'two distinct writer readiness identities required')
        for role, enrolled_writer in producer['writers'].items():
            query = subprocess.run(['systemctl', 'show', enrolled_writer['unit'],
                '--property=MainPID', '--property=ActiveState'], capture_output=True, text=True, timeout=10)
            require(query.returncode == 0, 'actual writer unit state not observable')
            values = dict(line.split('=', 1) for line in query.stdout.splitlines() if '=' in line)
            require(values.get('ActiveState') == 'active' and int(values['MainPID']) == ready[role]['pid'] and
                process_start_ticks(ready[role]['pid']) == ready[role]['start_ticks'],
                'actual enrolled writer is absent or substituted')
            writer_observations[role] = {'pid': ready[role]['pid'], 'start_ticks': ready[role]['start_ticks'],
                'unit': enrolled_writer['unit'], 'source': 'SYSTEMD_AND_OS_PROCESS_IDENTITY'}
    current = reconcile(step)
    expected, held = application_expected(action, cut)
    require(tuple(Path(step[key]).exists() for key in ('source', 'original', 'staging')) == expected, 'actual application replacement/cleanup state differs')
    require(current['write_hold'] is held, 'actual write hold differs from completed/absent action')
    if held or (action == 'stage' and cut == 'ag-consumed-before-accept'):
        verify_closed(Path(step['source']), revision=step['revision'], expected=step['expected'])
    if action != 'stage' or cut != 'ag-consumed-before-accept':
        for retained_copy in ('backup', 'restore'):
            verify_closed(Path(step[retained_copy]), revision=step['revision'], expected=step['expected'])
    if action == 'release' and cut != 'ag-consumed-before-accept':
        require(current['disposition'] in ('FORWARD_RECOVERY_ONLY', 'INDETERMINATE_WRITE_RESUMPTION_KEEP_STOPPED'), 'post-release state silently authorizes rollback')
    native = native_reexecution(directory, nq, nq_sha)
    return {'case': producer['case'], 'owner_reopened': True, 'original_spends': 1,
        'actual_owner_state': next(iter(recovered['after']['state'])),
        'writer_observations': writer_observations,
        'actual_companion_exit_observed': True, 'application_recovery': current,
        'native_reexecution': native, 'new_effect_authority': 'NONE',
        'qualification': 'SCOPED_CONTROLLER_LOSS_CHECKS_REQUIRE_INDEPENDENT_REVIEW'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--driver', type=Path, required=True)
    parser.add_argument('--driver-sha256', required=True)
    parser.add_argument('--nq', type=Path, required=True)
    parser.add_argument('--nq-sha256', required=True)
    args = parser.parse_args()
    print(json.dumps(check(args.directory, args.driver, args.driver_sha256, args.nq, args.nq_sha256), sort_keys=True))
