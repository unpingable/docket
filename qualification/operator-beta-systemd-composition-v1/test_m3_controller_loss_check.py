"""Closed checker correspondence controls, not actual owner/VM qualification."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from m3_controller_loss_check import owner_states, check_retained_owner, application_expected
from m3_loss_barrier import case_inventory, release_identity


def fixture(cut):
    before = ('dispatched' if cut == 'docket-settled-before-ag-poll' else
        'settled_observation_required' if cut == 'ag-settled-before-export' else 'authorization_consumed')
    unaccepted = cut == 'ag-consumed-before-accept'
    snapshot = {'state': {before: {'fixture': 'NOT_ACTUAL_OWNER_EVIDENCE'}}}
    return {'before': snapshot, 'after': copy.deepcopy(snapshot) if unaccepted else
        {'state': {'settled_observation_required': {}}},
        'replay_before': {'ag_spends': 1},
        'replay_after': {'ag_spends': 1, 'docket_attempts': 0 if unaccepted else 1,
            'settlements': 0 if unaccepted else 1},
        'recovery': {'result': 'issuance_not_accepted' if unaccepted else 'advanced'},
        'execution_capability': 'RECONCILIATION_ONLY_NO_SIGNER_NO_ACCEPT_ISSUANCE'}


class OwnerCorrespondenceTests(unittest.TestCase):
    def test_pre_stage_loss_preserves_already_enrolled_hold(self):
        self.assertEqual(application_expected('stage', 'ag-consumed-before-accept'),
            ((True, False, False), True))
        self.assertEqual(application_expected('stage', 'ag-settled-before-export'),
            ((True, False, True), True))

    def test_closed_five_cut_owner_shapes(self):
        from m3_loss_barrier import CUTS
        for cut in CUTS:
            with self.subTest(cut=cut):
                owner_states(fixture(cut), cut)

    def test_wrong_phase_cannot_establish_named_cut(self):
        value = fixture('docket-settled-before-ag-poll')
        value['before']['state'] = {'authorization_consumed': {}}
        with self.assertRaises(ValueError):
            owner_states(value, 'docket-settled-before-ag-poll')

    def test_indeterminate_not_relabelled_as_known_settlement(self):
        value = fixture('executor-completed-before-reply')
        value['after']['state'] = {'reconciliation_required': {}}
        value['replay_after']['settlements'] = 0
        owner_states(value, 'executor-completed-before-reply')
        value['replay_after']['settlements'] = 1
        with self.assertRaises(ValueError):
            owner_states(value, 'executor-completed-before-reply')

    def test_unaccepted_issuance_cannot_gain_attempt_or_spend(self):
        for field in ('ag_spends', 'docket_attempts', 'settlements'):
            value = fixture('ag-consumed-before-accept')
            value['replay_after'][field] += 1
            with self.subTest(field=field), self.assertRaises(ValueError):
                owner_states(value, 'ag-consumed-before-accept')

    def test_offline_binding_and_foreign_issuance_refusal(self):
        name = next(name for name, values in case_inventory().items()
            if values == ('stage', 'ag-consumed-before-accept', False))
        guest = Path('/var/lib/constellation-m3/later-cases') / name / '00-stage'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            barrier = root / '00-stage/controller-loss'
            barrier.mkdir(parents=True)
            def save(path, value):
                path.write_text(json.dumps(value))
            save(root / 'PRODUCER.json', {'case': name, 'action': 'stage',
                'cut': 'ag-consumed-before-accept', 'expired_cleanup': False,
                'actions': [{'action': 'stage', 'driver_exit': -9, 'evidence': str(guest)}],
                'barrier_directory': str(guest / 'controller-loss')})
            arrived = {'cut': 'ag-consumed-before-accept', 'companion': {'pid': 42, 'start_ticks': 1}}
            save(barrier / 'ARRIVED.json', arrived)
            save(barrier / 'ENROLLED-COMPANION.json', {'companion': arrived['companion'], 'sha256': 'fixture-not-binary-proof'})
            released = {'barrier_sha256': release_identity(arrived), 'companion': arrived['companion'], 'observed_exit': True}
            for filename in ('COMPANION-EXIT.json', 'RELEASE.json'):
                save(barrier / filename, released)
            save(barrier / 'COMPANION.json', {'issuance': 'fixture-original'})
            recovery = fixture('ag-consumed-before-accept')
            recovery['expected_issuance'] = 'fixture-original'
            save(barrier / 'RECOVERY-RESULT.json', {'exit': 0, 'stdout': json.dumps(recovery)})
            self.assertEqual(check_retained_owner(root)['issuance'], 'fixture-original')
            recovery['expected_issuance'] = 'fixture-other'
            save(barrier / 'RECOVERY-RESULT.json', {'exit': 0, 'stdout': json.dumps(recovery)})
            with self.assertRaisesRegex(ValueError, 'another issuance'):
                check_retained_owner(root)


if __name__ == '__main__':
    unittest.main()
