import json
from pathlib import Path
import tempfile
import unittest
from m3_case_check import nonsettled_owner


class NonsettledTests(unittest.TestCase):
    def test_pending_and_unknown_remain_distinct_from_application_refusal(self):
        for status, progress, pc in [('accepted', 'PENDING', 'dispatched'),
                ('indeterminate', 'RECONCILIATION_REQUIRED', 'reconciliation_required')]:
            with self.subTest(status=status), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                issuance = {'issuance': 'i', 'subject': 's', 'scope': 'scope'}
                accepted = {'issuance': 'i', 'attempt': 'a', 'executor_marker': 'm'}
                replay = {'ag_spends': 1, 'docket_attempts': 1, 'settlements': 0}
                inspection = {'record': {'status': status, 'settlement': None, 'issuance': issuance, 'custody': accepted}}
                result = {'schema': 'constellation.operator_beta.docket_systemd_composition_result.v1',
                    'disposition': 'NOT_SETTLED', 'duplicate_acceptance': 'NOT_RUN',
                    'application_disposition': 'NOT_INFERRED_FROM_OWNER_STATE',
                    'docket_inspection': {'observation': 'AVAILABLE', 'status': status},
                    'systemd_evidence': {'observation': 'AVAILABLE'}, 'docket_progress': progress,
                    'issuance': 'i', 'attempt': 'a', **replay}
                def write(name, value):
                    (root / name).write_text(json.dumps(value))
                write('composition-result.json', result)
                write('ag-state.json', {'state': {pc: {}}})
                write('executor-dispatch.json', {'attempt': 'a', 'marker': 'm', 'subject': 's', 'scope': 'scope'})
                self.assertEqual(nonsettled_owner(root, issuance, accepted, inspection, replay),
                    {'outcome': 'NOT_SETTLED', 'owner_status': status})
                for field, value in [('systemd_evidence', {'observation': 'NOT_OBSERVABLE'}),
                        ('attempt', 'other'), ('settlements', 1), ('application_disposition', 'REFUSED')]:
                    write('composition-result.json', {**result, field: value})
                    with self.subTest(field=field), self.assertRaises(ValueError):
                        nonsettled_owner(root, issuance, accepted, inspection, replay)
                write('composition-result.json', result)
                write('docket-settlement.json', {'receipt': 'invented'})
                with self.assertRaises(ValueError):
                    nonsettled_owner(root, issuance, accepted, inspection, replay)


if __name__ == '__main__':
    unittest.main()
