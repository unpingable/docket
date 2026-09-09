import copy
import json
from pathlib import Path
import tempfile
import unittest
from m3_case_check import retained_invocation


class InvocationTests(unittest.TestCase):
    def test_completed_oneshot_and_identity_refusals(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'custody').mkdir()
            candidate = {'unit': 'step.service', 'step_sha256': 'b' * 64}
            window = {**candidate, 'machine_id': 'c' * 32, 'started_us': 100000, 'finished_us': 300000}
            evidence = {'unit': 'step.service', 'live_machine_identity': 'c' * 32,
                'systemd_machine_identity': 'c' * 32, 'attempt': 'attempt', 'marker': 'marker',
                'action': 'start', 'job_path': '/org/freedesktop/systemd1/job/5',
                'started_at_unix_ms': 110, 'finished_at_unix_ms': 220,
                'outcome_code': 'start_unit_completed', 'job_result': 'done'}
            (root / 'execution-window.json').write_text(json.dumps(window))
            (root / 'custody/systemd-evidence.json').write_text(json.dumps(evidence))
            (root / 'unit-journal-structured.exit').write_text('0\n')
            row = {'_MACHINE_ID': 'c' * 32, '_SYSTEMD_UNIT': 'step.service',
                '_SYSTEMD_INVOCATION_ID': 'a' * 32, '__REALTIME_TIMESTAMP': '200000'}
            state = {'InvocationID': '', 'ActiveState': 'inactive', 'SubState': 'dead'}
            accepted = {'attempt': 'attempt', 'executor_marker': 'marker'}
            def check(rows, current=state):
                (root / 'unit-journal-structured.stdout').write_text(''.join(json.dumps(r) + '\n' for r in rows))
                return retained_invocation(root, candidate, current, accepted)
            self.assertEqual(check([row]), 'a' * 32)
            self.assertEqual(check([row], {**state, 'InvocationID': 'a' * 32}), 'a' * 32)
            for rows in ([], [row, {**row, '_SYSTEMD_INVOCATION_ID': 'd' * 32}],
                    [{**row, '_MACHINE_ID': 'd' * 32}], [{**row, '_SYSTEMD_UNIT': 'other.service'}],
                    [{**row, '__REALTIME_TIMESTAMP': '99999'}], [{**row, '_SYSTEMD_INVOCATION_ID': 'bad'}]):
                with self.subTest(rows=rows), self.assertRaises(ValueError):
                    check(rows)
            with self.assertRaises(ValueError):
                check([row], {**state, 'InvocationID': 'd' * 32})
            (root / 'unit-journal-structured.exit').write_text('1\n')
            with self.assertRaises(ValueError):
                check([row])


if __name__ == '__main__':
    unittest.main()
