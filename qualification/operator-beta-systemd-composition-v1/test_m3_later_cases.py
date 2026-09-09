import json
from pathlib import Path
import tempfile
import unittest
import m3_case_check as checker
import m3_later_cases as later


class LaterCaseTests(unittest.TestCase):
    def test_recovery_actions_have_real_predecessors(self):
        self.assertEqual(later.PREVIOUS['rollback-pre-ingest'], ['stage', 'replace'])
        self.assertEqual(later.PREVIOUS['reconcile-cleanup'][-1], 'cleanup-cut')
        for action in later.PREVIOUS:
            if action != 'stage':
                for cut in ('before_started', 'after_started', 'before_terminal', 'after_terminal'):
                    self.assertEqual(later.cases()[action + '-' + cut], (action, cut))

    def test_complete_named_later_cases_and_native_negatives_present(self):
        for name in ('normal', 'equal-count-content', 'pathname-recovery', 'writer-start-failure',
                     'post-start-verification', 'post-write-stale-rollback', 'unknown-resumption',
                     'cleanup-no-margin', 'duplicate-concurrent', 'concurrent-lock',
                     'fact-enactment-disagreement', 'cleanup-missing-receipt',
                     'cleanup-stale-receipt', 'cleanup-substituted-receipt'):
            self.assertIn(name, later.cases())

    def test_each_swap_cleanup_and_recovery_cut_has_distinct_actual_state(self):
        self.assertEqual(checker.cut_postcondition('replace', 'after_original_rename'), ((False, True, True), True))
        self.assertEqual(checker.cut_postcondition('replace', 'after_replacement_rename'), ((True, True, False), True))
        self.assertEqual(checker.cut_postcondition('rollback-pre-ingest', 'after_terminal'), ((True, False, True), True))
        self.assertEqual(checker.cut_postcondition('cleanup', 'before_cleanup_unlink'), ((True, True, False), True))
        self.assertEqual(checker.cut_postcondition('cleanup', 'after_cleanup_unlink'), ((True, False, False), True))
        self.assertEqual(checker.cut_postcondition('reconcile-cleanup', 'before_started'), ((True, False, False), True))
        self.assertEqual(checker.cut_postcondition('release', 'after_release_record'), ((True, False, False), False))
        self.assertEqual(checker.cut_postcondition('release', 'after_started'), ((True, False, False), True))

    def test_checker_does_not_promote_duplicate_or_nonfinite_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'record.json'
            for raw in ('{"x":1,"x":2}', '{"x":NaN}'):
                path.write_text(raw)
                with self.assertRaises(ValueError):
                    checker.read(path)

    def test_checker_requires_observed_actual_failed_writer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'RECOVERY-OBSERVATION.json').write_text(json.dumps({'disposition': 'REPLACEMENT_REQUIRES_VERIFICATION_KEEP_HELD', 'post_release_generation_observed': False}))
            (root / 'WRITER-READINESS.json').write_text('{"discovery":{}}')
            state = root / 'writer-state-main.stdout'
            state.write_text('ActiveState=failed\nExecMainStatus=2\nNRestarts=0\n')
            producer = {'schema': 'constellation.m3-later-case-producer/v1', 'case': 'writer-start-failure', 'actions': [{'status': 'NOT_ADMITTED'}]}
            checker.check_postconditions(root, producer)
            state.write_text('ActiveState=active\nExecMainStatus=0\nNRestarts=0\n')
            with self.assertRaises(ValueError):
                checker.check_postconditions(root, producer)


if __name__ == '__main__':
    unittest.main()
