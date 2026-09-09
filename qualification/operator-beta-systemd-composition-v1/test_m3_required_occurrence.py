import copy
from pathlib import Path
import unittest
from unittest.mock import patch

import m3_case_check as checker
from m3_later_cases import PREVIOUS, cases


def producer(name):
    action, cut = cases()[name]
    plan = [('cleanup', 'after_cleanup_unlink') if x == 'cleanup-cut' else (x, None)
            for x in PREVIOUS[action] if x != 'writers'] + [(action, cut)]
    if name == 'post-write-stale-rollback':
        plan.append(('rollback-pre-ingest', None))
    return {'schema': 'constellation.m3-later-case-producer/v1', 'case': name,
            'actions': [{'action': a, 'cut': c, 'candidate': '/fixture/candidate',
                         'evidence': '/fixture/absent', 'driver_exit': 0} for a, c in plan]}


class RequiredOccurrenceTests(unittest.TestCase):
    def exercise(self, value, candidate_cut=None):
        current = iter(value['actions'])
        def read(path):
            if Path(path).name == 'PRODUCER.json':
                return value
            item = next(current)
            return {'action': item['action'], 'qualification_interruption':
                    candidate_cut if candidate_cut is not None else item['cut']}
        observed = iter(value['actions'])
        def step(*args):
            item = next(observed)
            return {'action': item['action'], 'cut': item['cut']}
        with patch.object(checker, 'read', side_effect=read), \
                patch.object(checker, 'check_step', side_effect=step), \
                patch.object(checker, 'check_postconditions', return_value={}):
            return checker.check_case('/fixture')

    def test_every_later_scenario_has_exact_plan_and_no_dropped_action(self):
        for name in cases():
            value = producer(name)
            checker.expected_later_occurrences(value)
            value['actions'].pop()
            with self.subTest(name=name), self.assertRaises(ValueError):
                checker.expected_later_occurrences(value)

    def test_each_required_cut_refuses_intake_or_nonadmission(self):
        for name, (_, cut) in cases().items():
            if cut is None:
                continue
            for state in ('intake', 'not-admitted'):
                value = producer(name)
                if state == 'intake':
                    value['actions'][-1]['driver_exit'] = 'INTAKE_REFUSED_OR_OUTCOME_UNKNOWN'
                else:
                    value['actions'][-1].update(status='NOT_ADMITTED', seal_exit=1)
                with self.subTest(name=name, state=state), self.assertRaisesRegex(ValueError, 'not demonstrated'):
                    self.exercise(value)

    def test_reported_or_sealed_cut_substitution_refuses(self):
        value = producer('cleanup-after_cleanup_authorized')
        changed = copy.deepcopy(value)
        changed['actions'][-1]['cut'] = None
        with self.assertRaisesRegex(ValueError, 'required scenario'):
            self.exercise(changed)
        with self.assertRaisesRegex(ValueError, 'sealed candidate'):
            self.exercise(value, candidate_cut='wrong-cut')

    def test_matching_cut_routes_to_existing_actual_cut_checker(self):
        self.exercise(producer('cleanup-after_cleanup_authorized'))

    def test_controller_schema_cannot_enter_ordinary_checker(self):
        value = producer('normal')
        value['schema'] = 'constellation.m3-controller-loss-case/v1'
        with self.assertRaisesRegex(ValueError, 'another producer family'):
            self.exercise(value)

    def test_normal_case_cannot_pass_intake_absence(self):
        value = producer('normal')
        value['actions'][-1]['driver_exit'] = 'INTAKE_REFUSED_OR_OUTCOME_UNKNOWN'
        with self.assertRaises(ValueError):
            self.exercise(value)

    def test_explicit_receipt_refusal_retains_absent_custody_without_cut_claim(self):
        value = producer('cleanup-missing-receipt')
        value['actions'][-1]['driver_exit'] = 'INTAKE_REFUSED_OR_OUTCOME_UNKNOWN'
        with patch.object(Path, 'exists', return_value=False):
            result = self.exercise(value)
        self.assertEqual(result['occurrences'][-1]['claim'], 'LOCAL_INTAKE_REFUSED_NO_DRIVER_CUSTODY')
        with patch.object(Path, 'exists', return_value=True), self.assertRaises(ValueError):
            self.exercise(value)

    def test_writer_failure_keeps_explicit_nonadmission(self):
        value = producer('writer-start-failure')
        value['actions'][-1].update(status='NOT_ADMITTED', seal_exit=1)
        self.exercise(value)


if __name__ == '__main__':
    unittest.main()
