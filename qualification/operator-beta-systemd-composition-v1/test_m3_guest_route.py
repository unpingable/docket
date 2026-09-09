import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import m3_guest_route as route


class EnrolledRouteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.text = 'ExecStart=/usr/bin/python3.11 -m labelwatch.maintenance_step --step /var/lib/constellation-m3/run/step.json --expected-sha256 ' + 'a' * 64 + '\nRestart=no\n'
        self.root = root
        self.candidate = {'step': str(root / 'step.json'), 'step_sha256': 'a' * 64, 'action': 'stage', 'qualification_interruption': None, 'qualification_restore_substitution': False, 'unit_sha256': route.digest(self.text.encode())}
        self.candidate['unit'] = route.unit_name(self.candidate)
        (root / self.candidate['unit']).write_text(self.text)

    def test_positive_unit_is_not_instrumented(self):
        self.assertEqual(route.enrolled_unit(self.candidate), self.text.encode())

    def test_each_closed_cut_preserves_producer_seal(self):
        for cut in route.CUTS:
            with self.subTest(cut=cut):
                self.candidate['qualification_interruption'] = cut
                self.candidate['unit'] = route.unit_name(self.candidate)
                (self.root / self.candidate['unit']).write_text(self.text)
                self.assertEqual(route.enrolled_unit(self.candidate), self.text.encode())

    def test_changed_unit_or_unknown_cut_refuses(self):
        with self.assertRaises(ValueError):
            self.candidate['qualification_interruption'] = 'other'
            route.enrolled_unit(self.candidate)
        self.candidate['qualification_interruption'] = None
        self.candidate['unit_sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            route.enrolled_unit(self.candidate)

    def test_conflicting_or_relabelled_modes_refuse(self):
        self.candidate['qualification_interruption'] = 'before_started'
        with self.assertRaises(ValueError):
            route.enrolled_unit(self.candidate)
        self.candidate['qualification_restore_substitution'] = True
        with self.assertRaises(ValueError):
            route.unit_name(self.candidate)

    def test_restore_is_sealed_and_stage_only(self):
        self.candidate['qualification_restore_substitution'] = True
        self.candidate['unit'] = route.unit_name(self.candidate)
        (self.root / self.candidate['unit']).write_text(self.text)
        self.assertEqual(route.enrolled_unit(self.candidate), self.text.encode())
        self.candidate['action'] = 'cleanup'
        with self.assertRaises(ValueError):
            route.unit_name(self.candidate)

    def test_cleanup_action_cannot_be_relabelled_as_fixture_admission(self):
        step = {'schema': 'labelwatch.sqlite-relief-step/v1', 'action': 'cleanup', 'revision': 'b' * 40}
        raw = route.canonical(step)
        candidate = dict(self.candidate, schema='labelwatch.m3-enrollment-candidate/v1',
                         source_revision='b' * 40, status='NOT_ENROLLED_NOT_AUTHORIZED',
                         step_sha256=route.digest(raw), action='stage')
        candidate['unit'] = route.unit_name(candidate)
        with patch.object(route, 'enrolled_unit') as fragment:
            with self.assertRaisesRegex(ValueError, 'metadata differs'):
                route.validate_candidate(candidate, raw)
            fragment.assert_not_called()

    def test_malformed_digest_rejected_before_unit_path_construction(self):
        for sha in ('../other', 'A' * 64, 'g' * 64, 'a' * 63):
            with self.assertRaises(ValueError):
                route.unit_name(dict(self.candidate, step_sha256=sha))


if __name__ == '__main__':
    unittest.main()
