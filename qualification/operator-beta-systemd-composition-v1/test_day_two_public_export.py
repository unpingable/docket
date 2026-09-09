import importlib.util
import json
import pathlib
import unittest

SPEC = importlib.util.spec_from_file_location('public_export', pathlib.Path(__file__).with_name('day_two_public_export.py'))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PublicProjection(unittest.TestCase):
    def fixture(self):
        return {'schema': 'constellation.m4.day_two_fixture.v1', 'disposition': 'DAY_TWO_PROCEDURE_DEMONSTRATED', 'service': 'nqd.service', 'scheduled_watchers': 0, 'upgrade': 'ALREADY_CURRENT_ONLY', 'binary_upgrade': 'NOT_RUN', 'restored_history_authorizes_effects': False, 'human_operator_trial': 'NOT_RUN'}

    def test_unselected_secrets_never_copied(self):
        result = self.fixture()
        result.update({'password': 'PRIVATE_SENTINEL', 'cases': [{'case': 'PRIVATE_SENTINEL', 'stderr': 'PRIVATE_SENTINEL'}], 'restored_typed_row_manifest': {'PRIVATE_SENTINEL': 1}})
        output = MODULE.project(json.dumps(result).encode())
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps(output))
        self.assertEqual(output['independent_acceptance'], 'NOT_ASSERTED')

    def test_selected_free_text_is_not_accepted(self):
        result = self.fixture()
        result['service'] = 'nqd.service PRIVATE_SENTINEL'
        with self.assertRaises(ValueError):
            MODULE.project(json.dumps(result).encode())

    def test_wrong_type_and_stronger_claim_are_refused(self):
        for key, value in [('scheduled_watchers', False), ('restored_history_authorizes_effects', True), ('human_operator_trial', 'PASSED')]:
            result = self.fixture()
            result[key] = value
            with self.assertRaises(ValueError):
                MODULE.project(json.dumps(result).encode())


if __name__ == '__main__':
    unittest.main()
