import unittest
import m3_vm_inputs as inputs
import m3_guest_matrix as matrix


class InputTests(unittest.TestCase):
    def test_closed_package_set(self):
        with self.assertRaises(ValueError):
            inputs.verify({})
        self.assertEqual(len(inputs.PINS), 7)

    def test_finite_matrix_has_no_duplicate_occurrences(self):
        plan = matrix.inventory()
        self.assertEqual(len(plan), 61)
        self.assertEqual(len(set(plan)), 61)
        self.assertIn(('later', 'cleanup-foreign-operation-receipt'), plan)
        self.assertIn(('stage', 'normal-stage'), plan)


if __name__ == '__main__':
    unittest.main()
