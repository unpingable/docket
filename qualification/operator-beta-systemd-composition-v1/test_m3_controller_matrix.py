import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
import m3_controller_matrix as matrix
import run_m3_two_vm as host


class FixedControllerTests(unittest.TestCase):
    def test_closed_inventory_count_and_no_ordinary_schema_promotion(self):
        module = types.SimpleNamespace(case_inventory=lambda: {str(n): None for n in range(41)})
        with patch.dict('sys.modules', {'m3_loss_barrier': module}):
            self.assertEqual(len(matrix.inventory()), 41)
            module.case_inventory = lambda: {'one': None}
            with self.assertRaises(ValueError):
                matrix.inventory()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'M3-RESULT.json').write_text(json.dumps({'schema': matrix.SCHEMA}))
            with self.assertRaisesRegex(ValueError, 'exact M3 variant'):
                host.check_run(root, object())

    def test_driver_receipt_requires_two_exact_builds(self):
        import hashlib
        with tempfile.TemporaryDirectory() as temporary:
            receipt = Path(temporary) / 'receipt.json'
            rows = [{'binary_sha256': 'a' * 64, 'package_sha256': 'b' * 64}] * 2
            receipt.write_text(json.dumps({'results': rows}))
            with patch.dict(matrix.inputs.PINS, {'driver_receipt': hashlib.sha256(receipt.read_bytes()).hexdigest(),
                    'driver_package': 'b' * 64}):
                self.assertEqual(matrix.driver_digest(receipt), 'a' * 64)
                receipt.write_text('{}')
                with self.assertRaises(ValueError):
                    matrix.driver_digest(receipt)


if __name__ == '__main__':
    unittest.main()
