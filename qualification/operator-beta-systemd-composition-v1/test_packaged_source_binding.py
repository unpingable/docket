"""Exact historical package source is distinct from the current M3 driver."""
import hashlib
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock

import run_composed_two_vm as host


class PackagedSourceBinding(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parents[2]
        self.nq = SimpleNamespace(Refusal=ValueError,
            run=lambda command, **kwargs: subprocess.run(command, check=True, capture_output=True, **kwargs))

    def test_exact_packaged_driver_not_changed_current_path(self):
        facts = host.packaged_qualification_facts(self.root, self.nq)
        self.assertEqual(facts['driver']['sha256'],
            '9a86c31cc3d1fc18f8a890a0c25fb2ac95d5d75ed407fbe55e005e4f03035147')
        self.assertEqual(facts['builder']['sha256'],
            '62ceb6dd779a3645112b40d99090d2c4d1fe3b018610104a02ee6dc7fff3f93a')
        self.assertNotEqual(facts['driver']['sha256'],
            hashlib.sha256((self.root / host.builder.DRIVER_RELATIVE).read_bytes()).hexdigest())

    def test_wrong_declared_tree_refuses(self):
        with mock.patch.object(host.builder, 'DOCKET_TREE', '0' * 40):
            with self.assertRaisesRegex(ValueError, 'source tree differs'):
                host.packaged_qualification_facts(self.root, self.nq)

    def test_missing_fixed_source_refuses(self):
        with mock.patch.object(host.builder, 'DRIVER_RELATIVE', Path('missing-qualification-source.rs')):
            with self.assertRaisesRegex(ValueError, 'regular source blob'):
                host.packaged_qualification_facts(self.root, self.nq)

    def test_receipt_driver_mismatch_remains_detectable(self):
        facts = host.packaged_qualification_facts(self.root, self.nq)
        changed = {**facts, 'driver': {**facts['driver'], 'sha256': '0' * 64}}
        self.assertEqual(host.verify_packaged_qualification(self.root, self.nq, facts), facts)
        with self.assertRaisesRegex(ValueError, 'sources differ from the build receipt'):
            host.verify_packaged_qualification(self.root, self.nq, changed)

    def test_receipt_builder_mismatch_refuses(self):
        facts = host.packaged_qualification_facts(self.root, self.nq)
        changed = {**facts, 'builder': {**facts['builder'], 'sha256': '0' * 64}}
        with self.assertRaisesRegex(ValueError, 'sources differ from the build receipt'):
            host.verify_packaged_qualification(self.root, self.nq, changed)


if __name__ == '__main__':
    unittest.main()
