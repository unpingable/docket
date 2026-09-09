import importlib.util
import json
import pathlib
import sqlite3
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('cold_guest', pathlib.Path(__file__).with_name('day_two_cold_guest.py'))
guest = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guest)


class ColdBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.directory.name)
        self.calls = []
        self.patches = [
            patch.object(guest, 'ROOT', self.root),
            patch.object(guest.os, 'geteuid', return_value=0),
            patch.object(guest.pwd, 'getpwnam', return_value=types.SimpleNamespace(pw_uid=1000, pw_gid=1000)),
            patch.object(guest.subprocess, 'run', side_effect=self.run_command),
            patch.object(guest, 'digest', return_value=guest.NEW_BINARY),
        ]
        for item in self.patches:
            item.start()
        self.addCleanup(self.directory.cleanup)
        for item in reversed(self.patches):
            self.addCleanup(item.stop)

    def run_command(self, argv, **kwargs):
        self.calls.append(argv)
        stdout = b'inactive\n' if argv[:2] == ['systemctl', 'show'] else b'{}\n'
        return subprocess.CompletedProcess(argv, 0, stdout, b'')

    def checkpoint(self, phase, digest=guest.NEW_BINARY):
        (self.root / 'CHECKPOINT.json').write_text(json.dumps({'phase': phase, 'binary_sha256': digest}))

    def test_inspection_does_not_resume_or_launch(self):
        self.checkpoint('NEW_ONE_PREACTIVATION')
        guest.main('inspect')
        self.assertEqual(self.calls, [['systemctl', 'show', 'nqd.service', '--property=ActiveState', '--value']])
        self.assertTrue((self.root / 'INSPECT-NEW_ONE_PREACTIVATION.json').exists())

    def test_inspection_rejects_changed_binary(self):
        self.checkpoint('NEW_ONE_PREACTIVATION', guest.OLD_BINARY)
        with self.assertRaises(AssertionError):
            guest.main('inspect')
        self.assertFalse((self.root / 'INSPECT-NEW_ONE_PREACTIVATION.json').exists())
        self.assertFalse(any(call[0] == 'dpkg' for call in self.calls))

    def test_post_cut_phase_refuses_old_rollback(self):
        self.checkpoint('POST_CUT_FORWARD_ONLY')
        with self.assertRaises(AssertionError):
            guest.main('rollback')
        self.assertFalse(any(call[0] == 'dpkg' or 'restore' in call for call in self.calls))

    def test_changed_pre_activation_rows_refuse_rollback(self):
        self.checkpoint('NEW_ONE_PREACTIVATION')
        cohort = self.root / 'cut-one'
        cohort.mkdir()
        database = cohort / 'nq.sqlite'
        connection = sqlite3.connect(database)
        connection.execute('CREATE TABLE evidence(value TEXT)')
        connection.commit()
        baseline = guest.logical_manifest(database)
        (self.root / 'cut-one-baseline.json').write_text(json.dumps(baseline))
        connection.execute("INSERT INTO evidence VALUES ('post-cut')")
        connection.commit()
        connection.close()
        with self.assertRaises(AssertionError):
            guest.main('rollback')
        self.assertFalse(any(call[0] == 'dpkg' or 'restore' in call for call in self.calls))


if __name__ == '__main__':
    unittest.main()
