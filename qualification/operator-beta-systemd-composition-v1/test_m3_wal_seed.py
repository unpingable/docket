"""Run explicitly with M3_LABELWATCH_SOURCE and separate /data/git,/tmp filesystems."""
import gc
import hashlib
import importlib.util
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

import m3_stage_cases as stage
from m3_later_cases import Case


class ActualInitializerWalTests(unittest.TestCase):
    def test_both_seed_paths_close_wal_before_recorded_cut(self):
        source = Path(os.environ['M3_LABELWATCH_SOURCE'])
        sys.path.insert(0, str(source / 'src'))
        spec = importlib.util.spec_from_file_location('enrollment', source / 'scripts/m3_fixture_enrollment.py')
        enrollment = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(enrollment)
        for mode in ('legacy-control', 'stage', 'later'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(dir='/data/git') as target, tempfile.TemporaryDirectory(dir='/tmp') as backup:
                fixture = Path(target) / 'operation'
                enrollment.initialize(fixture, Path(backup), '17a2dedb2528025ec0c05b173d9be9b4b8b4ba53')
                database = fixture / 'source.sqlite'
                connection = sqlite3.connect(database)
                try:
                    self.assertEqual(connection.execute('PRAGMA journal_mode').fetchone()[0], 'wal')
                finally:
                    connection.close()
                before = hashlib.sha256(database.read_bytes()).hexdigest()
                if mode == 'legacy-control':
                    # The old context-manager form commits but does not close.
                    with sqlite3.connect(database) as connection:
                        connection.execute("UPDATE maintenance_types SET value=8 WHERE key='int'")
                    premature = hashlib.sha256(database.read_bytes()).hexdigest()
                    self.assertEqual(before, premature)
                    self.assertTrue(Path(str(database) + '-wal').exists())
                    connection.close()
                    self.assertNotEqual(premature, hashlib.sha256(database.read_bytes()).hexdigest())
                    continue
                if mode == 'stage':
                    evidence = stage.seed('source-before-cut', fixture, Path(target))
                    recorded = evidence['source_sha256_after_seed']
                else:
                    case = Case.__new__(Case)
                    case.base = {'source': str(database)}
                    case.mutate()
                    recorded = hashlib.sha256(database.read_bytes()).hexdigest()
                self.assertNotEqual(before, recorded)
                gc.collect()
                connection = sqlite3.connect(database)
                try:
                    self.assertEqual(connection.execute("SELECT value FROM maintenance_types WHERE key='int'").fetchall(), [(8,)])
                    self.assertEqual(connection.execute('SELECT count(*) FROM maintenance_types').fetchone()[0], 5)
                finally:
                    connection.close()
                gc.collect()
                self.assertEqual(recorded, hashlib.sha256(database.read_bytes()).hexdigest())
                self.assertFalse(Path(str(database) + '-wal').exists())


if __name__ == '__main__':
    unittest.main()
