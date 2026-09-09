import sqlite3
import tempfile
from pathlib import Path
import unittest
import m3_stage_cases as cases


class StageCaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        with sqlite3.connect(self.root / 'source.sqlite') as connection:
            connection.execute('CREATE TABLE maintenance_types (key TEXT PRIMARY KEY, value)')
            connection.execute("INSERT INTO maintenance_types VALUES ('int',7)")

    def test_content_seed_changes_actual_row_without_count_change(self):
        evidence = cases.seed('source-before-cut', self.root, self.root)
        self.assertNotEqual(evidence['source_sha256_before'], evidence['source_sha256_after_seed'])
        with sqlite3.connect(self.root / 'source.sqlite') as connection:
            self.assertEqual(connection.execute('SELECT * FROM maintenance_types').fetchall(), [('int',8)])

    def test_compaction_seed_preserved_and_never_overwritten(self):
        cases.seed('compaction-failure', self.root, self.root)
        before = (self.root / 'staging.sqlite').read_bytes()
        with self.assertRaises(FileExistsError):
            cases.seed('compaction-failure', self.root, self.root)
        self.assertEqual((self.root / 'staging.sqlite').read_bytes(), before)

    def test_space_seed_refuses_general_filesystem(self):
        with self.assertRaises(RuntimeError):
            cases.seed('temporary-space', self.root, self.root)
        self.assertFalse((self.root / 'qualification-space-reservation').exists())

    def test_closed_inventory_covers_all_stage_cuts(self):
        self.assertEqual(len(cases.CASES), len(set(cases.CASES)))
        self.assertEqual(len(cases.CASES), 12)
        self.assertTrue(all('cut-' + cut in cases.CASES for cut in cases.STAGE_CUTS))


if __name__ == '__main__':
    unittest.main()
