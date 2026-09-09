"""A full restored cut stays stable while later service history advances."""
from contextlib import closing
import pathlib
import sqlite3
import tempfile
import unittest

from day_two_cold_guest import retain_restored_snapshot
from day_two_restore import logical_manifest


class RestoredCut(unittest.TestCase):
    def test_snapshot_preserves_all_rows_before_later_status_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source, target = root / 'source.sqlite', root / 'restored.sqlite'
            with closing(sqlite3.connect(source)) as connection:
                connection.executescript('''
                    PRAGMA journal_mode=WAL;
                    CREATE TABLE status_events(id INTEGER PRIMARY KEY AUTOINCREMENT, value TEXT);
                    CREATE TABLE application_data(value BLOB);
                    INSERT INTO status_events(value) VALUES('restored');
                    INSERT INTO application_data VALUES(X'00FF');
                ''')
                connection.commit()
            before = logical_manifest(source)
            retain_restored_snapshot(source, target)
            self.assertEqual(logical_manifest(target), before)
            with closing(sqlite3.connect(source)) as connection:
                connection.execute("INSERT INTO status_events(value) VALUES('service-start')")
                connection.commit()
            self.assertNotEqual(logical_manifest(source), before)
            self.assertEqual(logical_manifest(target), before)
            with self.assertRaises(FileExistsError):
                retain_restored_snapshot(source, target)
            self.assertEqual(logical_manifest(target), before)


if __name__ == '__main__':
    unittest.main()
