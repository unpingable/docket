import importlib.util
import pathlib
import sqlite3
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('day_two_restore', pathlib.Path(__file__).with_name('day_two_restore.py'))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ManifestControls(unittest.TestCase):
    def test_changed_contents_with_equal_counts_do_not_match(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'fixture.sqlite'
            connection = sqlite3.connect(path)
            connection.execute('CREATE TABLE facts (value)')
            connection.execute('INSERT INTO facts VALUES (?)', ('original',))
            connection.commit()
            before = MODULE.logical_manifest(path)
            connection.execute('UPDATE facts SET value=?', ('modified',))
            connection.commit()
            after = MODULE.logical_manifest(path)
            connection.close()
            self.assertEqual(before['tables']['facts']['rows'], after['tables']['facts']['rows'])
            self.assertNotEqual(before, after)

    def test_sqlite_types_and_duplicate_rows_remain_distinct(self):
        self.assertNotEqual(MODULE.encoded(b'123'), MODULE.encoded('123'))
        self.assertNotEqual(MODULE.encoded(123), MODULE.encoded('123'))
        self.assertNotEqual(MODULE.encoded(None), MODULE.encoded(''))


if __name__ == '__main__':
    unittest.main()
