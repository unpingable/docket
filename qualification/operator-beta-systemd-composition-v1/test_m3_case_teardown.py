import subprocess
import unittest
from unittest.mock import patch
from m3_case_teardown import stop_unit, stop_established


class StopTests(unittest.TestCase):
    def result(self, exit=0, load='loaded', active='inactive', sub='dead', pid='0', query=0):
        with patch('m3_case_teardown.subprocess.run', side_effect=[
            subprocess.CompletedProcess([], exit, b'', b'not loaded' if exit else b''),
            subprocess.CompletedProcess([], query, f'LoadState={load}\nActiveState={active}\nSubState={sub}\nMainPID={pid}\n'.encode(), b'')]):
            return stop_unit('labelwatch-relief-test.service')

    def test_stopped_and_missing(self):
        self.assertTrue(stop_established(self.result()))
        absent = self.result(exit=5, load='not-found')
        self.assertTrue(stop_established(absent))
        self.assertEqual(absent['exit'], 5)

    def test_failure_and_uncertainty_stay_refused(self):
        for changes in ({'exit': 1}, {'exit': 5}, {'query': 1}, {'active': 'active'},
                        {'sub': 'running'}, {'pid': '123'}, {'load': 'error'}):
            with self.subTest(changes=changes):
                self.assertFalse(stop_established(self.result(**changes)))

    def test_timeout_is_retained_not_retried(self):
        with patch('m3_case_teardown.subprocess.run', side_effect=subprocess.TimeoutExpired('systemctl', 20)) as run:
            result = stop_unit('labelwatch-relief-test.service')
        self.assertFalse(stop_established(result))
        self.assertIsNone(result['exit'])
        self.assertEqual(run.call_count, 1)


if __name__ == '__main__':
    unittest.main()
