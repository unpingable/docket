import subprocess
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch
from m3_case_teardown import stop_unit, stop_established, observe_cgroup


class StopTests(unittest.TestCase):
    def result(self, exit=0, load='loaded', active='inactive', sub='dead', pid='0', control='0', query=0):
        with patch('m3_case_teardown.subprocess.run', side_effect=[
            subprocess.CompletedProcess([], exit, b'', b'not loaded' if exit else b''),
            subprocess.CompletedProcess([], query, f'LoadState={load}\nActiveState={active}\nSubState={sub}\nMainPID={pid}\nControlPID={control}\nControlGroup=\nKillMode=control-group\nResult=exit-code\nExecMainStatus=1\n'.encode(), b'')]):
            return stop_unit('labelwatch-relief-test.service')

    def test_stopped_and_missing(self):
        self.assertTrue(stop_established(self.result()))
        absent = self.result(exit=5, load='not-found')
        self.assertTrue(stop_established(absent))
        self.assertEqual(absent['exit'], 5)
        failed = self.result(active='failed', sub='failed')
        self.assertTrue(stop_established(failed))
        self.assertEqual(failed['state']['Result'], 'exit-code')
        self.assertEqual(failed['state']['ExecMainStatus'], '1')

    def test_failure_and_uncertainty_stay_refused(self):
        for changes in ({'exit': 1}, {'exit': 5}, {'query': 1}, {'active': 'active'},
                        {'sub': 'running'}, {'pid': '123'}, {'control': '123'}, {'load': 'error'},
                        {'active': 'failed'}, {'sub': 'failed'}, {'active': 'activating'},
                        {'active': 'deactivating'}, {'active': 'failed', 'sub': 'failed', 'pid': '9'}):
            with self.subTest(changes=changes):
                self.assertFalse(stop_established(self.result(**changes)))

    def test_timeout_is_retained_not_retried(self):
        with patch('m3_case_teardown.subprocess.run', side_effect=subprocess.TimeoutExpired('systemctl', 20)) as run:
            result = stop_unit('labelwatch-relief-test.service')
        self.assertFalse(stop_established(result))
        self.assertIsNone(result['exit'])
        self.assertEqual(run.call_count, 1)

    def test_exact_cgroup_empty_populated_absent_and_unknown(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'cgroup.controllers').write_text('cpu memory\n')
            group = root / 'enrolled.service'
            self.assertEqual(observe_cgroup('/enrolled.service', root)['observation'], 'ABSENT')
            group.mkdir()
            self.assertEqual(observe_cgroup('/enrolled.service', root)['observation'], 'NOT_OBSERVABLE')
            for value, expected in [('0', 'EMPTY'), ('1', 'POPULATED'), ('unknown', 'NOT_OBSERVABLE')]:
                (group / 'cgroup.events').write_text('populated ' + value + '\n')
                observed = observe_cgroup('/enrolled.service', root)
                self.assertEqual(observed['observation'], expected)
                record = self.result(active='failed', sub='failed')
                record['state']['ControlGroup'] = '/enrolled.service'
                record['cgroup'] = observed
                self.assertEqual(stop_established(record), value == '0')
            (root / 'alias').symlink_to(group, target_is_directory=True)
            for bad in ('/', '/../elsewhere', '/alias', None):
                self.assertEqual(observe_cgroup(bad, root)['observation'], 'NOT_OBSERVABLE')


if __name__ == '__main__':
    unittest.main()
