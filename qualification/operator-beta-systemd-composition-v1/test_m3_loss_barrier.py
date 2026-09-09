"""Actual bounded local child-process controls, not VM/custody acceptance."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import m3_loss_barrier as barrier


class LossBarrierTests(unittest.TestCase):
    def test_actual_exact_child_exit_and_bound_release(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)'])
            try:
                enrolled = barrier.identity(child.pid)
                record = barrier.arrive(root, barrier.CUTS[0], enrolled, {'qualification': 'LOCAL_CHILD_CONTROL_NOT_OWNER_EVIDENCE'})
                result = barrier.terminate_and_release(root, record, enrolled)
                self.assertTrue(result['observed_exit'])
                self.assertEqual(child.wait(timeout=2), -9)
                barrier.await_release(root, record, .2)
                self.assertEqual((root / 'COMPANION-EXIT.json').read_bytes(), (root / 'RELEASE.json').read_bytes())
            finally:
                if child.poll() is None:
                    child.kill()
                child.wait()

    def test_wrong_enrollment_does_not_signal_child(self):
        with tempfile.TemporaryDirectory() as temporary:
            child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)'])
            try:
                enrolled = barrier.identity(child.pid)
                record = barrier.arrive(Path(temporary), barrier.CUTS[1], enrolled, {})
                wrong = dict(enrolled, start_ticks=enrolled['start_ticks'] + 1)
                with self.assertRaisesRegex(ValueError, 'separately enrolled'):
                    barrier.terminate_and_release(temporary, record, wrong)
                self.assertIsNone(child.poll())
                self.assertFalse((Path(temporary) / 'RELEASE.json').exists())
            finally:
                child.kill()
                child.wait()

    def test_absent_or_substituted_release_never_resumes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record = {'companion': {'pid': 123, 'start_ticks': 456}, 'cut': barrier.CUTS[0]}
            with self.assertRaises(TimeoutError):
                barrier.await_release(root, record, .02)
            (root / 'RELEASE.json').write_text('{}')
            with self.assertRaisesRegex(ValueError, 'exact barrier'):
                barrier.await_release(root, record, .02)


if __name__ == '__main__':
    unittest.main()
