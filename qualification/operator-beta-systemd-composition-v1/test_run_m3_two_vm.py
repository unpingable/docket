"""Host-adapter controls only; these do not establish governed VM execution."""
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import run_m3_two_vm as host
import m3_guest_matrix as batch


class HostControls(unittest.TestCase):
    def test_manifest_covers_nested_terminal_named_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'nested').mkdir()
            (root / 'nested/M3-RESULT.json').write_text('retained evidence')
            (root / 'M3-RESULT.json').write_text('outer seal')
            self.assertEqual([item['path'] for item in host.make_manifest(root)['files']], ['nested/M3-RESULT.json'])
            (root / 'substitution').symlink_to(root / 'nested/M3-RESULT.json')
            with self.assertRaisesRegex(ValueError, 'symlink'):
                host.make_manifest(root)

    def test_archive_refuses_duplicate_and_parent_entries(self):
        for names in [('same', 'same'), ('../outside',), ('/absolute',)]:
            with self.subTest(names=names), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive = root / 'evidence.tar'
                with tarfile.open(archive, 'w') as stream:
                    for name in names:
                        item = tarfile.TarInfo(name)
                        item.size = 1
                        stream.addfile(item, io.BytesIO(b'x'))
                with self.assertRaisesRegex(ValueError, 'ambiguous'):
                    host.extract(archive, root / 'unpacked')
                self.assertFalse((root / 'outside').exists())

    def test_actual_batch_nonzero_and_timeout_are_retained(self):
        for code, timeout, expected in [('raise SystemExit(77)', 2, 77),
                ('import time; time.sleep(5)', .03, 'OUTCOME_UNKNOWN_TIMEOUT_NO_RETRY')]:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary)
                with self.assertRaisesRegex(RuntimeError, 'no new invocation'):
                    batch.call([sys.executable, '-c', code], output, 'producer', timeout)
                self.assertEqual(json.loads((output / 'producer.exit.json').read_bytes()), {'exit': expected})
                self.assertTrue((output / 'producer.stdout').exists())

    def test_failure_after_m3_start_preserves_guest(self):
        class Parent:
            terminated = False
            def terminate_guests(self):
                self.terminated = True
            def state(self, phase, next_action, **facts):
                self.observed = (phase, next_action)
        with patch.object(host.composition, 'producer_class', return_value=Parent):
            producer = host.producer_class(object())()
            producer.m3_started = True
            producer.terminate_guests()
            self.assertFalse(producer.terminated)
            self.assertEqual(producer.observed[0], 'm3_failed_no_explicit_guest_termination')
            producer.m3_started = False
            producer.terminate_guests()
            self.assertTrue(producer.terminated)

    def test_exact_git_checker_import_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            producer, checker = root / 'producer', root / 'checker'
            subprocess.run(['git', 'init', '-q', str(producer)], check=True)
            def git(*args):
                return subprocess.check_output(['git', '-C', str(producer), '-c', 'user.name=M3 fixture',
                    '-c', 'user.email=m3@example.invalid', *args], stderr=subprocess.STDOUT).decode().strip()
            source = producer / host.HOST_RELATIVE
            source.parent.mkdir(parents=True)
            source.write_text("PRODUCER_HEAD = 'UNFROZEN'\nPRODUCER_TREE = 'UNFROZEN'\n")
            (source.parent / 'imported.py').write_text('EXACT = True\n')
            git('add', '.')
            git('commit', '-qm', 'producer fixture')
            head, tree = git('rev-parse', 'HEAD'), git('rev-parse', 'HEAD^{tree}')
            git('worktree', 'add', '--detach', str(checker), head)
            b_source = checker / host.HOST_RELATIVE
            b_source.write_text(f"PRODUCER_HEAD = '{head}'\nPRODUCER_TREE = '{tree}'\n")
            def commit_b():
                subprocess.run(['git', '-C', str(checker), 'add', '.'], check=True)
                subprocess.run(['git', '-C', str(checker), '-c', 'user.name=M3 fixture',
                    '-c', 'user.email=m3@example.invalid', 'commit', '-qm', 'checker fixture'], check=True)
                return subprocess.check_output(['git', '-C', str(checker), 'rev-parse', 'HEAD'], text=True).strip()
            b_head = commit_b()
            self.assertEqual(host.checker_contract(producer, checker, head, b_head)[0], {'head': head, 'tree': tree})
            (b_source.parent / 'imported.py').write_text('EXACT = False\n')
            b_head = commit_b()
            with self.assertRaisesRegex(ValueError, 'outside exact host pins'):
                host.checker_contract(producer, checker, head, b_head)

    def test_phase_failure_collects_once_before_propagating(self):
        class Parent:
            pass
        with patch.object(host.composition, 'producer_class', return_value=Parent):
            producer = host.producer_class(object())()
            observed = []
            def fail(control, target):
                observed.append('single phase')
                raise RuntimeError('outcome uncertain')
            producer.m3_then_teardown = fail
            producer.capture_failure = lambda target, error: observed.append(('capture', str(error)))
            with self.assertRaisesRegex(RuntimeError, 'outcome uncertain'):
                producer.teardown('control', 'target')
            self.assertEqual(observed, ['single phase', ('capture', 'outcome uncertain')])

    def test_matrix_refusal_cannot_be_promoted_by_success_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'matrix').mkdir()
            (root / 'matrix/RESULT.json').write_text(json.dumps({'disposition': 'FINITE_CASE_CHECKS_COMPLETED',
                'count': len(host.inventory()), 'independent_final_review': 'REQUIRED', 'production': 'NOT_RUN'}))
            (root / 'matrix/REFUSAL.json').write_text('{}')
            with self.assertRaisesRegex(ValueError, 'also records refusal'):
                host.check_matrix(root)


if __name__ == '__main__':
    unittest.main()
