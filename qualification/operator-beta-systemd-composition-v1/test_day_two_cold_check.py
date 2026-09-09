import copy
import types
import unittest
import day_two_cold_check as checker


class ColdCheckerTests(unittest.TestCase):
    def test_missing_inspection_or_wrong_interruption_exit_refuses(self):
        nq = types.SimpleNamespace(Refusal=ValueError)
        valid = [{'step': name, 'exit': code} for name, code in checker.EXPECTED_STEPS]
        checker.verify_steps(valid, nq)
        for change in ('missing', 'zero_exit', 'reordered'):
            candidate = copy.deepcopy(valid)
            if change == 'missing':
                candidate.pop(1)
            elif change == 'zero_exit':
                candidate[0]['exit'] = 0
            else:
                candidate[4], candidate[5] = candidate[5], candidate[4]
            with self.subTest(change=change), self.assertRaises(ValueError):
                checker.verify_steps(candidate, nq)

    def test_manifest_checks_do_not_accept_counts_or_result_booleans(self):
        nq = types.SimpleNamespace(Refusal=ValueError)
        old = {'rows': 1, 'sha256': 'old'}
        empty = {'rows': 0, 'sha256': 'empty'}
        post = {'rows': 1, 'sha256': 'post'}
        valid = {'old-archive/db/nq.db': old, 'rollback-restored.sqlite': old, 'cut-one/nq.sqlite': empty, 'cut-two/nq.sqlite': post, 'forward-backup.sqlite': post}
        checker.verify_manifests(valid, empty, empty, nq)
        for key in ('rollback-restored.sqlite', 'cut-one/nq.sqlite', 'cut-two/nq.sqlite', 'forward-backup.sqlite'):
            changed = copy.deepcopy(valid)
            changed[key] = {**changed[key], 'sha256': 'same-count-different-content'}
            with self.subTest(key=key), self.assertRaises(ValueError):
                checker.verify_manifests(changed, empty, empty, nq)


if __name__ == '__main__':
    unittest.main()
