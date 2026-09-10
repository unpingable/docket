"""Real subprocess failure logs and retained partial fixture occurrence."""
import argparse
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

import build_bookworm_fixture as builder


class FailureRetention(unittest.TestCase):
    def test_failed_subprocess_retains_both_streams_without_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = pathlib.Path(temporary) / 'build.log'
            with self.assertRaisesRegex(builder.Refusal, 'exited 23'):
                builder.run_logged([sys.executable, '-c',
                                    'import sys; print("out"); print("err", file=sys.stderr); sys.exit(23)'], log)
            self.assertEqual(set(log.read_text().splitlines()), {'out', 'err'})
            before = log.read_bytes()
            with self.assertRaises(FileExistsError):
                builder.run_logged([sys.executable, '-c', 'raise SystemExit(0)'], log)
            self.assertEqual(log.read_bytes(), before)

    def test_missing_executable_retains_created_log(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = pathlib.Path(temporary) / 'build.log'
            with self.assertRaises(FileNotFoundError):
                builder.run_logged([str(pathlib.Path(temporary) / 'absent')], log)
            self.assertTrue(log.is_file())

    def test_failed_occurrence_keeps_prior_case_and_scratch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            args = argparse.Namespace(output=root / 'output', ag_source=root,
                                      docket_source=root, ag_registry_seed=root, docket_vendor=root)

            def partial_case(label, scratch, *_args):
                case = scratch / label
                case.mkdir()
                (case / 'retained.log').write_text(label)
                if label == 'b':
                    raise builder.Refusal('second build failed')
                return {'package': {}, 'binaries': {}}

            with mock.patch.object(builder.os, 'getuid', return_value=1000), \
                 mock.patch.object(builder.os, 'getgid', return_value=1000), \
                 mock.patch.object(builder, 'source_facts', return_value={}), \
                 mock.patch.object(builder, 'docket_vendor_facts', return_value={'tree_sha256': 'a' * 64, 'regular_files': 1}), \
                 mock.patch.object(builder, 'registry_facts', return_value={}), \
                 mock.patch.object(builder, 'image_facts', return_value={}), \
                 mock.patch.object(builder, 'build_case', side_effect=partial_case):
                with self.assertRaisesRegex(builder.Refusal, 'second build failed'):
                    builder.build(args)
            record = json.loads((args.output / 'BUILD_FAILURE.json').read_bytes())
            self.assertEqual(record['state'], 'BUILD_INCOMPLETE')
            self.assertIs(record['automatic_retry'], False)
            scratch = pathlib.Path(record['scratch'])
            self.assertEqual((scratch / 'a/retained.log').read_text(), 'a')
            self.assertEqual((scratch / 'b/retained.log').read_text(), 'b')
            self.assertFalse((args.output / 'fixture-build-receipt.v1.json').exists())

    def test_docket_vendor_mutation_after_build_cases_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            args = argparse.Namespace(output=root / 'output', ag_source=root,
                                      docket_source=root, ag_registry_seed=root,
                                      ag_registry_receipt=root / 'registry.json',
                                      ag_registry_receipt_sha256='b' * 64,
                                      docket_vendor=root)
            admitted = {'tree_sha256': 'a' * 64, 'regular_files': 1}
            changed = {'tree_sha256': 'c' * 64, 'regular_files': 1}
            case = {'package': {}, 'binaries': {}}
            with mock.patch.object(builder.os, 'getuid', return_value=1000), \
                 mock.patch.object(builder.os, 'getgid', return_value=1000), \
                 mock.patch.object(builder, 'source_facts', return_value={}), \
                 mock.patch.object(builder, 'docket_vendor_facts', side_effect=[admitted, changed]), \
                 mock.patch.object(builder, 'registry_facts', return_value={}), \
                 mock.patch.object(builder, 'image_facts', return_value={}), \
                 mock.patch.object(builder, 'build_case', return_value=case):
                with self.assertRaisesRegex(builder.Refusal, 'changed during build'):
                    builder.build(args)
            failure = json.loads((args.output / 'BUILD_FAILURE.json').read_bytes())
            self.assertEqual(failure['state'], 'BUILD_INCOMPLETE')


if __name__ == '__main__':
    unittest.main()
