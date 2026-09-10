"""Real subprocess failure logs and retained partial fixture occurrence."""
import argparse
import json
import pathlib
import os
import stat
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


class SuccessfulOutputCustody(unittest.TestCase):
    def make_output(self, root: pathlib.Path) -> pathlib.Path:
        output = root / 'output'
        output.mkdir(mode=0o700)
        for index, name in enumerate(sorted(builder.expected_output_files())):
            (output / name).write_bytes(f'evidence-{index}'.encode())
        return output

    def test_seal_retains_two_distinct_cases_and_enforces_modes(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = self.make_output(pathlib.Path(temporary))
            builder.seal_output(output)
            builder.verify_output_modes(output)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o555)
            identities = {
                (output / name).stat().st_ino
                for name in (builder.PACKAGE_FILE, *builder.CASE_PACKAGE_FILES.values())
            }
            self.assertEqual(len(identities), 3)
            self.assertEqual(
                {stat.S_IMODE(path.stat().st_mode) for path in output.iterdir()},
                {0o444},
            )

    def test_writable_retained_evidence_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = self.make_output(pathlib.Path(temporary))
            builder.seal_output(output)
            evidence = output / builder.CASE_PACKAGE_FILES['b']
            os.chmod(evidence, 0o644)
            with self.assertRaisesRegex(builder.Refusal, 'mode/custody differs'):
                builder.verify_output_modes(output)

    def test_missing_second_case_refuses_before_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = self.make_output(pathlib.Path(temporary))
            (output / builder.CASE_PACKAGE_FILES['b']).unlink()
            with self.assertRaisesRegex(builder.Refusal, 'closed artifact inventory'):
                builder.seal_output(output)

    def test_hardlinked_case_refuses_independent_custody(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = self.make_output(pathlib.Path(temporary))
            second = output / builder.CASE_PACKAGE_FILES['b']
            second.unlink()
            os.link(output / builder.CASE_PACKAGE_FILES['a'], second)
            with self.assertRaisesRegex(builder.Refusal, 'independently owned'):
                builder.seal_output(output)

    def test_prior_receipt_schema_cannot_transfer(self):
        receipt = {field: {} for field in builder.RECEIPT_FIELDS}
        receipt.update(schema='constellation.operator_beta.final_pin_fixture_build.v2',
                       limitations=builder.LIMITATIONS)
        raw = builder.canonical(receipt) + b'\n'
        with self.assertRaisesRegex(builder.Refusal, 'not exact canonical V3'):
            builder.validate_receipt_structure(receipt, raw)


if __name__ == '__main__':
    unittest.main()
