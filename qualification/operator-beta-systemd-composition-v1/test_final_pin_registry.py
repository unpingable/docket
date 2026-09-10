"""Local-only REGISTRY-SEED002 / BUILD002-input deterministic controls."""
import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("registry_builder_test", HERE / "build_bookworm_fixture.py")
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)
registry = builder.registry


class RegistryInputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        body = b"local crate fixture"
        checksum = hashlib.sha256(body).hexdigest()
        self.lock = self.source / "Cargo.lock"
        self.lock.write_text('version = 3\n[[package]]\nname = "fixture"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "' + checksum + '"\n')
        self.cache = self.root / "input-registry"
        (self.cache / "cache/index").mkdir(parents=True)
        (self.cache / "cache/index/fixture-1.0.0.crate").write_bytes(body)
        (self.cache / "index/index/.cache").mkdir(parents=True)
        (self.cache / "index/index/.cache/fixture").write_bytes(b"index fixture")
        self.args = argparse.Namespace(source=self.source, output=self.root / "seed002", receipt=self.root / "receipt002.json")
        self.patches = [mock.patch.object(registry, "SOURCE_REGISTRY", self.cache),
                        mock.patch.object(registry, "LOCK_SHA256", registry.sha256(self.lock)),
                        mock.patch.object(registry, "exact_source", return_value=self.source)]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        # Only campaign-created tiny test fixtures, never retained real seeds.
        for path in [self.root, *self.root.rglob("*")]:
            if not path.is_symlink():
                path.chmod(0o755 if path.is_dir() else 0o644)
        self.temp.cleanup()

    def prepare(self):
        with mock.patch("builtins.print"):
            registry.prepare(self.args)
        return registry.sha256(self.args.receipt)

    def validate(self, receipt_sha):
        return registry.validate_seed(self.args.output, self.args.receipt, receipt_sha, self.lock)

    def test_receipt_binds_final_readonly_state_including_directories(self):
        receipt_sha = self.prepare()
        receipt = json.loads(self.args.receipt.read_bytes())
        digest, count, total = registry.tree_digest(self.args.output, registry.TREE_DOMAIN)
        self.assertEqual(receipt["seed"], {"tree_sha256": digest, "regular_files": count, "bytes": total})
        self.validate(receipt_sha)
        for path in [self.args.output, *self.args.output.rglob("*")]:
            self.assertEqual(path.stat().st_mode & 0o777, 0o555 if path.is_dir() else 0o444)
        self.assertEqual(self.args.receipt.stat().st_mode & 0o777, 0o444)

    def test_file_mode_tamper_refuses_even_if_still_readonly(self):
        receipt_sha = self.prepare()
        archive = next(self.args.output.rglob("*.crate"))
        archive.chmod(0o440)
        with self.assertRaisesRegex(registry.Refusal, "final tree differs"):
            self.validate(receipt_sha)

    def test_directory_mode_tamper_refuses(self):
        receipt_sha = self.prepare()
        (self.args.output / "registry").chmod(0o550)
        with self.assertRaisesRegex(registry.Refusal, "final tree differs"):
            self.validate(receipt_sha)

    def test_writable_seed_refuses(self):
        receipt_sha = self.prepare()
        self.args.output.chmod(0o755)
        with self.assertRaisesRegex(registry.Refusal, "writable"):
            self.validate(receipt_sha)

    def test_index_content_tamper_refuses(self):
        receipt_sha = self.prepare()
        index = self.args.output / "registry/index/index/.cache/fixture"
        index.chmod(0o644)
        index.write_bytes(b"changed")
        index.chmod(0o444)
        with self.assertRaisesRegex(registry.Refusal, "final tree differs"):
            self.validate(receipt_sha)

    def test_changed_receipt_hash_refuses(self):
        self.prepare()
        with self.assertRaisesRegex(registry.Refusal, "receipt hash differs"):
            self.validate("0" * 64)

    def test_symlink_receipt_read_refuses(self):
        self.prepare()
        alias = self.root / "receipt-alias"
        alias.symlink_to(self.args.receipt)
        with self.assertRaises(OSError):
            registry.validate_seed(self.args.output, alias, registry.sha256(self.args.receipt), self.lock)

    def test_interrupted_finalization_retains_consumed_paths_without_valid_receipt(self):
        with mock.patch.object(registry, "finalize_readonly", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                registry.prepare(self.args)
        self.assertTrue(self.args.output.is_dir())
        self.assertEqual(self.args.receipt.read_bytes(), b"")
        with self.assertRaisesRegex(registry.Refusal, "already exists"):
            registry.prepare(self.args)

    def test_concurrent_output_creation_is_not_replaced(self):
        real_exclusive = registry.exclusive_file
        def create_then_substitute(path):
            descriptor = real_exclusive(path)
            self.args.output.mkdir()
            (self.args.output / "retained").write_bytes(b"other local fixture")
            return descriptor
        with mock.patch.object(registry, "exclusive_file", side_effect=create_then_substitute):
            with self.assertRaises(FileExistsError):
                registry.prepare(self.args)
        self.assertEqual((self.args.output / "retained").read_bytes(), b"other local fixture")
        self.assertEqual(self.args.receipt.read_bytes(), b"")

    def test_dangling_seed_refuses_before_source_and_does_not_follow(self):
        self.args.output.symlink_to(self.root / "missing-target")
        with self.assertRaisesRegex(registry.Refusal, "already exists"):
            registry.prepare(self.args)
        registry.exact_source.assert_not_called()
        self.assertFalse(self.args.receipt.exists())
        self.assertFalse((self.root / "missing-target").exists())

    def test_dangling_receipt_refuses_before_source_and_does_not_follow(self):
        self.args.receipt.symlink_to(self.root / "missing-target")
        with self.assertRaisesRegex(registry.Refusal, "already exists"):
            registry.prepare(self.args)
        registry.exact_source.assert_not_called()
        self.assertFalse(self.args.output.exists())
        self.assertFalse((self.root / "missing-target").exists())

    def test_exclusive_receipt_refuses_substitution_after_absence_cut(self):
        registry.require_absent(self.args.receipt)
        self.args.receipt.symlink_to(self.root / "missing-target")
        with self.assertRaises(FileExistsError):
            registry.exclusive_file(self.args.receipt)
        self.assertFalse((self.root / "missing-target").exists())

    def test_two_derivatives_are_distinct_writable_and_seed_unchanged(self):
        receipt_sha = self.prepare()
        first, second = self.root / "cargo-a", self.root / "cargo-b"
        builder.derive_cargo_home(self.args.output, first)
        builder.derive_cargo_home(self.args.output, second)
        relative = "registry/cache/index/fixture-1.0.0.crate"
        paths = [self.args.output / relative, first / relative, second / relative]
        self.assertEqual(len({(p.stat().st_dev, p.stat().st_ino) for p in paths}), 3)
        self.assertEqual(paths[1].stat().st_mode & 0o777, 0o644)
        paths[1].write_bytes(b"case-a mutation")
        self.assertEqual(paths[0].read_bytes(), paths[2].read_bytes())
        self.validate(receipt_sha)

    def test_dangling_cargo_home_and_build_output_refuse(self):
        self.prepare()
        destination = self.root / "cargo"
        destination.symlink_to(self.root / "missing-target")
        with self.assertRaisesRegex(registry.Refusal, "already exists"):
            builder.derive_cargo_home(self.args.output, destination)
        with self.assertRaisesRegex(registry.Refusal, "already exists"):
            builder.build(argparse.Namespace(output=destination))

    def test_actual_build_case_uses_registry_derivative_without_vendor_config(self):
        receipt_sha = self.prepare()
        driver = self.root / "driver.rs"
        driver.write_text("fn main() {}")
        def extract(_source, destination):
            (destination / "crates/ag-app/examples").mkdir(parents=True)
            (destination / "crates/ag-app/Cargo.toml").write_text("[features]\n")
        commands = []
        def log(command, destination):
            commands.append(command)
            destination.write_bytes(b"local mocked build, not executed")
        with mock.patch.object(builder, "extract_source", side_effect=extract), \
             mock.patch.object(builder, "run_logged", side_effect=log), \
             mock.patch.object(builder, "assemble", return_value=self.root / "not-built.deb"), \
             mock.patch.object(builder, "package_facts", return_value={}), \
             mock.patch.object(builder, "binary_facts", return_value={}):
            for label in ("a", "b"):
                builder.build_case(label, self.root, self.source, self.source,
                                   self.args.output, self.root / "docket-vendor", driver)
                config = (self.root / label / "ag/.cargo/config.toml").read_text()
                self.assertEqual(config, "[net]\noffline = true\n")
        for command in commands:
            self.assertEqual(command[command.index("--network") + 1], "none")
            self.assertEqual(command[command.index("--pull") + 1], "never")
            self.assertIn("--locked", command)
            self.assertIn("--offline", command)
        for label, command in zip(("a", "b"), commands[::2]):
            self.assertIn(f"{self.args.output}:/ag-registry-seed:ro", command)
            self.assertIn(f"{self.root / label / 'ag-cargo'}:/cargo-home:rw", command)
            self.assertFalse(any(":/ag-vendor:" in part for part in command))
        self.validate(receipt_sha)


if __name__ == "__main__":
    unittest.main()
