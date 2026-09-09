#!/usr/bin/env python3
"""Direct boundary tests for the qualification-only composition fixture builder."""

from __future__ import annotations

import copy
import importlib.util
import io
import pathlib
import stat
import tarfile
import tempfile
import unittest
from unittest import mock


HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "composition_fixture_builder", HERE / "build_bookworm_fixture.py"
)
assert SPEC is not None and SPEC.loader is not None
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class FixtureBuilderTests(unittest.TestCase):
    def test_vendor_digest_binds_path_mode_and_content_and_refuses_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            first = root / "crate-a"
            first.write_bytes(b"one")
            first.chmod(0o644)
            original = builder.tree_digest(root, b"test-domain")

            first.chmod(0o600)
            self.assertNotEqual(original, builder.tree_digest(root, b"test-domain"))
            first.chmod(0o644)
            first.write_bytes(b"two")
            self.assertNotEqual(original, builder.tree_digest(root, b"test-domain"))
            first.write_bytes(b"one")
            first.rename(root / "crate-b")
            self.assertNotEqual(original, builder.tree_digest(root, b"test-domain"))
            (root / "alias").symlink_to(root / "crate-b")
            with self.assertRaisesRegex(builder.Refusal, "non-regular entry"):
                builder.tree_digest(root, b"test-domain")

    def test_normalized_commands_are_network_disabled_and_input_explicit(self) -> None:
        commands = builder.normalized_commands()
        self.assertEqual(set(commands), {"ag", "docket"})
        for kind, command in commands.items():
            expected = builder.build_command(
                pathlib.Path(f"<{kind.upper()}_SOURCE>"),
                pathlib.Path(f"<{kind.upper()}_VENDOR>"),
                pathlib.Path("<CARGO_HOME>"),
                pathlib.Path("<TARGET>"),
                kind,
            )
            self.assertEqual(command, expected)
            self.assertIn("--network", command)
            self.assertEqual(command[command.index("--network") + 1], "none")
            self.assertEqual(command[command.index("--pull") + 1], "never")
            self.assertIn("--locked", command)
            self.assertIn("--offline", command)
            self.assertIn(f"<{kind.upper()}_SOURCE>:/{kind}:ro", command)
            self.assertIn(f"<{kind.upper()}_VENDOR>:/{kind}-vendor:ro", command)
            for mount in (
                f"<{kind.upper()}_SOURCE>:/{kind}:ro",
                f"<{kind.upper()}_VENDOR>:/{kind}-vendor:ro",
                "<CARGO_HOME>:/cargo-home:rw",
                "<TARGET>:/target:rw",
            ):
                self.assertGreater(command.index(mount), 0)
                self.assertEqual(command[command.index(mount) - 1], "-v")
            self.assertEqual(command.count(builder.IMAGE_ID), 1)

    def test_receipt_root_and_limitations_are_closed(self) -> None:
        receipt = {field: {} for field in builder.RECEIPT_FIELDS}
        receipt["schema"] = builder.SCHEMA
        receipt["limitations"] = builder.LIMITATIONS
        raw = builder.canonical(receipt) + b"\n"
        builder.validate_receipt_structure(receipt, raw)

        extra = copy.deepcopy(receipt)
        extra["aggregate_health"] = "green"
        with self.assertRaisesRegex(builder.Refusal, "exact canonical"):
            builder.validate_receipt_structure(extra, builder.canonical(extra) + b"\n")

        widened = copy.deepcopy(receipt)
        widened["limitations"] = []
        with self.assertRaisesRegex(builder.Refusal, "exact canonical"):
            builder.validate_receipt_structure(
                widened, builder.canonical(widened) + b"\n"
            )

    def test_package_inventory_is_exact_root_owned_two_binary_layout(self) -> None:
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w:") as data:
            for path in (
                ".",
                "usr",
                "usr/libexec",
                "usr/libexec/constellation-operator-beta",
            ):
                member = tarfile.TarInfo(path)
                member.type = tarfile.DIRTYPE
                member.mode = 0o755
                member.uid = 0
                member.gid = 0
                data.addfile(member)
            for path in builder.BINARIES.values():
                member = tarfile.TarInfo(path)
                member.mode = 0o755
                member.uid = 0
                member.gid = 0
                body = b"fixture"
                member.size = len(body)
                data.addfile(member, io.BytesIO(body))
        completed = mock.Mock(stdout=archive.getvalue())
        with mock.patch.object(builder, "run", return_value=completed):
            inventory = builder.package_data_inventory(pathlib.Path("fixture.deb"))
        self.assertEqual(len(inventory), 6)
        self.assertTrue(all(item["mode"] == "0755" for item in inventory))

        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w:") as data:
            member = tarfile.TarInfo("unexpected")
            member.mode = stat.S_IFREG | 0o755
            member.uid = 0
            member.gid = 0
            member.size = 0
            data.addfile(member, io.BytesIO())
        completed = mock.Mock(stdout=archive.getvalue())
        with mock.patch.object(builder, "run", return_value=completed):
            with self.assertRaisesRegex(builder.Refusal, "closed two-binary"):
                builder.package_data_inventory(pathlib.Path("fixture.deb"))


if __name__ == "__main__":
    unittest.main()
