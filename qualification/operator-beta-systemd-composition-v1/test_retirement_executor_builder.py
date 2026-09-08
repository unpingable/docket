"""Focused derivative package boundaries; these are not execution qualification."""
import pathlib
import subprocess
import tempfile
import unittest

import build_retirement_executor as builder


class ExecutorBuilderTests(unittest.TestCase):
    def test_command_keeps_offline_exact_image_and_feature_enabled_binary(self):
        command = builder.command(*(pathlib.Path(value) for value in ("source", "vendor", "cargo", "target")))
        self.assertEqual(command[command.index("--network") + 1], "none")
        self.assertEqual(command[command.index("--pull") + 1], "never")
        self.assertEqual(command[command.index("--bin") + 1], "ag-effectd")
        self.assertEqual(command[command.index("--features") + 1], "systemd-dbus")
        self.assertNotIn("--example", command)
        self.assertIn("--offline", command)
        self.assertIn("--locked", command)
        self.assertIn(builder.shared.IMAGE_ID, command)

    def test_package_is_only_the_exact_binary_without_service_or_scripts(self):
        with tempfile.TemporaryDirectory() as temporary:
            case = pathlib.Path(temporary)
            binary = case / "fixture-binary"
            binary.write_bytes(b"not executable qualification; package layout specimen")
            package = builder.package_binary(binary, case)
            extract = case / "extract"
            subprocess.run(["dpkg-deb", "-R", str(package), str(extract)], check=True, capture_output=True)
            files = sorted(path.relative_to(extract).as_posix() for path in extract.rglob("*") if path.is_file())
            self.assertEqual(files, ["DEBIAN/control", "usr/libexec/agent-governor-ng/ag-effectd"])
            installed = extract / files[1]
            self.assertEqual(installed.read_bytes(), binary.read_bytes())
            self.assertEqual(installed.stat().st_mode & 0o777, 0o755)

    def test_symlink_binary_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            case = pathlib.Path(temporary)
            binary = case / "alias"
            binary.symlink_to("/bin/true")
            with self.assertRaises(builder.shared.Refusal):
                builder.package_binary(binary, case)
