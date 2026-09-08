#!/usr/bin/env python3
"""Direct qualification cases for the thin NQ-ng composition adapter."""

from __future__ import annotations

import importlib.util
import io
import json
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


HERE = pathlib.Path(__file__).resolve().parent


def load(name: str, path: pathlib.Path):
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


adapter = load("composition_adapter_test", HERE / "run_composed_two_vm.py")
nq = load(
    "composition_nq_test",
    pathlib.Path(
        "/data/git/.worktrees/nq-ng-operator-beta-profile-v1/qualification/operator-beta-m1b-v1/run_two_vm.py"
    ),
)


class CompositionAdapterTests(unittest.TestCase):
    def test_manifest_reopen_requires_exact_physical_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            artifact = root / "evidence.json"
            artifact.write_bytes(b"{}\n")
            manifest = {
                "schema": "constellation.operator_beta.composed_m1b_artifact_manifest.v1",
                "files": [
                    {
                        "path": "evidence.json",
                        "bytes": 3,
                        "sha256": adapter.sha256(artifact),
                    }
                ],
            }
            (root / "ARTIFACTS.sha256").write_bytes(nq.canonical(manifest) + b"\n")
            adapter.reopen_manifest(root, nq)
            (root / "unrecorded").write_bytes(b"x")
            with self.assertRaisesRegex(nq.Refusal, "physical inventory"):
                adapter.reopen_manifest(root, nq)

    def test_archive_command_is_bounded_and_refuses_nonregular_entries(self) -> None:
        command = adapter.composition_archive_command("/home/betaoperator/result.tar")
        for token in (
            "sudo sh -eu -c",
            "test ! -e /home/betaoperator/result.tar; test ! -L /home/betaoperator/result.tar",
            "test ! -e /home/betaoperator/result.tar.tmp; test ! -L /home/betaoperator/result.tar.tmp",
            "find /var/lib/constellation-operator-beta-composition -xdev",
            "! -type f ! -type d",
            "tar --sort=name",
            "--owner=0 --group=0 --numeric-owner",
            str(adapter.MAX_COMPOSITION_ARCHIVE_BYTES),
            "chmod 0400",
        ):
            self.assertIn(token, command)

    def test_archive_reopen_refuses_symlink_and_content_overflow(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            archive = root / "occurrence.tar"
            with tarfile.open(archive, "w:") as output:
                member = tarfile.TarInfo("link")
                member.type = tarfile.SYMTYPE
                member.linkname = "target"
                output.addfile(member)
            with self.assertRaisesRegex(nq.Refusal, "non-regular"):
                adapter.extract_regular_archive(archive, root / "out", nq)

    def occurrence(self, root: pathlib.Path, outcome: str = "success") -> pathlib.Path:
        occurrence = root / "composition-occurrence"
        (occurrence / "occurrence").mkdir(parents=True)
        result = {
            "schema": "constellation.operator_beta.docket_systemd_composition_result.v1",
            "run_id": "composition-test-1",
            "disposition": "SETTLED",
            "ag_spends": 1,
            "docket_attempts": 1,
            "settlements": 1,
            "issuance": "sha256:" + "1" * 64,
            "attempt": "sha256:" + "2" * 64,
            "marker": "sha256:" + "3" * 64,
            "work": "sha256:" + "4" * 64,
            "subject": "sha256:" + "5" * 64,
            "scope": "sha256:" + "6" * 64,
            "receipt": "sha256:" + "7" * 64,
            "docket_status": "settled",
            "duplicate_same_custody": True,
            "ag_restart_exact": True,
            "executor_reconcile_exact": True,
        }
        (occurrence / "composition-result.json").write_bytes(
            nq.canonical(result) + b"\n"
        )
        (occurrence / "executor-outcome.json").write_bytes(
            nq.canonical(
                {
                    "attempt": result["attempt"],
                    "marker": result["marker"],
                    "outcome": outcome,
                    "receipt": result["receipt"],
                }
            )
            + b"\n"
        )
        (occurrence / "executor-dispatch.json").write_bytes(b"{}\n")
        (occurrence / "occurrence" / "systemd-plan-v2.json").write_bytes(b"{}\n")
        return occurrence

    def test_enact_uses_real_packaged_docket_path_and_binds_one_spend_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "evidence").mkdir()
            (root / "evidence" / "guest-identities.json").write_text(
                json.dumps({"target_machine_identity": "a" * 32})
            )
            occurrence = self.occurrence(root)
            producer_type = adapter.producer_class(nq)
            producer = producer_type.__new__(producer_type)
            producer.output = root
            producer.run_id = "composition-test-1"
            producer.effect_custody = None
            producer.effect_outcome = "NO_EFFECT_ATTEMPTED"
            producer.state = mock.Mock()
            producer.complete_phase = mock.Mock()
            observed: list[str] = []

            def ssh(_target, command):
                observed.append(command)
                return subprocess.CompletedProcess([], 0, b"SETTLED\n", b"")

            producer.ssh = ssh
            producer.retain_composition_archive = mock.Mock(return_value=occurrence)
            bindings = {
                "subject_identity": "sha256:" + "5" * 64,
                "systemd_policy": {
                    "request_scope": {"digest": "sha256:" + "6" * 64}
                },
            }
            record = producer.enact(object(), bindings)
            self.assertEqual(len(observed), 1)
            for token in (
                "sudo /usr/libexec/constellation-operator-beta/composition-driver",
                "/usr/libexec/constellation-operator-beta/docket",
                "/usr/libexec/agent-governor-ng/ag-effectd",
                adapter.REMOTE_COMPOSITION_ROOT,
                "composition-test-1",
                "a" * 32,
                nq.UNIT,
            ):
                self.assertIn(token, observed[0])
            self.assertEqual(record["authority_owner"], "AG-ng")
            self.assertEqual(record["custody_owner"], "Docket")
            self.assertEqual(producer.effect_custody["ag_authorization_consumption"], "RECORDED")
            self.assertEqual(producer.effect_custody["docket_state"], "RECORDED")

    def test_enact_refuses_worker_success_when_owner_outcome_is_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "evidence").mkdir()
            (root / "evidence" / "guest-identities.json").write_text(
                json.dumps({"target_machine_identity": "a" * 32})
            )
            occurrence = self.occurrence(root, outcome="failure")
            producer_type = adapter.producer_class(nq)
            producer = producer_type.__new__(producer_type)
            producer.output = root
            producer.run_id = "composition-test-1"
            producer.effect_custody = None
            producer.effect_outcome = "NO_EFFECT_ATTEMPTED"
            producer.state = mock.Mock()
            producer.complete_phase = mock.Mock()
            producer.ssh = mock.Mock(
                return_value=subprocess.CompletedProcess([], 0, b"SETTLED\n", b"")
            )
            producer.retain_composition_archive = mock.Mock(return_value=occurrence)
            bindings = {
                "subject_identity": "sha256:" + "5" * 64,
                "systemd_policy": {
                    "request_scope": {"digest": "sha256:" + "6" * 64}
                },
            }
            with self.assertRaisesRegex(nq.Refusal, "does not establish"):
                producer.enact(object(), bindings)

    def test_terminal_result_keeps_custody_current_support_and_deployment_separate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            producer_type = adapter.producer_class(nq)
            producer = producer_type.__new__(producer_type)
            producer.output = root
            producer.run_id = "composition-test-1"
            producer.last_completed = "teardown_complete"
            producer.args = mock.Mock(
                harness_subject=adapter.NQ_HEAD,
                composition_subject="a" * 40,
            )
            producer.state = mock.Mock()
            producer.seal()
            result = json.loads((root / "RESULT.json").read_bytes())
            self.assertEqual(result["authorization_consumption"], "RECORDED")
            self.assertEqual(result["docket_database_occurrence"], "RECORDED")
            self.assertEqual(result["effect_enactment"], "RECORDED_SUCCESS")
            self.assertEqual(result["aggregate_postcondition"], "NOT_RECORDED")
            self.assertEqual(result["literal_distributed_exactly_once"], "NOT_CLAIMED")
            self.assertEqual(result["deployment"], "NOT_RUN")
            self.assertEqual(result["production"], "NOT_RUN")


if __name__ == "__main__":
    unittest.main()
