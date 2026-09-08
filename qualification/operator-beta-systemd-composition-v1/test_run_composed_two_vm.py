#!/usr/bin/env python3
"""Direct qualification cases for the thin NQ-ng composition adapter."""

from __future__ import annotations

import copy
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
    def refusal_records(self, root: pathlib.Path) -> tuple[dict, dict]:
        refusal = {
            "schema": "constellation.operator_beta.m1b_refusal.v1",
            "run_id": "composition-refusal-1",
            "occurred_at": "2026-09-08T12:00:00Z",
            "phase": "guests_prepared",
            "reason": "bounded local fixture refusal",
            "effect_outcome": "NO_EFFECT_ATTEMPTED",
        }
        recovery = {
            "schema": "constellation.operator_beta.m1b_recovery.v1",
            "campaign": nq.CAMPAIGN,
            "run_id": refusal["run_id"],
            "host": "local-fixture",
            "working_directory": str(root),
            "harness_subject": adapter.NQ_HEAD,
            "accepted_package_result": "fixture",
            "input_facts": {"fixture": "admitted"},
            "protocols": {"docket_transport": "gwr.executor-transport/v1"},
            "phase": "refused",
            "last_completed_phase": refusal["phase"],
            "next_lawful_action": "reopen evidence; do not restart producer",
            "effect_outcome": refusal["effect_outcome"],
            "effect_custody": None,
            "updated_at": refusal["occurred_at"],
            "producer": {
                "systemd_unit": "constellation-composition-refusal-1.service",
                "invocation_id": "1" * 32,
                "main_pid": 1200,
                "start_ticks": 4500,
            },
            "expected_terminal_records": [
                "RESULT.json + ARTIFACTS.sha256",
                "or REFUSAL.json + RECOVERY.json",
            ],
            "paths": {
                "run_root": str(root),
                "host_log": str(root / "host.log"),
                "evidence": str(root / "evidence"),
            },
            "guests": [],
            "composition": {
                "subject": "a" * 40,
                "package_sha256": adapter.COMPOSITION_PACKAGE_SHA256,
                "receipt_sha256": adapter.COMPOSITION_RECEIPT_SHA256,
                "authority": "AG-ng decision/spend; Docket attempt/transport; AG-ng effect evidence",
            },
            "refusal": copy.deepcopy(refusal),
        }
        return refusal, recovery

    def write_refusal_records(
        self, root: pathlib.Path, refusal: dict, recovery: dict
    ) -> None:
        (root / "REFUSAL.json").write_bytes(nq.canonical(refusal) + b"\n")
        (root / "RECOVERY.json").write_bytes(nq.canonical(recovery) + b"\n")

    def test_refusal_reopens_only_exact_agreeing_owner_records(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            refusal, recovery = self.refusal_records(root)
            self.write_refusal_records(root, refusal, recovery)
            with mock.patch("sys.stdout", new_callable=io.StringIO) as output:
                adapter.check_refusal(root, nq)
            self.assertEqual(
                json.loads(output.getvalue()),
                {"result": "COMPOSED_REFUSAL_REOPENED", "run_id": refusal["run_id"]},
            )

    def test_refusal_reopen_rejects_disagreement_and_success_terminal(self) -> None:
        substitutions = (
            ("run", lambda refusal, _recovery: refusal.__setitem__("run_id", "other")),
            ("phase", lambda refusal, _recovery: refusal.__setitem__("phase", "other")),
            (
                "effect",
                lambda refusal, _recovery: refusal.__setitem__(
                    "effect_outcome", "KNOWN_COMPOSED_EFFECT_OWNER_SUCCESS"
                ),
            ),
            ("reason", lambda refusal, _recovery: refusal.__setitem__("reason", "other")),
            (
                "nested",
                lambda _refusal, recovery: recovery["refusal"].__setitem__(
                    "reason", "other"
                ),
            ),
        )
        for label, substitute in substitutions:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary).resolve()
                refusal, recovery = self.refusal_records(root)
                substitute(refusal, recovery)
                self.write_refusal_records(root, refusal, recovery)
                with self.assertRaisesRegex(nq.Refusal, "disagree|custody"):
                    adapter.check_refusal(root, nq)
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            refusal, recovery = self.refusal_records(root)
            self.write_refusal_records(root, refusal, recovery)
            (root / "RESULT.json").write_bytes(b"{}\n")
            with self.assertRaisesRegex(nq.Refusal, "additional success"):
                adapter.check_refusal(root, nq)
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            refusal, recovery = self.refusal_records(root)
            self.write_refusal_records(root, refusal, recovery)
            (root / "ARTIFACTS.sha256").symlink_to(root / "missing")
            with self.assertRaisesRegex(nq.Refusal, "additional success"):
                adapter.check_refusal(root, nq)

    def test_docket_inspection_preserves_owner_json_framing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "docket-inspection.json"
            owner_bytes = b'{"schema":"docket.governed-loop.inspection/v1","requested_issuance":"sha256:1","record":{"status":"settled"}}\n'
            path.write_bytes(owner_bytes)
            self.assertEqual(
                adapter.owner_json_record(path, "Docket inspection", nq),
                {
                    "schema": "docket.governed-loop.inspection/v1",
                    "requested_issuance": "sha256:1",
                    "record": {"status": "settled"},
                },
            )
            self.assertEqual(path.read_bytes(), owner_bytes)

            for invalid in (
                owner_bytes.rstrip(b"\n"),
                owner_bytes + b"{}\n",
                b'{"schema":"first","schema":"second"}\n',
            ):
                path.write_bytes(invalid)
                with self.assertRaisesRegex(nq.Refusal, "Docket inspection"):
                    adapter.owner_json_record(path, "Docket inspection", nq)

    def test_nq_artifact_uses_nq_owner_framing_without_newline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "systemd-pre-artifact.json"
            owner_bytes = nq.canonical(
                {"schema": "nq.diagnostic-artifact/v1", "observations": []}
            )
            path.write_bytes(owner_bytes)
            self.assertEqual(
                adapter.nq_owner_record(path, "NQ diagnostic artifact", nq),
                {"schema": "nq.diagnostic-artifact/v1", "observations": []},
            )
            self.assertEqual(path.read_bytes(), owner_bytes)

            path.write_bytes(
                b'{"schema":"nq.diagnostic-artifact/v1","observations":[]}'
            )
            with self.assertRaisesRegex(nq.Refusal, "canonical JSON"):
                adapter.nq_owner_record(path, "NQ diagnostic artifact", nq)

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
