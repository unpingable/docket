#!/usr/bin/env python3
"""Run the accepted NQ-ng two-VM lane with real AG and Docket custody.

This is a qualification adapter, not a product runtime.  NQ-ng remains the
owner of VM lifecycle and pre/post observation.  The packaged composition
driver creates the AG decision/spend and invokes Docket's real governed-loop
transport against AG's accepted systemd executor.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import sqlite3
import stat
import sys
import tarfile
import tempfile
from typing import Any


HERE = pathlib.Path(__file__).resolve().parent
BUILDER_PATH = HERE / "build_bookworm_fixture.py"
NQ_HEAD = "e0151d0c090be7ce56e00f7d293440dbe43bf4a4"
NQ_TREE = "2dbe73cb0fca01b0dbdbd55b7025ab135213af15"
NQ_QUALIFIED_HARNESS = "e0151d0c090be7ce56e00f7d293440dbe43bf4a4"
# Checker-only pins: the final checker descendant binds its frozen producer A.
# The producer records actual admitted HEAD/tree, never these checker constants.
COMPOSITION_OWNER_SUBJECT = "b255fc84d72f38138c4614321c6ce7a06dead860"
COMPOSITION_OWNER_TREE = "a2a04e41c9ea85181f0286240dcc56eb0a7f1d49"
COMPOSITION_PACKAGE_SHA256 = "54ac28c11c1b7cb54f621217c786086d481a4ccbae41a4bc15546995471f9bd5"
COMPOSITION_RECEIPT_SHA256 = "0d02551ae4666e129f759a6e643037f2fb514aaef7b0c78850f17b03714b050b"
COMPOSITION_PACKAGE_NAME = "constellation-operator-beta-composition-fixture"
COMPOSITION_PACKAGE_VERSION = "0.1.0-1"
REMOTE_COMPOSITION_ROOT = "/var/lib/constellation-operator-beta-composition"
MAX_COMPOSITION_ARCHIVE_BYTES = 128 * 1024 * 1024
UUID_PATTERN = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


def load_module(name: str, path: pathlib.Path) -> Any:
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


builder = load_module("docket_composition_fixture_builder", BUILDER_PATH)


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def exact_repository(path: pathlib.Path, head: str, tree: str, nq: Any) -> None:
    repository = path.resolve().parents[2]
    observed_head = nq.run(["git", "rev-parse", "HEAD"], cwd=repository).stdout.decode().strip()
    observed_tree = nq.run(["git", "rev-parse", "HEAD^{tree}"], cwd=repository).stdout.decode().strip()
    if observed_head != head or observed_tree != tree:
        raise nq.Refusal("NQ-ng harness differs from the admitted head/tree")
    if nq.run(["git", "status", "--porcelain"], cwd=repository).stdout:
        raise nq.Refusal("NQ-ng harness worktree is not clean")
    relative = path.resolve().relative_to(repository).as_posix()
    unchanged = nq.run(
        ["git", "diff", "--quiet", NQ_QUALIFIED_HARNESS, head, "--", relative],
        cwd=repository,
        check=False,
    )
    if unchanged.returncode != 0:
        raise nq.Refusal("NQ-ng producer differs from its admitted derivative harness")


def exact_composition_repository(subject: str, nq: Any) -> dict[str, str]:
    repository = HERE.parents[1]
    head = nq.run(["git", "rev-parse", "HEAD"], cwd=repository).stdout.decode().strip()
    tree = nq.run(["git", "rev-parse", "HEAD^{tree}"], cwd=repository).stdout.decode().strip()
    if head != subject or not re.fullmatch(r"[0-9a-f]{40}", subject):
        raise nq.Refusal("composition checkout differs from its admitted subject")
    if nq.run(["git", "status", "--porcelain"], cwd=repository).stdout:
        raise nq.Refusal("composition checkout is not clean")
    return {"head": head, "tree": tree}


def verify_fixture_inputs(args: argparse.Namespace, nq: Any) -> dict[str, Any]:
    nq.regular_file(args.composition_deb, "composition fixture package")
    nq.regular_file(args.composition_receipt, "composition fixture receipt")
    package_sha = sha256(args.composition_deb)
    receipt_sha = sha256(args.composition_receipt)
    if package_sha != COMPOSITION_PACKAGE_SHA256 or receipt_sha != COMPOSITION_RECEIPT_SHA256:
        raise nq.Refusal("composition fixture package or receipt differs from the accepted input")
    raw = args.composition_receipt.read_bytes()
    try:
        receipt = json.loads(raw)
    except json.JSONDecodeError as error:
        raise nq.Refusal("composition fixture receipt is not JSON") from error
    try:
        builder.validate_receipt_structure(receipt, raw)
    except builder.Refusal as error:
        raise nq.Refusal(str(error)) from error
    if receipt.get("sources") != {
        "ag": {
            "head": builder.AG_HEAD,
            "tree": builder.AG_TREE,
            "cargo_lock_sha256": receipt["sources"]["ag"].get("cargo_lock_sha256"),
            "cargo_toml_sha256": receipt["sources"]["ag"].get("cargo_toml_sha256"),
        },
        "docket": {
            "head": builder.DOCKET_HEAD,
            "tree": builder.DOCKET_TREE,
            "cargo_lock_sha256": receipt["sources"]["docket"].get("cargo_lock_sha256"),
            "cargo_toml_sha256": receipt["sources"]["docket"].get("cargo_toml_sha256"),
        },
    }:
        raise nq.Refusal("composition receipt names another AG or Docket source")
    with tempfile.TemporaryDirectory(prefix="composition-input-verify.") as temporary:
        try:
            package = builder.package_facts(args.composition_deb, pathlib.Path(temporary))
        except builder.Refusal as error:
            raise nq.Refusal(str(error)) from error
    if receipt.get("package") != package:
        raise nq.Refusal("composition package differs from its exact build receipt")
    qualification = builder.qualification_facts(HERE.parents[1])
    if receipt.get("qualification") != qualification:
        raise nq.Refusal("composition qualification sources differ from the build receipt")
    return {
        "package_sha256": package_sha,
        "receipt_sha256": receipt_sha,
        "ag_source": builder.AG_HEAD,
        "docket_source": builder.DOCKET_HEAD,
        "binaries": receipt["binaries"],
    }


def extract_regular_archive(archive: pathlib.Path, destination: pathlib.Path, nq: Any) -> None:
    metadata = nq.regular_file(archive, "composition occurrence archive")
    if metadata.st_size <= 0 or metadata.st_size > MAX_COMPOSITION_ARCHIVE_BYTES:
        raise nq.Refusal("composition occurrence archive exceeds its byte bound")
    destination.mkdir(mode=0o700)
    total = 0
    with tarfile.open(archive, "r:") as source:
        members = source.getmembers()
        if not members or len(members) > 4096:
            raise nq.Refusal("composition occurrence archive has invalid cardinality")
        for member in members:
            relative = pathlib.PurePosixPath(member.name.removeprefix("./"))
            if relative.is_absolute() or ".." in relative.parts:
                raise nq.Refusal("composition occurrence archive has an unsafe path")
            if not (member.isdir() or member.isfile()):
                raise nq.Refusal("composition occurrence archive has a non-regular entry")
            total += member.size
            if total > MAX_COMPOSITION_ARCHIVE_BYTES:
                raise nq.Refusal("composition occurrence archive contents exceed the byte bound")
        source.extractall(destination, filter="data")


def composition_archive_command(remote_archive: str) -> str:
    return (
        "sudo sh -eu -c '"
        f"test -d {REMOTE_COMPOSITION_ROOT}; "
        f"test ! -e {remote_archive}; test ! -L {remote_archive}; "
        f"test ! -e {remote_archive}.tmp; test ! -L {remote_archive}.tmp; "
        f"test -z \"$(find {REMOTE_COMPOSITION_ROOT} -xdev ! -type f ! -type d -print -quit)\"; "
        f"tar --sort=name --format=posix --mtime=@0 --owner=0 --group=0 --numeric-owner "
        f"-cf {remote_archive}.tmp -C {REMOTE_COMPOSITION_ROOT} .; "
        f"test $(stat -c %s {remote_archive}.tmp) -le {MAX_COMPOSITION_ARCHIVE_BYTES}; "
        f"chown betaoperator:betaoperator {remote_archive}.tmp; chmod 0400 {remote_archive}.tmp; "
        f"mv {remote_archive}.tmp {remote_archive}'"
    )


def producer_class(nq: Any) -> type:
    class CompositionProducer(nq.Producer):
        def state(self, phase: str, next_action: str, **facts: Any) -> None:
            super().state(phase, next_action, **facts)
            path = self.output / "RECOVERY.json"
            record = json.loads(path.read_bytes())
            record["protocols"]["docket_transport"] = "gwr.executor-transport/v1"
            record["composition"] = {
                "subject": self.args.composition_subject,
                "package_sha256": COMPOSITION_PACKAGE_SHA256,
                "receipt_sha256": COMPOSITION_RECEIPT_SHA256,
                "authority": "AG-ng decision/spend; Docket attempt/transport; AG-ng effect evidence",
            }
            nq.atomic_write(path, nq.canonical(record) + b"\n")

        def preflight(self) -> dict[str, Any]:
            exact_repository(self.args.nq_harness, NQ_HEAD, NQ_TREE, nq)
            facts = super().preflight()
            facts["composition_repository"] = exact_composition_repository(
                self.args.composition_subject, nq
            )
            facts["composition_fixture"] = verify_fixture_inputs(self.args, nq)
            return facts

        def create_run(self, preflight: dict[str, Any]) -> None:
            super().create_run(preflight)
            retained_package = self.output / "input" / builder.PACKAGE_FILE
            retained_receipt = self.output / "input" / "composition-fixture-receipt.v1.json"
            shutil.copyfile(self.args.composition_deb, retained_package)
            shutil.copyfile(self.args.composition_receipt, retained_receipt)
            os.chmod(retained_package, 0o400)
            os.chmod(retained_receipt, 0o400)
            if (
                sha256(retained_package) != COMPOSITION_PACKAGE_SHA256
                or sha256(retained_receipt) != COMPOSITION_RECEIPT_SHA256
            ):
                raise nq.Refusal("retained composition inputs differ after copy")
            record = {
                "schema": "constellation.operator_beta.composition_inputs.v1",
                "run_id": self.run_id,
                "composition_subject": self.args.composition_subject,
                "nq_harness_subject": self.args.harness_subject,
                "package_sha256": COMPOSITION_PACKAGE_SHA256,
                "receipt_sha256": COMPOSITION_RECEIPT_SHA256,
                "ag_source": builder.AG_HEAD,
                "docket_source": builder.DOCKET_HEAD,
            }
            nq.atomic_write(
                self.output / "evidence" / "composition-inputs.json",
                nq.canonical(record) + b"\n",
                0o400,
            )

        def install_inputs(self) -> tuple[Any, Any]:
            control, target = super().install_inputs()
            package = self.output / "input" / builder.PACKAGE_FILE
            self.scp_to(target, [package], "/home/betaoperator/")
            self.ssh(
                target,
                f"printf '{COMPOSITION_PACKAGE_SHA256}  /home/betaoperator/{builder.PACKAGE_FILE}\\n' | sha256sum -c -; "
                f"sudo dpkg -i /home/betaoperator/{builder.PACKAGE_FILE}; "
                f"test \"$(dpkg-query -W -f='${{Status}}' {COMPOSITION_PACKAGE_NAME})\" = 'install ok installed'; "
                "test -x /usr/libexec/constellation-operator-beta/docket; "
                "test -x /usr/libexec/constellation-operator-beta/composition-driver",
            )
            self.complete_phase(
                "composition_fixture_installed",
                "generate exact NQ configuration and AG decision context",
            )
            return control, target

        def retain_composition_archive(self, target: Any, label: str) -> pathlib.Path:
            remote = f"/home/betaoperator/{label}.tar"
            self.ssh(target, composition_archive_command(remote))
            archive = self.output / "evidence" / f"{label}.tar"
            self.scp_from(target, remote, archive)
            os.chmod(archive, 0o400)
            destination = self.output / "evidence" / label
            extract_regular_archive(archive, destination, nq)
            self.ssh(target, f"rm -f {remote}")
            return destination

        def enact(self, target: Any, bindings: dict[str, Any]) -> dict[str, Any]:
            identities = json.loads(
                (self.output / "evidence" / "guest-identities.json").read_bytes()
            )
            subject = bindings["subject_identity"]
            scope = bindings["systemd_policy"]["request_scope"]["digest"]
            command = [
                "/usr/libexec/constellation-operator-beta/composition-driver",
                "/usr/libexec/constellation-operator-beta/docket",
                "/usr/libexec/agent-governor-ng/ag-effectd",
                REMOTE_COMPOSITION_ROOT,
                self.run_id,
                identities["target_machine_identity"],
                nq.UNIT,
                subject,
                scope,
            ]
            self.effect_outcome = "OUTCOME_UNKNOWN_REQUIRES_COMPOSED_REOPEN"
            self.state(
                "composition_dispatch_prepared",
                "invoke one AG-authorized Docket attempt and reopen the exact settlement",
            )
            result = self.ssh(target, "sudo " + __import__("shlex").join(command))
            if result.stdout != b"SETTLED\n" or result.stderr:
                raise nq.Refusal("composition driver did not emit its exact terminal marker")
            occurrence = self.retain_composition_archive(target, "composition-occurrence")
            composition = json.loads((occurrence / "composition-result.json").read_bytes())
            outcome = json.loads((occurrence / "executor-outcome.json").read_bytes())
            if (
                set(composition)
                != {
                    "schema", "run_id", "disposition", "ag_spends", "docket_attempts",
                    "settlements", "issuance", "attempt", "marker", "work", "subject",
                    "scope", "receipt", "docket_status", "duplicate_same_custody",
                    "ag_restart_exact", "executor_reconcile_exact",
                }
                or composition.get("schema")
                != "constellation.operator_beta.docket_systemd_composition_result.v1"
                or composition.get("run_id") != self.run_id
                or composition.get("disposition") != "SETTLED"
                or (composition.get("ag_spends"), composition.get("docket_attempts"), composition.get("settlements"))
                != (1, 1, 1)
                or composition.get("subject") != subject
                or composition.get("scope") != scope
                or composition.get("docket_status") != "settled"
                or not all(
                    composition.get(field) is True
                    for field in (
                        "duplicate_same_custody",
                        "ag_restart_exact",
                        "executor_reconcile_exact",
                    )
                )
                or outcome.get("outcome") != "success"
                or outcome.get("receipt") != composition.get("receipt")
            ):
                raise nq.Refusal("composition result does not establish the exact successful custody chain")
            self.effect_custody = {
                "issuance": composition["issuance"],
                "attempt": composition["attempt"],
                "marker": composition["marker"],
                "work": composition["work"],
                "subject": composition["subject"],
                "scope": composition["scope"],
                "receipt": composition["receipt"],
                "plan_sha256": sha256(occurrence / "occurrence" / "systemd-plan-v2.json"),
                "dispatch_sha256": sha256(occurrence / "executor-dispatch.json"),
                "outcome_sha256": sha256(occurrence / "executor-outcome.json"),
                "docket_state": "RECORDED",
                "ag_authorization_consumption": "RECORDED",
            }
            self.effect_outcome = "KNOWN_COMPOSED_EFFECT_OWNER_SUCCESS"
            record = {
                "schema": "constellation.operator_beta.composed_effect_occurrence.v1",
                "run_id": self.run_id,
                "authority_owner": "AG-ng",
                "custody_owner": "Docket",
                "effect_evidence_owner": "AG-ng",
                "result": composition,
                "outcome": outcome,
            }
            nq.atomic_write(
                self.output / "evidence" / "composed-effect-occurrence.json",
                nq.canonical(record) + b"\n",
                0o400,
            )
            self.complete_phase(
                "composed_effect_completed",
                "record fresh post-effect NQ observations",
            )
            return record

        def retain_and_audit_ag_store_cut(self, target: Any) -> None:
            source = f"{REMOTE_COMPOSITION_ROOT}/occurrence/ag-effectd-attempts.sqlite"
            remote_cut = "/home/betaoperator/composition-ag-attempt-store-cut.sqlite"
            stable = self.ssh(target, nq.ag_store_cut_command(source, remote_cut))
            facts = dict(
                line.split("=", 1)
                for line in stable.stdout.decode().splitlines()
                if "=" in line
            )
            cut = self.output / "evidence" / "composition-ag-attempt-store-cut.sqlite"
            self.scp_from(target, remote_cut, cut)
            os.chmod(cut, 0o400)
            metadata = nq.regular_file(cut, "composition AG attempt-store cut")
            cut_sha = sha256(cut)
            if facts != {
                "source_sha256": cut_sha,
                "source_bytes": str(metadata.st_size),
                "wal": "ABSENT_OR_ZERO_LENGTH",
            }:
                raise nq.Refusal("composition AG store cut disagrees with its locked source")
            first = self.output / "evidence" / "composition-occurrence"
            plan = first / "occurrence" / "systemd-plan-v2.json"
            dispatch = first / "executor-dispatch.json"
            expected_outcome = first / "executor-outcome.json"
            audit_binary = (
                self.output / "runtime" / "ag-package" / "usr" / "libexec"
                / "agent-governor-ng" / "ag-effectd"
            )
            completed = nq.run(
                [
                    str(audit_binary), "audit-store", str(plan), "--store-cut", str(cut),
                    "--store-bytes", str(metadata.st_size), "--store-sha256", "sha256:" + cut_sha,
                ],
                stdin=dispatch.read_bytes(),
            )
            if completed.stderr or completed.stdout != expected_outcome.read_bytes():
                raise nq.Refusal("AG owner audit disagrees with the composed terminal outcome")
            nq.atomic_write(
                self.output / "evidence" / "composition-ag-store-audit-outcome.json",
                completed.stdout,
                0o400,
            )
            result = json.loads((first / "composition-result.json").read_bytes())
            inspection = self.ssh(
                target,
                "sudo /usr/libexec/constellation-operator-beta/docket governed-loop inspect "
                f"--state {REMOTE_COMPOSITION_ROOT}/occurrence/docket-state "
                f"--issuance {result['issuance']}",
            )
            if inspection.stderr or inspection.stdout != (first / "docket-inspection.json").read_bytes():
                raise nq.Refusal("Docket restart inspection disagrees with original settlement")
            nq.atomic_write(
                self.output / "evidence" / "docket-restart-inspection.json",
                inspection.stdout,
                0o400,
            )
            self.retain_composition_archive(target, "composition-after-restart")
            self.effect_custody.update(
                {
                    "ag_store_cut_bytes": metadata.st_size,
                    "ag_store_cut_sha256": cut_sha,
                    "ag_store_audit_outcome_sha256": sha256(
                        self.output / "evidence" / "composition-ag-store-audit-outcome.json"
                    ),
                    "docket_restart_inspection_sha256": sha256(
                        self.output / "evidence" / "docket-restart-inspection.json"
                    ),
                }
            )
            store_record = {
                "schema": "constellation.operator_beta.composed_ag_store_cut.v1",
                "run_id": self.run_id,
                "source_store": source,
                "wal": "ABSENT_OR_ZERO_LENGTH",
                "store_bytes": metadata.st_size,
                "store_sha256": "sha256:" + cut_sha,
                "plan_sha256": self.effect_custody["plan_sha256"],
                "dispatch_sha256": self.effect_custody["dispatch_sha256"],
                "outcome_sha256": self.effect_custody["outcome_sha256"],
                "issuance": self.effect_custody["issuance"],
                "attempt": self.effect_custody["attempt"],
                "marker": self.effect_custody["marker"],
                "work": self.effect_custody["work"],
                "subject": self.effect_custody["subject"],
                "scope": self.effect_custody["scope"],
                "receipt": self.effect_custody["receipt"],
                "owner_audit_outcome_sha256": self.effect_custody[
                    "ag_store_audit_outcome_sha256"
                ],
                "docket_restart_inspection_sha256": self.effect_custody[
                    "docket_restart_inspection_sha256"
                ],
            }
            nq.atomic_write(
                self.output / "evidence" / "composition-store-cut.json",
                nq.canonical(store_record) + b"\n",
                0o400,
            )
            self.complete_phase("composed_store_custody_audited", "perform bounded teardown")

        def teardown(self, control: Any, target: Any) -> None:
            day_two = load_module("composition_day_two", HERE / "day_two.py")
            day_two.exercise(self, nq, (control, target))
            cold = load_module("composition_day_two_cold", HERE / "day_two_cold.py")
            cold.exercise(self, nq, control)
            result = self.ssh(
                target,
                f"sudo dpkg -r {COMPOSITION_PACKAGE_NAME}; "
                f"sudo rm -rf {REMOTE_COMPOSITION_ROOT}; "
                f"rm -f /home/betaoperator/{builder.PACKAGE_FILE} "
                "/home/betaoperator/composition-ag-attempt-store-cut.sqlite; "
                "test ! -e /usr/libexec/constellation-operator-beta/docket; "
                "test ! -e /usr/libexec/constellation-operator-beta/composition-driver; "
                f"sudo test ! -e {REMOTE_COMPOSITION_ROOT}; "
                f"test \"$(dpkg-query -W -f='${{db:Status-Abbrev}}' {COMPOSITION_PACKAGE_NAME} 2>/dev/null || true)\" != ii",
            )
            nq.atomic_write(
                self.output / "evidence" / "composition-teardown.txt",
                result.stdout,
                0o400,
            )
            super().teardown(control, target)

        def seal(self) -> None:
            private_key = self.output / "runtime" / "id_ed25519"
            if private_key.exists():
                private_key.unlink()
            result = {
                "schema": "constellation.operator_beta.composed_m1b_run_result.v1",
                "run_id": self.run_id,
                "disposition": "ONE_SPEND_ONE_ATTEMPT_BOUNDED_EFFECT_CUSTODY_WITH_DECLARED_LIMITATIONS",
                "completed_at": nq.utc_now(),
                "nq_harness_subject": self.args.harness_subject,
                "composition_subject": self.args.composition_subject,
                "composition_package_sha256": COMPOSITION_PACKAGE_SHA256,
                "signed_upstream_checksum": "NOT_QUALIFIED",
                "docket_database_occurrence": "RECORDED",
                "authorization_consumption": "RECORDED",
                "effect_enactment": "RECORDED_SUCCESS",
                "aggregate_postcondition": "NOT_RECORDED",
                "literal_distributed_exactly_once": "NOT_CLAIMED",
                "deployment": "NOT_RUN",
                "production": "NOT_RUN",
            }
            self.last_completed = "sealed"
            self.state("sealed", "independent evidence audit", terminal_disposition=result["disposition"])
            files = []
            for path in sorted(self.output.rglob("*")):
                if not path.is_file() or path.name in {"ARTIFACTS.sha256", "RESULT.json"}:
                    continue
                files.append(
                    {
                        "path": path.relative_to(self.output).as_posix(),
                        "bytes": path.stat().st_size,
                        "sha256": nq.digest_file(path, "sha256"),
                    }
                )
            manifest = {
                "schema": "constellation.operator_beta.composed_m1b_artifact_manifest.v1",
                "files": files,
            }
            nq.atomic_write(
                self.output / "ARTIFACTS.sha256", nq.canonical(manifest) + b"\n", 0o400
            )
            result["manifest_sha256"] = nq.digest_file(
                self.output / "ARTIFACTS.sha256", "sha256"
            )
            nq.atomic_write(self.output / "RESULT.json", nq.canonical(result) + b"\n", 0o400)

    return CompositionProducer


def canonical_record(path: pathlib.Path, label: str, nq: Any) -> dict[str, Any]:
    metadata = nq.regular_file(path, label)
    if metadata.st_size <= 0 or metadata.st_size > 16 * 1024 * 1024:
        raise nq.Refusal(f"{label} exceeds its byte bound")
    raw = path.read_bytes()
    try:
        record = json.loads(raw)
    except json.JSONDecodeError as error:
        raise nq.Refusal(f"{label} is not JSON") from error
    if not isinstance(record, dict) or raw != nq.canonical(record) + b"\n":
        raise nq.Refusal(f"{label} is not one canonical object")
    return record


def owner_json_record(path: pathlib.Path, label: str, nq: Any) -> dict[str, Any]:
    """Open one newline-framed owner JSON object without reconstructing its bytes."""
    metadata = nq.regular_file(path, label)
    if metadata.st_size <= 0 or metadata.st_size > 16 * 1024 * 1024:
        raise nq.Refusal(f"{label} exceeds its byte bound")
    raw = path.read_bytes()
    if (
        not raw.endswith(b"\n")
        or not raw[:-1].startswith(b"{")
        or not raw[:-1].endswith(b"}")
    ):
        raise nq.Refusal(f"{label} is not one newline-framed JSON object")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON member: {key}")
            result[key] = value
        return result

    try:
        record = json.loads(raw[:-1], object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise nq.Refusal(f"{label} is not one duplicate-free JSON object") from error
    if not isinstance(record, dict):
        raise nq.Refusal(f"{label} is not one JSON object")
    return record


def nq_owner_record(path: pathlib.Path, label: str, nq: Any) -> dict[str, Any]:
    """Use NQ-ng's accepted framing law for NQ-owned diagnostic artifacts."""
    return nq.load_json_artifact(path, label)


def reopen_archive_exact(
    archive: pathlib.Path, retained: pathlib.Path, nq: Any
) -> None:
    with tempfile.TemporaryDirectory(prefix="composition-archive-reopen.") as temporary:
        reopened = pathlib.Path(temporary) / "root"
        extract_regular_archive(archive, reopened, nq)
        expected = {
            path.relative_to(retained).as_posix(): path
            for path in retained.rglob("*")
            if path.is_file()
        }
        observed = {
            path.relative_to(reopened).as_posix(): path
            for path in reopened.rglob("*")
            if path.is_file()
        }
        if set(expected) != set(observed):
            raise nq.Refusal("retained composition archive inventory disagrees")
        for relative in expected:
            left = expected[relative]
            right = observed[relative]
            if (
                left.read_bytes() != right.read_bytes()
                or stat.S_IMODE(left.stat().st_mode) != stat.S_IMODE(right.stat().st_mode)
            ):
                raise nq.Refusal(f"retained composition archive differs at {relative}")


def reopen_manifest(path: pathlib.Path, nq: Any) -> tuple[dict[str, Any], set[str]]:
    manifest_path = path / "ARTIFACTS.sha256"
    manifest = canonical_record(manifest_path, "composition artifact manifest", nq)
    if set(manifest) != {"schema", "files"} or manifest.get("schema") != (
        "constellation.operator_beta.composed_m1b_artifact_manifest.v1"
    ):
        raise nq.Refusal("composition artifact manifest root is not closed")
    entries = manifest.get("files")
    if not isinstance(entries, list) or not entries or len(entries) > 4096:
        raise nq.Refusal("composition artifact manifest cardinality is invalid")
    expected: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "bytes", "sha256"}:
            raise nq.Refusal("composition artifact entry is not closed")
        relative = entry.get("path")
        if (
            not isinstance(relative, str)
            or relative.startswith("/")
            or ".." in pathlib.PurePosixPath(relative).parts
            or relative in expected
        ):
            raise nq.Refusal("composition artifact entry has an invalid path")
        artifact = path / relative
        metadata = nq.regular_file(artifact, f"composition artifact {relative}")
        if (
            metadata.st_size != entry.get("bytes")
            or sha256(artifact) != entry.get("sha256")
        ):
            raise nq.Refusal(f"composition artifact differs from manifest: {relative}")
        expected.add(relative)
    actual = {
        item.relative_to(path).as_posix()
        for item in path.rglob("*")
        if item.is_file() and item.name not in {"ARTIFACTS.sha256", "RESULT.json"}
    }
    if actual != expected:
        raise nq.Refusal("composition manifest does not close the physical inventory")
    return manifest, expected


def verify_composition_chain(path: pathlib.Path, result: dict[str, Any], nq: Any) -> None:
    first = path / "evidence" / "composition-occurrence"
    after = path / "evidence" / "composition-after-restart"
    reopen_archive_exact(path / "evidence" / "composition-occurrence.tar", first, nq)
    reopen_archive_exact(path / "evidence" / "composition-after-restart.tar", after, nq)
    composition = canonical_record(first / "composition-result.json", "composition result", nq)
    if (
        composition.get("run_id") != result.get("run_id")
        or composition.get("disposition") != "SETTLED"
        or (composition.get("ag_spends"), composition.get("docket_attempts"), composition.get("settlements"))
        != (1, 1, 1)
        or composition.get("docket_status") != "settled"
        or any(
            composition.get(field) is not True
            for field in (
                "duplicate_same_custody",
                "ag_restart_exact",
                "executor_reconcile_exact",
            )
        )
    ):
        raise nq.Refusal("composition result does not establish one spend/attempt/settlement")
    for relative in (
        "authorization-state.json",
        "issuance.json",
        "docket-custody.json",
        "docket-settlement.json",
        "docket-inspection.json",
        "executor-dispatch.json",
        "executor-outcome.json",
        "ag-replay.json",
    ):
        if (first / relative).read_bytes() != (after / relative).read_bytes():
            raise nq.Refusal(f"composition restart changed retained owner record {relative}")
    issuance = canonical_record(first / "issuance.json", "AG issuance", nq)
    custody = canonical_record(first / "docket-custody.json", "Docket custody", nq)
    settlement = canonical_record(first / "docket-settlement.json", "Docket settlement", nq)
    inspection = owner_json_record(first / "docket-inspection.json", "Docket inspection", nq)
    dispatch = canonical_record(first / "executor-dispatch.json", "executor dispatch", nq)
    outcome = canonical_record(first / "executor-outcome.json", "executor outcome", nq)
    replay = canonical_record(first / "ag-replay.json", "AG replay", nq)
    authorization = canonical_record(first / "authorization-state.json", "AG authorization state", nq)
    if (
        issuance.get("issuance") != composition.get("issuance")
        or issuance.get("subject") != composition.get("subject")
        or issuance.get("scope") != composition.get("scope")
        or issuance.get("work") != composition.get("work")
        or custody.get("issuance") != composition.get("issuance")
        or custody.get("ag_spend") != issuance.get("spend")
        or custody.get("attempt") != composition.get("attempt")
        or custody.get("executor_marker") != composition.get("marker")
        or settlement.get("issuance") != composition.get("issuance")
        or settlement.get("attempt") != composition.get("attempt")
        or settlement.get("executor_marker") != composition.get("marker")
        or settlement.get("receipt") != composition.get("receipt")
        or settlement.get("outcome") != "success"
        or dispatch
        != {
            "attempt": composition.get("attempt"),
            "marker": composition.get("marker"),
            "work_schema": "ag-effectd.docket-executor-systemd-work/v2",
            "work": composition.get("work"),
            "subject": composition.get("subject"),
            "scope": composition.get("scope"),
        }
        or outcome
        != {
            "attempt": composition.get("attempt"),
            "marker": composition.get("marker"),
            "outcome": "success",
            "receipt": composition.get("receipt"),
        }
        or (replay.get("ag_spends"), replay.get("docket_attempts"), replay.get("settlements"))
        != (1, 1, 1)
    ):
        raise nq.Refusal("AG, Docket, dispatch, and settlement identities do not compose")
    inspected = inspection.get("record", {})
    if (
        inspection.get("requested_issuance") != composition.get("issuance")
        or inspected.get("status") != "settled"
        or inspected.get("issuance") != issuance
        or inspected.get("custody") != custody
        or inspected.get("settlement") != settlement
    ):
        raise nq.Refusal("Docket query-only inspection disagrees with exact custody")
    consumed = authorization.get("state", {}).get("authorization_consumed", {})
    decision = consumed.get("admitted", {}).get("decision", {})
    authorized_issuance = consumed.get("issuance", {})
    if (
        authorized_issuance != issuance
        or not isinstance(decision.get("policy_basis"), str)
        or decision.get("disposition") != "admitted"
        or decision.get("proposal") != issuance.get("proposal")
        or decision.get("observation") != issuance.get("observation")
        or decision.get("standing_resolution") != issuance.get("standing_resolution")
    ):
        raise nq.Refusal("AG historical decision/spend basis does not reopen")
    bindings = canonical_record(path / "evidence" / "bindings.json", "NQ bindings", nq)
    if (
        composition.get("subject") != bindings.get("subject_identity")
        or composition.get("scope")
        != bindings.get("systemd_policy", {}).get("request_scope", {}).get("digest")
    ):
        raise nq.Refusal("composition edge does not bind the exact NQ subject and scope")
    restart_inspection = path / "evidence" / "docket-restart-inspection.json"
    if restart_inspection.read_bytes() != (first / "docket-inspection.json").read_bytes():
        raise nq.Refusal("Docket restart inspection differs from original settlement")
    cut = path / "evidence" / "composition-ag-attempt-store-cut.sqlite"
    cut_record = canonical_record(path / "evidence" / "composition-store-cut.json", "store cut", nq)
    if (
        cut_record.get("store_bytes") != cut.stat().st_size
        or cut_record.get("store_sha256") != "sha256:" + sha256(cut)
        or cut_record.get("wal") != "ABSENT_OR_ZERO_LENGTH"
        or cut_record.get("issuance") != composition.get("issuance")
        or cut_record.get("attempt") != composition.get("attempt")
        or cut_record.get("receipt") != composition.get("receipt")
    ):
        raise nq.Refusal("AG store cut does not bind the composed occurrence")
    audit_binary = (
        path / "runtime" / "ag-package" / "usr" / "libexec" / "agent-governor-ng" / "ag-effectd"
    )
    audited = nq.run(
        [
            str(audit_binary), "audit-store", str(first / "occurrence" / "systemd-plan-v2.json"),
            "--store-cut", str(cut), "--store-bytes", str(cut.stat().st_size),
            "--store-sha256", "sha256:" + sha256(cut),
        ],
        stdin=(first / "executor-dispatch.json").read_bytes(),
    )
    if (
        audited.stderr
        or audited.stdout != (first / "executor-outcome.json").read_bytes()
        or audited.stdout
        != (path / "evidence" / "composition-ag-store-audit-outcome.json").read_bytes()
    ):
        raise nq.Refusal("independent AG store-cut reopen disagrees")
    with tempfile.TemporaryDirectory(prefix="composition-docket-reopen.") as temporary:
        package_root = pathlib.Path(temporary)
        nq.run(["dpkg-deb", "-x", str(path / "input" / builder.PACKAGE_FILE), str(package_root)])
        docket = package_root / builder.BINARIES["docket"]
        reopened = nq.run(
            [
                str(docket), "governed-loop", "inspect", "--state",
                str(after / "occurrence" / "docket-state"), "--issuance",
                composition["issuance"],
            ]
        )
    if reopened.stderr or reopened.stdout != (first / "docket-inspection.json").read_bytes():
        raise nq.Refusal("independent Docket store reopen disagrees")


def verify_nq_and_teardown(path: pathlib.Path, result: dict[str, Any], nq: Any) -> None:
    identities = canonical_record(path / "evidence" / "guest-identities.json", "guest identities", nq)
    bindings = canonical_record(path / "evidence" / "bindings.json", "NQ bindings", nq)
    if bindings != nq.expected_m1b_bindings(result["run_id"], identities):
        raise nq.Refusal("NQ bindings differ from the exact composed occurrence")
    cases = (
        ("systemd-pre-artifact.json", "nq.systemd_unit", "present", "systemd-pre"),
        ("http-pre-artifact.json", "nq.http_endpoint", "unresolved", "http-pre"),
        ("systemd-post-artifact.json", "nq.systemd_unit", "explicitly_absent", "systemd-post"),
        ("http-post-artifact.json", "nq.http_endpoint", "explicitly_absent", "http-post"),
        ("systemd-restart-artifact.json", "nq.systemd_unit", "present", "systemd-restart"),
        ("http-restart-artifact.json", "nq.http_endpoint", "unresolved", "http-restart"),
    )
    for name, profile, condition, instance in cases:
        artifact = nq_owner_record(path / "evidence" / name, name, nq)
        nq.verify_diagnostic_artifact(
            artifact,
            profile=profile,
            condition=condition,
            instance=instance,
            bindings=bindings,
        )
    for role in ("control", "target"):
        before = (path / "evidence" / f"{role}-boot-before.txt").read_text().strip()
        after = (path / "evidence" / f"{role}-boot-after.txt").read_text().strip()
        if not re.fullmatch(UUID_PATTERN, before) or not re.fullmatch(UUID_PATTERN, after) or before == after:
            raise nq.Refusal(f"{role} boot identity did not change")
        backup = path / "evidence" / f"{role}-nq-backup.sqlite"
        connection = sqlite3.connect(f"file:{backup}?mode=ro&immutable=1", uri=True)
        integrity = connection.execute("PRAGMA integrity_check").fetchone()
        connection.close()
        if integrity != ("ok",):
            raise nq.Refusal(f"{role} NQ backup fails integrity check")
    support = canonical_record(
        path / "evidence" / "current-support-after-restart.json", "current support", nq
    )
    if (
        support.get("historical_effect") != "AG_OWNER_RECEIPT_RETAINED"
        or support.get("systemd_current_condition") != "present"
        or support.get("http_current_condition") != "unresolved"
        or support.get("aggregate_postcondition") != "NOT_RECORDED"
    ):
        raise nq.Refusal("historical effect and current support were collapsed")
    final = canonical_record(path / "evidence" / "host-final-observation.json", "host teardown", nq)
    absent = [value for key, value in final.items() if key.endswith("_absent")]
    if not absent or not all(value is True for value in absent):
        raise nq.Refusal("host teardown does not establish bounded absence")


def check_run(path: pathlib.Path, nq: Any) -> None:
    if path.resolve(strict=True) != path or not path.is_dir() or path.is_symlink():
        raise nq.Refusal("run path is not one exact physical directory")
    manifest, _inventory = reopen_manifest(path, nq)
    result = canonical_record(path / "RESULT.json", "composition run result", nq)
    fields = {
        "schema", "run_id", "disposition", "completed_at", "nq_harness_subject",
        "composition_subject", "composition_package_sha256", "signed_upstream_checksum",
        "docket_database_occurrence", "authorization_consumption", "effect_enactment",
        "aggregate_postcondition", "literal_distributed_exactly_once", "deployment",
        "production", "manifest_sha256",
    }
    if (
        set(result) != fields
        or result.get("schema") != "constellation.operator_beta.composed_m1b_run_result.v1"
        or result.get("disposition")
        != "ONE_SPEND_ONE_ATTEMPT_BOUNDED_EFFECT_CUSTODY_WITH_DECLARED_LIMITATIONS"
        or result.get("nq_harness_subject") != NQ_HEAD
        or result.get("composition_subject") != COMPOSITION_OWNER_SUBJECT
        or result.get("composition_package_sha256") != COMPOSITION_PACKAGE_SHA256
        or result.get("signed_upstream_checksum") != "NOT_QUALIFIED"
        or result.get("docket_database_occurrence") != "RECORDED"
        or result.get("authorization_consumption") != "RECORDED"
        or result.get("effect_enactment") != "RECORDED_SUCCESS"
        or result.get("aggregate_postcondition") != "NOT_RECORDED"
        or result.get("literal_distributed_exactly_once") != "NOT_CLAIMED"
        or result.get("deployment") != "NOT_RUN"
        or result.get("production") != "NOT_RUN"
        or result.get("manifest_sha256") != sha256(path / "ARTIFACTS.sha256")
    ):
        raise nq.Refusal("composition result is not the closed bounded disposition")
    inputs = canonical_record(path / "evidence" / "composition-inputs.json", "composition inputs", nq)
    if inputs != {
        "schema": "constellation.operator_beta.composition_inputs.v1",
        "run_id": result["run_id"],
        "composition_subject": result["composition_subject"],
        "nq_harness_subject": NQ_HEAD,
        "package_sha256": COMPOSITION_PACKAGE_SHA256,
        "receipt_sha256": COMPOSITION_RECEIPT_SHA256,
        "ag_source": builder.AG_HEAD,
        "docket_source": builder.DOCKET_HEAD,
    }:
        raise nq.Refusal("composition input record names another accepted chain")
    retained_package = path / "input" / builder.PACKAGE_FILE
    retained_receipt = path / "input" / "composition-fixture-receipt.v1.json"
    if sha256(retained_package) != COMPOSITION_PACKAGE_SHA256 or sha256(retained_receipt) != COMPOSITION_RECEIPT_SHA256:
        raise nq.Refusal("retained composition fixture differs")
    verify_composition_chain(path, result, nq)
    verify_nq_and_teardown(path, result, nq)
    cold_checker = load_module("composition_cold_checker", HERE / "day_two_cold_check.py")
    cold_checker.verify(path, nq, owner_json_record)
    print(json.dumps({"result": "COMPOSED_RUN_REOPENED", "run_id": result["run_id"]}, sort_keys=True))


def check_refusal(path: pathlib.Path, nq: Any) -> None:
    recovery = nq.load_recovery(path)
    refusal = nq.load_json_artifact(path / "REFUSAL.json", "composition refusal")
    refusal_fields = {
        "schema",
        "run_id",
        "occurred_at",
        "phase",
        "reason",
        "effect_outcome",
    }
    producer = recovery.get("producer")
    composition = recovery.get("composition")
    if (
        set(refusal) != refusal_fields
        or refusal.get("schema") != "constellation.operator_beta.m1b_refusal.v1"
        or not isinstance(refusal.get("run_id"), str)
        or not refusal["run_id"]
        or not isinstance(refusal.get("phase"), str)
        or not refusal["phase"]
        or not isinstance(refusal.get("reason"), str)
        or not refusal["reason"]
        or len(refusal["reason"].encode()) > 4096
        or not isinstance(refusal.get("occurred_at"), str)
        or refusal.get("effect_outcome") not in {
            "NO_EFFECT_ATTEMPTED",
            "OUTCOME_UNKNOWN_REQUIRES_COMPOSED_REOPEN",
            "KNOWN_COMPOSED_EFFECT_OWNER_SUCCESS",
        }
    ):
        raise nq.Refusal("composition refusal is not one closed owner record")
    if (
        recovery.get("phase") != "refused"
        or recovery.get("run_id") != refusal["run_id"]
        or recovery.get("last_completed_phase") != refusal["phase"]
        or recovery.get("effect_outcome") != refusal["effect_outcome"]
        or recovery.get("refusal") != refusal
        or recovery.get("next_lawful_action")
        != "reopen evidence; do not restart producer"
    ):
        raise nq.Refusal("composition recovery and refusal disagree")
    if (
        recovery.get("harness_subject") != NQ_HEAD
        or recovery.get("accepted_package_result")
        != "491914640612960e393e8da7c1c0d1280002330c"
        or not isinstance(recovery.get("input_facts"), dict)
        or set(recovery["input_facts"])
        != {
            "ag_deb_sha256",
            "ag_executable_sha256",
            "ag_store_audit_result",
            "composition_fixture",
            "composition_repository",
            "free_bytes",
            "image_checksum_signature",
            "image_sha512",
            "nq_deb_sha256",
        }
        or recovery["input_facts"].get("ag_deb_sha256")
        != "80ea7ad067da9d5ed1f07b39fb7ee41eef58680f3af15fad64c6b1bf05c1045c"
        or recovery["input_facts"].get("ag_executable_sha256")
        != "7c45c79de452ab838cf79575872b0797eafbe27c7904b113e560967d11eef75e"
        or recovery["input_facts"].get("ag_store_audit_result")
        != "5194005c3cb029e2d7ac98b9c4c6beb6dda6e5f1"
        or recovery["input_facts"].get("image_checksum_signature")
        != "UPSTREAM_DETACHED_SIGNATURE_NOT_PUBLISHED"
        or recovery["input_facts"].get("image_sha512")
        != "490f38e2665bc4c31f1bd4cd66dfab3c7695f652a62862a7034d95f8f05ede4146d6dd55c70cc8b0ac9d9b4f54e18f8860bd5ad5ebfb7a8d5e934f3d12cf3817"
        or recovery["input_facts"].get("nq_deb_sha256")
        != "bb9b89fbe87d2b9b720de497c8a8f96e00aabfeadb0a7598fe0acc8c4fed76ca"
        or not isinstance(recovery["input_facts"].get("free_bytes"), int)
        or recovery["input_facts"]["free_bytes"] < 0
        or not isinstance(producer, dict)
        or set(producer) != {"systemd_unit", "invocation_id", "main_pid", "start_ticks"}
        or not re.fullmatch(
            r"[A-Za-z0-9_.@:-]{1,255}\.service", str(producer.get("systemd_unit", ""))
        )
        or not re.fullmatch(r"[0-9a-fA-F]{32}", str(producer.get("invocation_id", "")))
        or type(producer.get("main_pid")) is not int or producer["main_pid"] <= 0
        or type(producer.get("start_ticks")) is not int or producer["start_ticks"] <= 0
        or not isinstance(composition, dict)
        or composition.get("subject") != COMPOSITION_OWNER_SUBJECT
        or composition.get("package_sha256") != COMPOSITION_PACKAGE_SHA256
        or composition.get("receipt_sha256") != COMPOSITION_RECEIPT_SHA256
        or composition.get("authority")
        != "AG-ng decision/spend; Docket attempt/transport; AG-ng effect evidence"
    ):
        raise nq.Refusal("composition refusal does not bind the admitted occurrence")
    facts = recovery["input_facts"]
    fixture = facts.get("composition_fixture")
    repository = facts.get("composition_repository")
    if (
        not isinstance(fixture, dict)
        or fixture.get("ag_source")
        != "bf6adde2792a886d1ba75d97ca77efb8e914f4f5"
        or fixture.get("docket_source")
        != "09ba85fdf0c05b7e1664ebea84cdbb611a0ceda4"
        or fixture.get("package_sha256") != COMPOSITION_PACKAGE_SHA256
        or fixture.get("receipt_sha256") != COMPOSITION_RECEIPT_SHA256
        or not isinstance(fixture.get("binaries"), dict)
        or set(fixture["binaries"]) != {"composition-driver", "docket"}
        or fixture["binaries"]["composition-driver"].get("sha256")
        != "4ce5ee7a73d7b2c1d3abd00e23302cbc0032c44088af49872c7a87a8d5525a4c"
        or fixture["binaries"]["docket"].get("sha256")
        != "4134dba8a5437782669d7a694acacb61ac49628f6a805ddbce2e7a1f9a3c95b1"
        or not isinstance(repository, dict)
        or repository
        != {"head": COMPOSITION_OWNER_SUBJECT, "tree": COMPOSITION_OWNER_TREE}
    ):
        raise nq.Refusal("composition refusal input cohort differs")
    custody = recovery.get("effect_custody")
    if (
        refusal["effect_outcome"] == "KNOWN_COMPOSED_EFFECT_OWNER_SUCCESS"
        and not isinstance(custody, dict)
    ):
        raise nq.Refusal("successful effect testimony has no retained owner custody")
    if refusal["effect_outcome"] == "KNOWN_COMPOSED_EFFECT_OWNER_SUCCESS":
        identities = {"issuance", "attempt", "marker", "work", "subject", "scope", "receipt"}
        raw_digests = {"plan_sha256", "dispatch_sha256", "outcome_sha256"}
        required = identities | raw_digests | {"docket_state", "ag_authorization_consumption"}
        optional = {"ag_store_audit_outcome_sha256", "ag_store_cut_bytes", "ag_store_cut_sha256",
                    "docket_restart_inspection_sha256"}
        if (
            not required.issubset(custody) or set(custody) - required - optional
            or any(not re.fullmatch(r"sha256:[0-9a-f]{64}", str(custody.get(key, ""))) for key in identities)
            or any(not re.fullmatch(r"[0-9a-f]{64}", str(custody.get(key, ""))) for key in raw_digests)
            or custody.get("docket_state") != "RECORDED"
            or custody.get("ag_authorization_consumption") != "RECORDED"
        ):
            raise nq.Refusal("successful effect testimony has invalid owner custody")
        occurrence = path / "evidence" / "composition-occurrence"
        result = canonical_record(occurrence / "composition-result.json", "composition result", nq)
        outcome = canonical_record(occurrence / "executor-outcome.json", "executor outcome", nq)
        if (
            any(result.get(key) != custody[key] for key in identities)
            or result.get("run_id") != recovery["run_id"]
            or outcome.get("outcome") != "success" or outcome.get("receipt") != custody["receipt"]
            or sha256(occurrence / "executor-outcome.json") != custody["outcome_sha256"]
            or sha256(occurrence / "executor-dispatch.json") != custody["dispatch_sha256"]
            or sha256(occurrence / "occurrence" / "systemd-plan-v2.json") != custody["plan_sha256"]
        ):
            raise nq.Refusal("refusal effect custody differs from retained owner records")
    if refusal["effect_outcome"] == "NO_EFFECT_ATTEMPTED" and custody is not None:
        raise nq.Refusal("no-effect refusal unexpectedly retains effect custody")
    if (
        refusal["effect_outcome"] == "OUTCOME_UNKNOWN_REQUIRES_COMPOSED_REOPEN"
        and custody is not None
    ):
        raise nq.Refusal("unknown effect outcome unexpectedly retains settled custody")
    def pathname_exists(candidate: pathlib.Path) -> bool:
        try:
            candidate.lstat()
        except FileNotFoundError:
            return False
        return True

    if pathname_exists(path / "RESULT.json") or pathname_exists(path / "ARTIFACTS.sha256"):
        raise nq.Refusal("refused composition has an additional success terminal record")
    print(json.dumps({"result": "COMPOSED_REFUSAL_REOPENED", "run_id": refusal["run_id"]}, sort_keys=True))


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    command = commands.add_parser("run")
    for name in ("image", "checksums", "nq-deb", "ag-deb", "composition-deb", "composition-receipt"):
        command.add_argument("--" + name, type=pathlib.Path, required=True)
    command.add_argument("--nq-harness", type=pathlib.Path, required=True)
    command.add_argument("--output", type=pathlib.Path, required=True)
    command.add_argument("--run-id", required=True)
    command.add_argument("--harness-subject", required=True)
    command.add_argument("--composition-subject", required=True)
    command.add_argument("--producer-unit", required=True)
    command.add_argument("--controller-ssh-port", type=int, default=23151)
    command.add_argument("--target-ssh-port", type=int, default=23152)
    command.add_argument("--fixture-link-port", type=int, default=24577)
    command.add_argument("--preflight-only", action="store_true")
    check = commands.add_parser("check-run")
    check.add_argument("path", type=pathlib.Path)
    check.add_argument("--nq-harness", type=pathlib.Path, required=True)
    refusal = commands.add_parser("check-refusal")
    refusal.add_argument("path", type=pathlib.Path)
    refusal.add_argument("--nq-harness", type=pathlib.Path, required=True)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        nq = load_module("nq_operator_beta_m1b", args.nq_harness)
        exact_repository(args.nq_harness, NQ_HEAD, NQ_TREE, nq)
        if args.command == "check-run":
            check_run(args.path, nq)
        elif args.command == "check-refusal":
            check_refusal(args.path, nq)
        else:
            producer_class(nq)(args).execute()
    except Exception as error:
        print(f"composed M1B qualification refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
