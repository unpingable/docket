#!/usr/bin/env python3
"""One-shot launch custody and query-only status for the fixed M2 demonstration.

This is a deliberately closed adapter around the accepted composition runner.
It is not a scheduler, retry controller, or general campaign interface.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import time
from typing import Any, Protocol


HERE = pathlib.Path(__file__).resolve().parent
RUNNER_PATH = HERE / "run_composed_two_vm.py"
SPEC_SCHEMA = "constellation.operator_beta.fixed_demo_launch_spec.v1"
INTENT_SCHEMA = "constellation.operator_beta.fixed_demo_launch_intent.v1"
ACCEPTED_SCHEMA = "constellation.operator_beta.fixed_demo_launch_accepted.v1"
PROJECTION_SCHEMA = "constellation.operator_beta.fixed_demo_status.v1"
SCENARIO = "operator-beta-systemd-http-recovery"
MAX_RECORD_BYTES = 1024 * 1024
MAX_BOUND_FILE_BYTES = 8 * 1024 * 1024 * 1024
MAX_REASON_BYTES = 4096
RUN_BOUND_SECONDS = 7200
PORT_FIELDS = ("controller_ssh_port", "target_ssh_port", "fixture_link_port")
INPUT_FIELDS = (
    "image",
    "checksums",
    "nq_deb",
    "ag_deb",
    "composition_deb",
    "composition_receipt",
)


class Refusal(RuntimeError):
    """A fixed-controller contract refusal."""


class Manager(Protocol):
    def start(self, spec: dict[str, Any], argv: list[str], spec_sha256: str) -> None: ...

    def query(self, unit: str) -> dict[str, Any]: ...


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_path(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def pathname_exists(path: pathlib.Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def stat_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def duplicate_free_object(raw: bytes, label: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise Refusal(f"{label} contains a duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Refusal(f"{label} is not JSON") from error
    if not isinstance(value, dict):
        raise Refusal(f"{label} is not one object")
    return value


def read_nofollow_path(
    path: pathlib.Path, label: str, expected_bytes: int | None = None
) -> tuple[bytes, os.stat_result]:
    if not path.is_absolute():
        raise Refusal(f"{label} path is not absolute")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise Refusal(f"{label} cannot be opened") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise Refusal(f"{label} is not a regular file")
        if metadata.st_size <= 0 or metadata.st_size > MAX_RECORD_BYTES:
            raise Refusal(f"{label} exceeds its byte bound")
        if expected_bytes is not None and metadata.st_size != expected_bytes:
            raise Refusal(f"{label} length differs")
        chunks = []
        remaining = metadata.st_size
        while remaining:
            block = os.read(descriptor, min(remaining, 1024 * 1024))
            if not block:
                raise Refusal(f"{label} ended before its recorded length")
            chunks.append(block)
            remaining -= len(block)
        raw = b"".join(chunks)
        if stat_identity(os.fstat(descriptor)) != stat_identity(metadata):
            raise Refusal(f"{label} changed while being read")
        return raw, metadata
    finally:
        os.close(descriptor)


def read_at(directory: int, name: str, label: str) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=directory)
    except OSError as error:
        raise Refusal(f"{label} cannot be opened") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise Refusal(f"{label} is not a regular file")
        if metadata.st_size <= 0 or metadata.st_size > MAX_RECORD_BYTES:
            raise Refusal(f"{label} exceeds its byte bound")
        raw = b""
        while len(raw) < metadata.st_size:
            block = os.read(descriptor, metadata.st_size - len(raw))
            if not block:
                raise Refusal(f"{label} ended before its recorded length")
            raw += block
        if stat_identity(os.fstat(descriptor)) != stat_identity(metadata):
            raise Refusal(f"{label} changed while being read")
        return raw, metadata
    finally:
        os.close(descriptor)


def create_exclusive_at(directory: int, name: str, raw: bytes, mode: int = 0o400) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(name, flags, mode, dir_fd=directory)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise Refusal(f"could not write complete {name}")
            view = view[written:]
        os.fdatasync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(directory)


def exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise Refusal(f"{label} fields are not closed")


def absolute_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\n" in value:
        raise Refusal(f"{label} is not one path")
    path = pathlib.Path(value)
    if not path.is_absolute() or str(path) != value:
        raise Refusal(f"{label} is not one absolute normalized path")
    return value


def hex_digest(value: Any, label: str, length: int = 64) -> str:
    if not isinstance(value, str) or not re.fullmatch(rf"[0-9a-f]{{{length}}}", value):
        raise Refusal(f"{label} is not one lowercase digest")
    return value


def validate_spec(value: dict[str, Any]) -> None:
    exact_keys(
        value,
        {
            "schema",
            "scenario",
            "controller_subject",
            "controller_tree",
            "state_root",
            "state_root_device",
            "state_root_inode",
            "state_root_uid",
            "state_root_gid",
            "state_root_mode",
            "run_id",
            "run_root",
            "producer_unit",
            "controller_ssh_port",
            "target_ssh_port",
            "fixture_link_port",
            "run_bound_seconds",
            "working_directory",
            "runner",
            "nq_harness",
            "composition_subject",
            "composition_tree",
            "inputs",
        },
        "fixed demo spec",
    )
    if value["schema"] != SPEC_SCHEMA or value["scenario"] != SCENARIO:
        raise Refusal("fixed demo spec names another protocol or scenario")
    for field in ("controller_subject", "controller_tree", "composition_subject", "composition_tree"):
        hex_digest(value[field], field, 40)
    for field in ("state_root", "run_root", "working_directory"):
        absolute_string(value[field], field)
    if value["state_root"] == value["run_root"]:
        raise Refusal("controller state and run roots must be distinct")
    for field in ("state_root_device", "state_root_inode", "state_root_uid", "state_root_gid"):
        if not isinstance(value[field], int) or value[field] < 0:
            raise Refusal(f"{field} is invalid")
    if value["state_root_mode"] != 0o700:
        raise Refusal("controller state root mode is not 0700")
    if value["run_bound_seconds"] != RUN_BOUND_SECONDS:
        raise Refusal("fixed demo run bound differs")
    if not isinstance(value["run_id"], str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", value["run_id"]):
        raise Refusal("fixed demo run identity is invalid")
    if not isinstance(value["producer_unit"], str) or not re.fullmatch(
        r"[A-Za-z0-9_.@:-]{1,255}\.service", value["producer_unit"]
    ):
        raise Refusal("fixed demo producer unit is invalid")
    ports = []
    for field in PORT_FIELDS:
        port = value[field]
        if not isinstance(port, int) or not 1024 <= port <= 65535:
            raise Refusal(f"{field} is invalid")
        ports.append(port)
    if len(set(ports)) != len(ports):
        raise Refusal("fixed demo ports are not distinct")
    for field in ("runner", "nq_harness"):
        record = value[field]
        if not isinstance(record, dict):
            raise Refusal(f"{field} is not one record")
        expected = {"path", "bytes", "sha256", "subject", "tree"}
        if field == "nq_harness":
            expected.add("qualified_harness_subject")
        exact_keys(record, expected, field)
        absolute_string(record["path"], f"{field} path")
        if not isinstance(record["bytes"], int) or record["bytes"] <= 0:
            raise Refusal(f"{field} length is invalid")
        hex_digest(record["sha256"], f"{field} sha256")
        hex_digest(record["subject"], f"{field} subject", 40)
        hex_digest(record["tree"], f"{field} tree", 40)
        if field == "nq_harness":
            hex_digest(record["qualified_harness_subject"], "qualified harness subject", 40)
    inputs = value["inputs"]
    if not isinstance(inputs, dict) or set(inputs) != set(INPUT_FIELDS):
        raise Refusal("fixed demo inputs are not closed")
    for name in INPUT_FIELDS:
        record = inputs[name]
        if not isinstance(record, dict):
            raise Refusal(f"{name} input is not one record")
        exact_keys(record, {"path", "bytes", "sha256"}, f"{name} input")
        absolute_string(record["path"], f"{name} input path")
        if not isinstance(record["bytes"], int) or record["bytes"] <= 0:
            raise Refusal(f"{name} input length is invalid")
        hex_digest(record["sha256"], f"{name} input sha256")


def load_spec(path: pathlib.Path, expected_bytes: int, expected_sha256: str) -> tuple[dict[str, Any], bytes]:
    hex_digest(expected_sha256, "expected spec sha256")
    raw, _metadata = read_nofollow_path(path, "fixed demo spec", expected_bytes)
    if digest_bytes(raw) != expected_sha256:
        raise Refusal("fixed demo spec digest differs")
    value = duplicate_free_object(raw, "fixed demo spec")
    if raw != canonical(value) + b"\n":
        raise Refusal("fixed demo spec is not one canonical newline-framed object")
    validate_spec(value)
    return value, raw


def verify_bound_file(record: dict[str, Any], label: str) -> None:
    path = pathlib.Path(record["path"])
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise Refusal(f"{label} cannot be opened") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size != record["bytes"]
            or metadata.st_size <= 0
            or metadata.st_size > MAX_BOUND_FILE_BYTES
        ):
            raise Refusal(f"{label} identity or length differs")
        digest = hashlib.sha256()
        remaining = metadata.st_size
        while remaining:
            block = os.read(descriptor, min(remaining, 1024 * 1024))
            if not block:
                raise Refusal(f"{label} ended before its recorded length")
            digest.update(block)
            remaining -= len(block)
        if stat_identity(os.fstat(descriptor)) != stat_identity(metadata):
            raise Refusal(f"{label} changed while being read")
        if digest.hexdigest() != record["sha256"]:
            raise Refusal(f"{label} digest differs")
    finally:
        os.close(descriptor)


def runner_argv(spec: dict[str, Any]) -> list[str]:
    inputs = spec["inputs"]
    argv = ["/usr/bin/python3", spec["runner"]["path"], "run"]
    for name in INPUT_FIELDS:
        argv.extend(["--" + name.replace("_", "-"), inputs[name]["path"]])
    argv.extend(
        [
            "--nq-harness",
            spec["nq_harness"]["path"],
            "--output",
            spec["run_root"],
            "--run-id",
            spec["run_id"],
            "--harness-subject",
            spec["nq_harness"]["subject"],
            "--composition-subject",
            spec["composition_subject"],
            "--producer-unit",
            spec["producer_unit"],
            "--controller-ssh-port",
            str(spec["controller_ssh_port"]),
            "--target-ssh-port",
            str(spec["target_ssh_port"]),
            "--fixture-link-port",
            str(spec["fixture_link_port"]),
        ]
    )
    return argv


def expected_execution(spec: dict[str, Any], argv: list[str], spec_sha256: str) -> dict[str, Any]:
    return {
        "argv": argv,
        "working_directory": spec["working_directory"],
        "environment": {"CONSTELLATION_FIXED_DEMO_SPEC_SHA256": spec_sha256},
    }


def intent_record(spec: dict[str, Any], spec_raw: bytes, spec_sha256: str) -> dict[str, Any]:
    argv = runner_argv(spec)
    execution = expected_execution(spec, argv, spec_sha256)
    return {
        "schema": INTENT_SCHEMA,
        "scenario": SCENARIO,
        "spec_bytes": len(spec_raw),
        "spec_sha256": spec_sha256,
        "controller_subject": spec["controller_subject"],
        "controller_tree": spec["controller_tree"],
        "state_root": spec["state_root"],
        "state_root_device": spec["state_root_device"],
        "state_root_inode": spec["state_root_inode"],
        "run_id": spec["run_id"],
        "run_root": spec["run_root"],
        "producer_unit": spec["producer_unit"],
        "runner_sha256": spec["runner"]["sha256"],
        "execution_sha256": digest_bytes(canonical(execution)),
    }


def validate_intent(value: dict[str, Any], expected: dict[str, Any]) -> None:
    if value != expected:
        raise Refusal("launch intent differs from the fixed spec")


def process_start_ticks(pid: int) -> int:
    try:
        raw = pathlib.Path(f"/proc/{pid}/stat").read_text()
    except OSError as error:
        raise Refusal("manager PID is not observable") from error
    closing = raw.rfind(")")
    fields = raw[closing + 2 :].split() if closing >= 0 else []
    if len(fields) < 20 or not fields[19].isdigit():
        raise Refusal("manager PID start ticks are not observable")
    return int(fields[19])


def process_execution(pid: int, spec_sha256: str) -> dict[str, Any]:
    try:
        argv_raw = pathlib.Path(f"/proc/{pid}/cmdline").read_bytes()
        cwd = os.readlink(f"/proc/{pid}/cwd")
        environment_raw = pathlib.Path(f"/proc/{pid}/environ").read_bytes()
    except (OSError, UnicodeDecodeError) as error:
        raise Refusal("manager process execution is not observable") from error
    argv = [part.decode() for part in argv_raw.rstrip(b"\0").split(b"\0")]
    environment = {}
    for item in environment_raw.rstrip(b"\0").split(b"\0"):
        if item.startswith(b"CONSTELLATION_FIXED_DEMO_SPEC_SHA256="):
            key, value = item.decode().split("=", 1)
            environment[key] = value
    return {
        "argv": argv,
        "working_directory": cwd,
        "environment": environment,
    }


class SystemdUserManager:
    def start(self, spec: dict[str, Any], argv: list[str], spec_sha256: str) -> None:
        command = [
            "systemd-run",
            "--user",
            "--quiet",
            "--no-block",
            "--collect",
            "--unit",
            spec["producer_unit"],
            "--property",
            f"WorkingDirectory={spec['working_directory']}",
            "--setenv",
            f"CONSTELLATION_FIXED_DEMO_SPEC_SHA256={spec_sha256}",
            "--",
            *argv,
        ]
        completed = subprocess.run(command, capture_output=True, check=False, timeout=30)
        if completed.returncode != 0:
            reason = completed.stderr.decode(errors="replace")[:MAX_REASON_BYTES].strip()
            raise Refusal(f"user-systemd start refused: {reason or 'no detail'}")

    def query(self, unit: str) -> dict[str, Any]:
        completed = subprocess.run(
            [
                "systemctl",
                "--user",
                "show",
                unit,
                "--property=LoadState",
                "--property=ActiveState",
                "--property=SubState",
                "--property=InvocationID",
                "--property=MainPID",
            ],
            capture_output=True,
            check=False,
            timeout=10,
        )
        if completed.returncode != 0:
            return {
                "source": "user-systemd",
                "state": "NOT_OBSERVABLE",
                "reason": completed.stderr.decode(errors="replace")[:MAX_REASON_BYTES].strip(),
            }
        properties = dict(
            line.split("=", 1)
            for line in completed.stdout.decode(errors="strict").splitlines()
            if "=" in line
        )
        return {"source": "user-systemd", "state": "OBSERVED", "properties": properties}


def open_state_root(spec: dict[str, Any]) -> int:
    path = pathlib.Path(spec["state_root"])
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise Refusal("controller state root cannot be opened") from error
    metadata = os.fstat(descriptor)
    expected = (
        spec["state_root_device"],
        spec["state_root_inode"],
        spec["state_root_uid"],
        spec["state_root_gid"],
        spec["state_root_mode"],
    )
    observed = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IMODE(metadata.st_mode),
    )
    if not stat.S_ISDIR(metadata.st_mode) or observed != expected:
        os.close(descriptor)
        raise Refusal("controller state root identity differs")
    return descriptor


def load_child_record(directory: int, name: str, label: str) -> tuple[dict[str, Any], bytes]:
    raw, metadata = read_at(directory, name, label)
    if stat.S_IMODE(metadata.st_mode) != 0o400:
        raise Refusal(f"{label} mode differs")
    value = duplicate_free_object(raw, label)
    if raw != canonical(value) + b"\n":
        raise Refusal(f"{label} is not one canonical newline-framed object")
    return value, raw


def optional_child_record(directory: int, name: str, label: str) -> tuple[dict[str, Any], bytes] | None:
    try:
        return load_child_record(directory, name, label)
    except Refusal as error:
        try:
            os.stat(name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            return None
        raise error


def manager_occurrence(
    manager: Manager, spec: dict[str, Any], argv: list[str], spec_sha256: str
) -> dict[str, Any]:
    observed = manager.query(spec["producer_unit"])
    if observed.get("state") != "OBSERVED":
        return observed
    properties = observed.get("properties")
    if not isinstance(properties, dict):
        return {"source": "user-systemd", "state": "NOT_OBSERVABLE", "reason": "invalid reply"}
    try:
        pid = int(properties.get("MainPID", "0"))
    except (TypeError, ValueError):
        pid = 0
    active = properties.get("ActiveState") == "active" and pid > 0
    result: dict[str, Any] = {
        "source": "user-systemd",
        "state": "PROCESS_ACTIVE" if active else "PROCESS_EXITED",
        "load_state": properties.get("LoadState", "NOT_OBSERVABLE"),
        "active_state": properties.get("ActiveState", "NOT_OBSERVABLE"),
        "sub_state": properties.get("SubState", "NOT_OBSERVABLE"),
        "invocation_id": properties.get("InvocationID") or "NOT_OBSERVABLE",
        "main_pid": pid,
    }
    if active:
        try:
            result["start_ticks"] = process_start_ticks(pid)
            execution = process_execution(pid, spec_sha256)
            result["execution_sha256"] = digest_bytes(canonical(execution))
            result["execution_matches"] = execution == expected_execution(spec, argv, spec_sha256)
        except Refusal as error:
            result["state"] = "NOT_OBSERVABLE"
            result["reason"] = str(error)
    return result


def await_manager_occurrence(
    manager: Manager, spec: dict[str, Any], argv: list[str], spec_sha256: str
) -> dict[str, Any]:
    deadline = time.monotonic() + 5.0
    while True:
        occurrence = manager_occurrence(manager, spec, argv, spec_sha256)
        if occurrence.get("state") in {"PROCESS_ACTIVE", "NOT_OBSERVABLE"}:
            return occurrence
        if time.monotonic() >= deadline:
            return occurrence
        time.sleep(0.05)


def accepted_record(
    spec: dict[str, Any], intent_raw: bytes, occurrence: dict[str, Any]
) -> dict[str, Any]:
    if occurrence.get("state") != "PROCESS_ACTIVE" or occurrence.get("execution_matches") is not True:
        raise Refusal("manager occurrence does not match the launch intent")
    invocation = occurrence.get("invocation_id")
    if not isinstance(invocation, str) or not re.fullmatch(r"[0-9a-fA-F]{32}", invocation):
        raise Refusal("manager occurrence has no exact invocation identity")
    return {
        "schema": ACCEPTED_SCHEMA,
        "scenario": SCENARIO,
        "intent_sha256": digest_bytes(intent_raw),
        "run_id": spec["run_id"],
        "producer_unit": spec["producer_unit"],
        "invocation_id": invocation.lower(),
        "main_pid": occurrence["main_pid"],
        "start_ticks": occurrence["start_ticks"],
        "execution_sha256": occurrence["execution_sha256"],
    }


def os_occurrence_from_acceptance(
    accepted: dict[str, Any], spec: dict[str, Any], spec_sha256: str, manager_testimony: dict[str, Any]
) -> dict[str, Any]:
    pid = accepted["main_pid"]
    try:
        ticks = process_start_ticks(pid)
    except Refusal:
        return {
            "source": "OS process table plus retained Docket launch acceptance",
            "state": "PROCESS_EXITED",
            "main_pid": pid,
            "start_ticks": accepted["start_ticks"],
            "manager_testimony": manager_testimony,
        }
    if ticks != accepted["start_ticks"]:
        return {
            "source": "OS process table plus retained Docket launch acceptance",
            "state": "PROCESS_EXITED",
            "main_pid": pid,
            "start_ticks": accepted["start_ticks"],
            "unrelated_pid_start_ticks": ticks,
            "manager_testimony": manager_testimony,
        }
    try:
        execution = process_execution(pid, spec_sha256)
    except Refusal as error:
        return {
            "source": "OS process table",
            "state": "NOT_OBSERVABLE",
            "reason": str(error),
            "manager_testimony": manager_testimony,
        }
    matches = execution == expected_execution(spec, runner_argv(spec), spec_sha256)
    return {
        "source": "OS process table plus retained Docket launch acceptance",
        "state": "PROCESS_ACTIVE",
        "main_pid": pid,
        "start_ticks": ticks,
        "invocation_id": accepted["invocation_id"],
        "execution_sha256": digest_bytes(canonical(execution)),
        "execution_matches": matches,
        "manager_testimony": manager_testimony,
    }


def load_owner_modules(spec: dict[str, Any]) -> tuple[Any, Any]:
    runner_spec = importlib.util.spec_from_file_location("fixed_demo_composition_runner", spec["runner"]["path"])
    if runner_spec is None or runner_spec.loader is None:
        raise Refusal("composition runner cannot be loaded")
    runner = importlib.util.module_from_spec(runner_spec)
    sys.modules[runner_spec.name] = runner
    runner_spec.loader.exec_module(runner)
    nq = runner.load_module("fixed_demo_nq_harness", pathlib.Path(spec["nq_harness"]["path"]))
    return runner, nq


def owner_terminal(spec: dict[str, Any]) -> dict[str, Any] | None:
    root = pathlib.Path(spec["run_root"])
    if not pathname_exists(root):
        return None
    runner, nq = load_owner_modules(spec)
    has_result = pathname_exists(root / "RESULT.json")
    has_manifest = pathname_exists(root / "ARTIFACTS.sha256")
    has_refusal = pathname_exists(root / "REFUSAL.json")
    if has_refusal and (has_result or has_manifest):
        return {
            "state": "INDETERMINATE",
            "owner": "Docket",
            "reason": "composition run has conflicting terminal record families",
        }
    if has_result or has_manifest:
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                runner.check_run(root, nq)
            result = nq.load_json_artifact(root / "RESULT.json", "composition result")
            if (
                result.get("run_id") != spec["run_id"]
                or result.get("composition_subject") != spec["composition_subject"]
                or result.get("nq_harness_subject") != spec["nq_harness"]["subject"]
            ):
                raise Refusal("composition result disagrees with the fixed launch spec")
        except Exception as error:
            return {"state": "INDETERMINATE", "owner": "Docket", "reason": str(error)}
        return {
            "state": "TERMINAL",
            "owner": "Docket",
            "disposition": result["disposition"],
            "evidence": str(root / "RESULT.json"),
            "replay": "check-run",
        }
    if has_refusal:
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                runner.check_refusal(root, nq)
            recovery = nq.load_recovery(root)
            if (
                recovery.get("run_id") != spec["run_id"]
                or recovery.get("harness_subject") != spec["nq_harness"]["subject"]
                or recovery.get("composition", {}).get("subject")
                != spec["composition_subject"]
            ):
                raise Refusal("composition refusal disagrees with the fixed launch spec")
        except Exception as error:
            return {"state": "INDETERMINATE", "owner": "Docket", "reason": str(error)}
        return {
            "state": "REFUSED",
            "owner": "Docket",
            "disposition": "REFUSED",
            "evidence": str(root / "REFUSAL.json"),
            "replay": "check-refusal",
        }
    return None


def runner_recovery(spec: dict[str, Any], accepted: dict[str, Any] | None) -> dict[str, Any] | None:
    path = pathlib.Path(spec["run_root"])
    if not pathname_exists(path / "RECOVERY.json"):
        return None
    runner, nq = load_owner_modules(spec)
    try:
        recovery = nq.load_recovery(path)
    except Exception as error:
        return {"state": "INDETERMINATE", "reason": str(error)}
    producer = recovery.get("producer", {})
    fixed = (
        recovery.get("run_id") == spec["run_id"]
        and recovery.get("harness_subject") == spec["nq_harness"]["subject"]
        and producer.get("systemd_unit") == spec["producer_unit"]
    )
    if accepted is not None:
        fixed = fixed and (
            str(producer.get("invocation_id", "")).lower() == accepted["invocation_id"]
            and producer.get("main_pid") == accepted["main_pid"]
            and producer.get("start_ticks") == accepted["start_ticks"]
        )
    if not fixed:
        return {"state": "INDETERMINATE", "reason": "runner recovery disagrees with launch custody"}
    return {
        "state": "REOPENED",
        "phase": recovery.get("phase", "NOT_OBSERVABLE"),
        "last_completed_phase": recovery.get("last_completed_phase", "NOT_OBSERVABLE"),
        "next_lawful_action": recovery.get("next_lawful_action", "NOT_OBSERVABLE"),
        "effect_outcome": recovery.get("effect_outcome", "NOT_OBSERVABLE"),
        "producer": producer,
    }


def status_projection(
    spec: dict[str, Any], spec_raw: bytes, spec_sha256: str, manager: Manager
) -> dict[str, Any]:
    argv = runner_argv(spec)
    expected_intent = intent_record(spec, spec_raw, spec_sha256)
    directory = open_state_root(spec)
    disagreements: list[str] = []
    try:
        try:
            intent_item = optional_child_record(directory, "launch-intent.v1.json", "launch intent")
        except Refusal as error:
            intent_item = None
            disagreements.append(str(error))
        try:
            accepted_item = optional_child_record(
                directory, "launch-accepted.v1.json", "launch acceptance"
            )
        except Refusal as error:
            accepted_item = None
            disagreements.append(str(error))
    finally:
        os.close(directory)
    occurrence = manager_occurrence(manager, spec, argv, spec_sha256)
    if intent_item is None:
        intent = None
    else:
        intent, _intent_raw = intent_item
        try:
            validate_intent(intent, expected_intent)
        except Refusal as error:
            disagreements.append(str(error))
    accepted = accepted_item[0] if accepted_item else None
    accepted_for_binding = accepted
    if accepted is not None:
        expected_fields = {
            "schema", "scenario", "intent_sha256", "run_id", "producer_unit",
            "invocation_id", "main_pid", "start_ticks", "execution_sha256",
        }
        if set(accepted) != expected_fields or accepted.get("schema") != ACCEPTED_SCHEMA:
            disagreements.append("launch acceptance fields disagree")
            accepted_for_binding = None
        if intent_item is None or accepted.get("intent_sha256") != digest_bytes(intent_item[1]):
            disagreements.append("launch acceptance does not bind the retained intent")
            accepted_for_binding = None
        if accepted.get("run_id") != spec["run_id"] or accepted.get("producer_unit") != spec["producer_unit"]:
            disagreements.append("launch acceptance names another occurrence")
            accepted_for_binding = None
        if occurrence.get("state") == "PROCESS_ACTIVE" and (
            str(occurrence.get("invocation_id", "")).lower() != accepted.get("invocation_id")
            or occurrence.get("main_pid") != accepted.get("main_pid")
            or occurrence.get("start_ticks") != accepted.get("start_ticks")
            or occurrence.get("execution_sha256") != accepted.get("execution_sha256")
            or occurrence.get("execution_matches") is not True
        ):
            disagreements.append("live manager occurrence disagrees with launch acceptance")
            accepted_for_binding = None
    if accepted_for_binding is not None and occurrence.get("state") == "NOT_OBSERVABLE":
        occurrence = os_occurrence_from_acceptance(
            accepted_for_binding, spec, spec_sha256, occurrence
        )
        if occurrence.get("state") == "PROCESS_ACTIVE" and occurrence.get("execution_matches") is not True:
            disagreements.append("OS process occurrence differs from launch acceptance")
    recovery = runner_recovery(spec, accepted_for_binding)
    if (
        recovery is not None
        and recovery.get("state") == "REOPENED"
        and occurrence.get("state") == "PROCESS_ACTIVE"
    ):
        producer = recovery.get("producer", {})
        if (
            str(producer.get("invocation_id", "")).lower()
            != str(occurrence.get("invocation_id", "")).lower()
            or producer.get("main_pid") != occurrence.get("main_pid")
            or producer.get("start_ticks") != occurrence.get("start_ticks")
            or occurrence.get("execution_matches") is not True
        ):
            disagreements.append("live manager occurrence disagrees with runner recovery")
    terminal = owner_terminal(spec)
    if terminal is not None and terminal.get("state") == "INDETERMINATE":
        disagreements.append(terminal.get("reason", "terminal owner disagreement"))
    if recovery is not None and recovery.get("state") == "INDETERMINATE":
        disagreements.append(recovery.get("reason", "runner recovery disagreement"))
    if disagreements:
        durable_state = "INDETERMINATE"
    elif terminal is not None:
        durable_state = terminal["state"]
    elif recovery is not None:
        durable_state = recovery.get("phase", "NONTERMINAL")
    elif accepted_for_binding is not None:
        durable_state = "STARTED_AWAITING_RUNNER_CUSTODY"
    elif intent_item is not None:
        durable_state = "INDETERMINATE_LAUNCH_OUTCOME"
        if occurrence.get("state") == "PROCESS_ACTIVE":
            disagreements.append("manager confirms an active occurrence without launch acceptance")
        if occurrence.get("execution_matches") is False:
            disagreements.append("active manager process differs from the fixed execution")
    elif occurrence.get("state") == "PROCESS_ACTIVE":
        durable_state = "INDETERMINATE"
        disagreements.append("active unit exists without launch intent")
    else:
        durable_state = "NOT_STARTED"
    return {
        "schema": PROJECTION_SCHEMA,
        "scenario": SCENARIO,
        "subject": {"spec_sha256": spec_sha256, "run_id": spec["run_id"]},
        "durable": {
            "source": "Docket fixed controller and composition owner records",
            "state": durable_state,
            "recovery": recovery,
            "terminal": terminal,
        },
        "liveness": occurrence,
        "execution": {
            "identity": "BOUNDED_COMPOSITION_RUNNER",
            "model_provider": "NOT_APPLICABLE",
        },
        "disagreements": disagreements,
        "limitations": {
            "aggregate_postcondition": "NOT_RECORDED",
            "literal_distributed_exactly_once": "NOT_CLAIMED",
            "signed_upstream_checksum": "NOT_QUALIFIED",
            "deployment": "NOT_RUN",
            "production": "NOT_RUN",
        },
    }


class FixedController:
    def __init__(
        self,
        spec_path: pathlib.Path,
        expected_bytes: int,
        expected_sha256: str,
        manager: Manager | None = None,
        cut_hook: Any | None = None,
    ) -> None:
        self.spec_path = spec_path
        self.expected_bytes = expected_bytes
        self.expected_sha256 = expected_sha256
        self.manager = manager or SystemdUserManager()
        self.cut_hook = cut_hook or (lambda _name: None)

    def status(self) -> dict[str, Any]:
        spec, raw = load_spec(self.spec_path, self.expected_bytes, self.expected_sha256)
        verify_bound_file(spec["runner"], "composition runner")
        verify_bound_file(spec["nq_harness"], "NQ harness")
        return status_projection(spec, raw, self.expected_sha256, self.manager)

    def start(self) -> dict[str, Any]:
        spec, spec_raw = load_spec(self.spec_path, self.expected_bytes, self.expected_sha256)
        verify_bound_file(spec["runner"], "composition runner")
        verify_bound_file(spec["nq_harness"], "NQ harness")
        for name in INPUT_FIELDS:
            verify_bound_file(spec["inputs"][name], f"{name} input")
        argv = runner_argv(spec)
        intent = intent_record(spec, spec_raw, self.expected_sha256)
        intent_raw = canonical(intent) + b"\n"
        directory = open_state_root(spec)
        lock_descriptor = -1
        try:
            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            lock_descriptor = os.open("launch.lock", flags, 0o600, dir_fd=directory)
            lock_metadata = os.fstat(lock_descriptor)
            if (
                not stat.S_ISREG(lock_metadata.st_mode)
                or stat.S_IMODE(lock_metadata.st_mode) != 0o600
                or lock_metadata.st_uid != spec["state_root_uid"]
                or lock_metadata.st_gid != spec["state_root_gid"]
            ):
                raise Refusal("launch lock identity or mode differs")
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
            existing = optional_child_record(directory, "launch-intent.v1.json", "launch intent")
            if existing is not None:
                validate_intent(existing[0], intent)
                return status_projection(spec, spec_raw, self.expected_sha256, self.manager)
            create_exclusive_at(directory, "launch-intent.v1.json", intent_raw)
            self.cut_hook("intent_durable")
            self.manager.start(spec, argv, self.expected_sha256)
            self.cut_hook("manager_returned")
            occurrence = await_manager_occurrence(
                self.manager, spec, argv, self.expected_sha256
            )
            accepted = accepted_record(spec, intent_raw, occurrence)
            create_exclusive_at(directory, "launch-accepted.v1.json", canonical(accepted) + b"\n")
            self.cut_hook("acceptance_durable")
        finally:
            if lock_descriptor >= 0:
                os.close(lock_descriptor)
            os.close(directory)
        return status_projection(spec, spec_raw, self.expected_sha256, self.manager)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("command", choices=("start", "status"))
    root.add_argument("--spec", type=pathlib.Path, required=True)
    root.add_argument("--spec-bytes", type=int, required=True)
    root.add_argument("--spec-sha256", required=True)
    return root


def main() -> int:
    args = parser().parse_args()
    controller = FixedController(args.spec, args.spec_bytes, args.spec_sha256)
    try:
        projection = controller.start() if args.command == "start" else controller.status()
    except Exception as error:
        print(f"fixed demo controller refused: {error}", file=sys.stderr)
        return 1
    print(json.dumps(projection, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
