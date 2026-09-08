#!/usr/bin/env python3
"""One-shot launch custody and query-only status for the fixed M2 demonstration.

This is a deliberately closed adapter around the accepted composition runner.
It is not a scheduler, retry controller, or general campaign interface.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import fcntl
import hashlib
import importlib.util
import importlib.abc
import io
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import time
import zlib
from typing import Any, Protocol


HERE = pathlib.Path(__file__).resolve().parent
RUNNER_PATH = HERE / "run_composed_two_vm.py"
CHECKER_BYTES = 54529
CHECKER_SHA256 = "4c44d4ff56a6802ac9af0279c059278a799a77353c8d9b21c8cb4af659ed2bb1"
SPEC_SCHEMA = "constellation.operator_beta.fixed_demo_launch_spec.v1"
INTENT_SCHEMA = "constellation.operator_beta.fixed_demo_launch_intent.v1"
ACCEPTED_SCHEMA = "constellation.operator_beta.fixed_demo_launch_accepted.v1"
PROJECTION_SCHEMA = "constellation.operator_beta.fixed_demo_status.v1"
SCENARIO = "operator-beta-systemd-http-recovery"
MAX_RECORD_BYTES = 1024 * 1024
MAX_BOUND_FILE_BYTES = 8 * 1024 * 1024 * 1024
MAX_REASON_BYTES = 4096
RUN_BOUND_SECONDS = 7200
LOCK_WAIT_SECONDS = 5.0
PORT_FIELDS = ("controller_ssh_port", "target_ssh_port", "fixture_link_port")
INPUT_FIELDS = (
    "image",
    "checksums",
    "nq_deb",
    "ag_deb",
    "composition_deb",
    "composition_receipt",
)

ADMITTED_SPEC_PATH = pathlib.Path(
    "/var/tmp/constellation-operator-beta-m2-controller-run-002/fixed-demo-spec.v1.json"
)
# Independently enrolled physical state/lock identity, frozen before launch.
# These literals must be supplied by the integration owner's enrollment record;
# absent enrollment is a refusal, never a digest derived from candidate bytes.
ADMITTED_SPEC_BYTES = 0
ADMITTED_SPEC_SHA256 = ""
COMPOSITION_BASE = "8ac6ea566c2b530f03ee307f0149d2e860fd2583"
COMPOSITION_TREE = "8da5d562c0e14e6804a54ad1e1a84e3741bd05ba"
COMPOSITION_DIRECTORY = "/data/git/.worktrees/docket-operator-beta-systemd-composition-v1"
INPUT_DIRECTORY = "/data/git/.campaign-artifacts/docket-systemd-composition-v1/operator-beta-composed-m1b-v1/run-002/input"
ADMITTED_COHORT: dict[str, Any] | None = {
    "scenario": SCENARIO,
    "controller_base_subject": COMPOSITION_BASE,
    "controller_base_tree": COMPOSITION_TREE,
    "state_root": "/var/tmp/constellation-operator-beta-m2-controller-run-002/state",
    "run_id": "operator-beta-composed-m2-run-002",
    "run_root": "/data/git/.campaign-artifacts/constellation-operator-beta-composed-m2-run-002",
    "producer_unit": "constellation-operator-beta-composed-m2-run-002.service",
    "controller_ssh_port": 23155,
    "target_ssh_port": 23156,
    "fixture_link_port": 24579,
    "run_bound_seconds": RUN_BOUND_SECONDS,
    "working_directory": COMPOSITION_DIRECTORY,
    "composition_subject": COMPOSITION_BASE,
    "composition_tree": COMPOSITION_TREE,
    "runner": {
        "path": COMPOSITION_DIRECTORY + "/qualification/operator-beta-systemd-composition-v1/run_composed_two_vm.py",
        "bytes": 45738,
        "sha256": "314f6f7cbbaf66078a609df4ddfe2b5ea17d49a34b4c2113b83644d0c372dc88",
        "subject": COMPOSITION_BASE,
        "tree": COMPOSITION_TREE,
    },
    "builder": {
        "path": COMPOSITION_DIRECTORY + "/qualification/operator-beta-systemd-composition-v1/build_bookworm_fixture.py",
        "bytes": 24750,
        "sha256": "5dbf3d967808154187009dbf4c0b3904545f1066dd6738d4894ce47144d59f8f",
        "subject": COMPOSITION_BASE,
        "tree": COMPOSITION_TREE,
    },
    "nq_harness": {
        "path": "/data/git/.worktrees/nq-ng-operator-beta-profile-v1/qualification/operator-beta-m1b-v1/run_two_vm.py",
        "bytes": 129280,
        "sha256": "2cded8a0a65770ed98c6fa4fc056908e7274bfb6e361075add5396db82c5114e",
        "subject": "9f1b081b7fc5b2d99fb92ee6b0ac4107c7e7dfe4",
        "tree": "dd1a7d1d501848b26fd2d69b44ede75afed710b1",
        "qualified_harness_subject": "dc5d602484a4556c465df6947e98d81dba0d314a",
    },
    "inputs": {
        name: {"path": INPUT_DIRECTORY + "/" + filename, "bytes": size, "sha256": sha}
        for name, filename, size, sha in (
            ("image", "debian-12-genericcloud-amd64-20260903-2590.qcow2", 339214336, "86712ca4faf8697fb7a623699ac1888a7859813ce1abf06d0cb284c1da6d649d"),
            ("checksums", "SHA512SUMS", 6976, "9940ca296126c029ba80df3daf7ec4d1db285e356fc2b7b6ec1e9bd26636459c"),
            ("nq_deb", "nq-ng_amd64.deb", 8703042, "0fd1ce9e1be48b56ba5e526993a94c4682499bb9dbd9304dffd4500c01603636"),
            ("ag_deb", "agent-governor-ng-systemd-executor_amd64.deb", 2649438, "98a4f31f0b6c13653ae95ce55586dbac6d0826b649cd7612882f3716b80e2279"),
            ("composition_deb", "constellation-operator-beta-composition-fixture_0.1.0-1_amd64.deb", 2945714, "5bb3f3d27a4c19cbb2c7bc80bdf69d9f5aab076d9f20cd49b59a8b8c45e4a479"),
            ("composition_receipt", "composition-fixture-receipt.v1.json", 5862, "e1b859a84e77ef94a545daaa6d3fd7acce9e0a249c998a8948306d93e109b4db"),
        )
    },
}

# Only admitted campaign modules are loaded from this capsule. Python, its
# standard library, systemd and the host toolchain are trusted platform inputs.
CAPSULE_BOOTSTRAP = r'''import base64,hashlib,importlib.abc,importlib.util,json,sys,zlib
encoded,expected,entry=sys.argv[1:4]
compressed=base64.urlsafe_b64decode(encoded)
decoder=zlib.decompressobj()
raw=decoder.decompress(compressed,1048577)
if len(raw)>1048576 or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
    raise SystemExit("code capsule exceeds its bound or framing")
if hashlib.sha256(raw).hexdigest()!=expected:
    raise SystemExit("code capsule identity differs")
files=json.loads(raw)
if not isinstance(files,dict) or entry not in files or len(files)!=3:
    raise SystemExit("code capsule module set differs")
class FrozenLoader(importlib.abc.SourceLoader):
    def __init__(self,path): self.path=path
    def get_filename(self,fullname): return self.path
    def get_data(self,path):
        if path not in files: raise ImportError("unadmitted campaign module")
        return files[path].encode()
def frozen_spec(name,location,*args,**kwargs):
    path=str(location)
    if path not in files: raise ImportError("unadmitted campaign module")
    return importlib.util.spec_from_loader(name,FrozenLoader(path))
importlib.util.spec_from_file_location=frozen_spec
sys.argv=sys.argv[3:]
namespace={"__name__":"__main__","__file__":entry,"__package__":None}
exec(compile(files[entry],entry,"exec"),namespace)
'''


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


def executed_source_sha256() -> str:
    value = globals().get("__executed_source_sha256__")
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise Refusal("controller execution has no retained source identity")
    return value


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
            "controller_base_subject",
            "controller_base_tree",
            "state_root",
            "state_root_device",
            "state_root_inode",
            "state_root_uid",
            "state_root_gid",
            "state_root_mode",
            "launch_lock_device",
            "launch_lock_inode",
            "run_id",
            "run_root",
            "producer_unit",
            "controller_ssh_port",
            "target_ssh_port",
            "fixture_link_port",
            "run_bound_seconds",
            "working_directory",
            "runner",
            "builder",
            "nq_harness",
            "composition_subject",
            "composition_tree",
            "inputs",
        },
        "fixed demo spec",
    )
    if value["schema"] != SPEC_SCHEMA or value["scenario"] != SCENARIO:
        raise Refusal("fixed demo spec names another protocol or scenario")
    for field in ("controller_base_subject", "controller_base_tree", "composition_subject", "composition_tree"):
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
    for field in ("launch_lock_device", "launch_lock_inode"):
        if not isinstance(value[field], int) or value[field] <= 0:
            raise Refusal(f"{field} is invalid")
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
    for field in ("runner", "builder", "nq_harness"):
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
    validate_admitted_cohort(value)


def admitted_cohort(value: dict[str, Any]) -> dict[str, Any]:
    """Return only the Docket-owned fixed mechanics and occurrence selection."""
    return {
        "scenario": value["scenario"],
        "controller_base_subject": value["controller_base_subject"],
        "controller_base_tree": value["controller_base_tree"],
        "state_root": value["state_root"],
        "run_id": value["run_id"],
        "run_root": value["run_root"],
        "producer_unit": value["producer_unit"],
        "controller_ssh_port": value["controller_ssh_port"],
        "target_ssh_port": value["target_ssh_port"],
        "fixture_link_port": value["fixture_link_port"],
        "run_bound_seconds": value["run_bound_seconds"],
        "working_directory": value["working_directory"],
        "runner": value["runner"],
        "builder": value["builder"],
        "nq_harness": value["nq_harness"],
        "composition_subject": value["composition_subject"],
        "composition_tree": value["composition_tree"],
        "inputs": value["inputs"],
    }


def validate_admitted_cohort(value: dict[str, Any]) -> None:
    if ADMITTED_COHORT is None:
        raise Refusal("Docket fixed demo cohort is not admitted")
    if admitted_cohort(value) != ADMITTED_COHORT:
        raise Refusal("fixed demo spec differs from the Docket-admitted cohort")


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


def verify_owner_repository(record: dict[str, Any]) -> None:
    repository = pathlib.Path(record["path"]).parents[2]
    for arguments, expected in (
        (["rev-parse", "HEAD"], record["subject"] + "\n"),
        (["rev-parse", "HEAD^{tree}"], record["tree"] + "\n"),
        (["status", "--porcelain", "--untracked-files=all"], ""),
    ):
        try:
            result = subprocess.run(
                ["git", "-C", str(repository), *arguments], capture_output=True,
                timeout=10, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise Refusal("owner repository custody is not observable") from error
        if result.returncode or result.stdout != expected.encode() or result.stderr:
            raise Refusal("owner repository differs from the admitted clean subject")


def runner_argv(spec: dict[str, Any]) -> list[str]:
    inputs = spec["inputs"]
    files = {}
    for name in ("runner", "builder", "nq_harness"):
        record = spec[name]
        raw, _metadata = read_nofollow_path(pathlib.Path(record["path"]), name, record["bytes"])
        if digest_bytes(raw) != record["sha256"]:
            raise Refusal(f"{name} capsule source digest differs")
        files[record["path"]] = raw.decode("utf-8")
    capsule = canonical(files)
    # URL-safe base64 excludes systemd's dollar/environment and percent/specifier
    # characters, so the retained argument is not reinterpreted by the manager.
    encoded = base64.urlsafe_b64encode(zlib.compress(capsule, 9)).decode("ascii")
    if len(capsule) > MAX_RECORD_BYTES or len(encoded) > 100000:
        raise Refusal("code capsule exceeds the fixed launch bound")
    argv = ["/usr/bin/python3", "-I", "-B", "-c", CAPSULE_BOOTSTRAP,
            encoded, digest_bytes(capsule), spec["runner"]["path"], "run"]
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
        "controller_base_subject": spec["controller_base_subject"],
        "controller_base_tree": spec["controller_base_tree"],
        "controller_sha256": executed_source_sha256(),
        "checker_sha256": CHECKER_SHA256,
        "state_root": spec["state_root"],
        "state_root_device": spec["state_root_device"],
        "state_root_inode": spec["state_root_inode"],
        "run_id": spec["run_id"],
        "run_root": spec["run_root"],
        "producer_unit": spec["producer_unit"],
        "runner_sha256": spec["runner"]["sha256"],
        "execution_sha256": digest_bytes(canonical(execution)),
        "code_capsule_sha256": argv[6],
        "bootstrap_sha256": digest_bytes(CAPSULE_BOOTSTRAP.encode()),
    }


def validate_intent(value: dict[str, Any], expected: dict[str, Any]) -> None:
    if value != expected:
        raise Refusal("launch intent differs from the fixed spec")


def process_start_ticks(pid: int) -> int:
    try:
        raw = pathlib.Path(f"/proc/{pid}/stat").read_text()
    except (OSError, UnicodeError) as error:
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
        argv = [part.decode() for part in argv_raw.rstrip(b"\0").split(b"\0")]
        environment = {}
        for item in environment_raw.rstrip(b"\0").split(b"\0"):
            if item.startswith(b"CONSTELLATION_FIXED_DEMO_SPEC_SHA256="):
                key, value = item.decode().split("=", 1)
                environment[key] = value
    except (OSError, UnicodeError) as error:
        raise Refusal("manager process execution is not observable") from error
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
            "--property",
            f"RuntimeMaxSec={spec['run_bound_seconds']}",
            "--property",
            "TimeoutStopSec=30",
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
        try:
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
        except (OSError, subprocess.TimeoutExpired) as error:
            return {
                "source": "user-systemd",
                "state": "NOT_OBSERVABLE",
                "reason": str(error)[:MAX_REASON_BYTES],
            }
        if completed.returncode != 0:
            return {
                "source": "user-systemd",
                "state": "NOT_OBSERVABLE",
                "reason": completed.stderr.decode(errors="replace")[:MAX_REASON_BYTES].strip(),
            }
        try:
            properties = {}
            for line in completed.stdout.decode(errors="strict").splitlines():
                if "=" not in line:
                    raise Refusal("manager reply has an invalid property line")
                key, value = line.split("=", 1)
                if key in properties:
                    raise Refusal("manager reply repeats a property")
                properties[key] = value
            validate_manager_properties(properties)
        except (UnicodeError, Refusal) as error:
            return {
                "source": "user-systemd",
                "state": "NOT_OBSERVABLE",
                "reason": str(error)[:MAX_REASON_BYTES],
            }
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


def validate_manager_properties(properties: Any) -> None:
    fields = {"LoadState", "ActiveState", "SubState", "InvocationID", "MainPID"}
    if not isinstance(properties, dict) or set(properties) != fields:
        raise Refusal("manager reply does not contain exactly five requested properties")
    if not all(isinstance(value, str) for value in properties.values()):
        raise Refusal("manager property is not a string")
    if properties["LoadState"] not in {"loaded", "not-found", "bad-setting", "error", "merged", "masked", "stub"}:
        raise Refusal("manager load state is invalid")
    if properties["ActiveState"] not in {"active", "reloading", "inactive", "failed", "activating", "deactivating", "maintenance", "refreshing"}:
        raise Refusal("manager active state is invalid")
    if properties["SubState"] not in {
        "dead", "condition", "start-pre", "start", "start-post", "running", "exited",
        "reload", "reload-signal", "reload-notify", "refreshing", "stop", "stop-watchdog",
        "stop-sigterm", "stop-sigkill", "stop-post", "final-watchdog", "final-sigterm",
        "final-sigkill", "failed", "auto-restart", "auto-restart-queued", "cleaning",
    }:
        raise Refusal("manager service sub-state is invalid")
    pid = properties["MainPID"]
    if not re.fullmatch(r"0|[1-9][0-9]{0,9}", pid) or int(pid) > 2147483647:
        raise Refusal("manager main PID is invalid")
    invocation = properties["InvocationID"]
    if invocation and not re.fullmatch(r"[0-9a-fA-F]{32}", invocation):
        raise Refusal("manager invocation identity is invalid")
    if int(pid) > 0 and not invocation:
        raise Refusal("manager process has no invocation identity")


def manager_occurrence(
    manager: Manager, spec: dict[str, Any], argv: list[str], spec_sha256: str
) -> dict[str, Any]:
    try:
        observed = manager.query(spec["producer_unit"])
    except (OSError, TimeoutError, UnicodeError, subprocess.TimeoutExpired) as error:
        return {
            "source": "user-systemd",
            "state": "NOT_OBSERVABLE",
            "reason": str(error)[:MAX_REASON_BYTES],
        }
    if observed.get("state") != "OBSERVED":
        return observed
    properties = observed.get("properties")
    try:
        validate_manager_properties(properties)
    except Refusal as error:
        return {"source": "user-systemd", "state": "NOT_OBSERVABLE", "reason": str(error)}
    pid = int(properties["MainPID"])
    active = pid > 0
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


def validate_acceptance(
    value: dict[str, Any], spec: dict[str, Any], intent_raw: bytes, expected_execution_sha256: str
) -> None:
    exact_keys(
        value,
        {
            "schema",
            "scenario",
            "intent_sha256",
            "run_id",
            "producer_unit",
            "invocation_id",
            "main_pid",
            "start_ticks",
            "execution_sha256",
        },
        "launch acceptance",
    )
    if value["schema"] != ACCEPTED_SCHEMA or value["scenario"] != SCENARIO:
        raise Refusal("launch acceptance names another protocol or scenario")
    if value["intent_sha256"] != digest_bytes(intent_raw):
        raise Refusal("launch acceptance does not bind the retained intent")
    if value["run_id"] != spec["run_id"] or value["producer_unit"] != spec["producer_unit"]:
        raise Refusal("launch acceptance names another occurrence")
    if not isinstance(value["invocation_id"], str) or not re.fullmatch(
        r"[0-9a-f]{32}", value["invocation_id"]
    ):
        raise Refusal("launch acceptance invocation identity is invalid")
    for field in ("main_pid", "start_ticks"):
        if not isinstance(value[field], int) or isinstance(value[field], bool) or value[field] <= 0:
            raise Refusal(f"launch acceptance {field} is invalid")
    hex_digest(value["execution_sha256"], "launch acceptance execution sha256")
    if value["execution_sha256"] != expected_execution_sha256:
        raise Refusal("launch acceptance execution differs from the fixed intent")


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
    # Capture the validator separately from the admitted producer. Its identity
    # is reported by status and bound in launch intent; it grants no mechanics.
    checker, _metadata = read_nofollow_path(RUNNER_PATH, "composition checker", CHECKER_BYTES)
    if digest_bytes(checker) != CHECKER_SHA256:
        raise Refusal("composition checker differs from the admitted validator")
    captured = {str(RUNNER_PATH): checker}
    for field in ("builder", "nq_harness"):
        record = spec[field]
        raw, _metadata = read_nofollow_path(pathlib.Path(record["path"]), field, record["bytes"])
        if digest_bytes(raw) != record["sha256"]:
            raise Refusal(f"{field} checker import identity differs")
        captured[record["path"]] = raw
    # The checker uses its own adjacent builder path; map only that exact path
    # to captured accepted builder bytes, never to a mutable local import.
    captured[str(RUNNER_PATH.with_name("build_bookworm_fixture.py"))] = captured[spec["builder"]["path"]]
    class CapturedLoader(importlib.abc.SourceLoader):
        def __init__(self, path): self.path = path
        def get_filename(self, fullname): return self.path
        def get_data(self, path):
            if path not in captured:
                raise Refusal("checker requested an unadmitted local module")
            return captured[path]
    def frozen_spec(name, location, *args, **kwargs):
        path = str(location)
        if path not in captured:
            raise Refusal("checker requested an unadmitted local module")
        return importlib.util.spec_from_loader(name, CapturedLoader(path))
    original = importlib.util.spec_from_file_location
    try:
        importlib.util.spec_from_file_location = frozen_spec
        module_spec = frozen_spec("fixed_demo_composition_runner", RUNNER_PATH)
        runner = importlib.util.module_from_spec(module_spec)
        sys.modules[module_spec.name] = runner
        module_spec.loader.exec_module(runner)
        nq = runner.load_module("fixed_demo_nq_harness", pathlib.Path(spec["nq_harness"]["path"]))
    finally:
        importlib.util.spec_from_file_location = original
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
            "validator": "Docket",
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
            "owner": "NQ-ng",
            "validator": "Docket",
            "disposition": "REFUSED",
            "reason": recovery["refusal"]["reason"],
            "effect_outcome": recovery["effect_outcome"],
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


def evidence_projection(spec: dict[str, Any], terminal: dict[str, Any] | None) -> list[dict[str, Any]]:
    entries = []
    for source, label, relative in (
        ("NQ-ng", "Service observation before execution", "evidence/systemd-pre-artifact.json"),
        ("NQ-ng", "HTTP observation before execution", "evidence/http-pre-artifact.json"),
        ("AG-ng", "Authorization decision and spend", "evidence/composition-occurrence/authorization-state.json"),
        ("Docket", "Attempt and settlement custody", "evidence/composition-occurrence/docket-inspection.json"),
        ("AG-ng", "Execution outcome", "evidence/composition-occurrence/executor-outcome.json"),
        ("NQ-ng", "Service observation after execution", "evidence/systemd-post-artifact.json"),
        ("NQ-ng", "HTTP observation after execution", "evidence/http-post-artifact.json"),
        ("NQ-ng", "Current support after restart", "evidence/current-support-after-restart.json"),
        ("AG-ng", "Owner store-cut replay", "evidence/composition-ag-store-audit-outcome.json"),
        ("NQ-ng / OS", "Teardown observation", "evidence/host-final-observation.json"),
    ):
        path = pathlib.Path(spec["run_root"]) / relative
        entry = {"source": source, "label": label, "evidence": str(path)}
        try:
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                raise Refusal("evidence path is not a regular file")
            raw, _metadata = read_nofollow_path(path, label)
            entry.update(bytes=len(raw), sha256=digest_bytes(raw),
                         state="OWNER_VALIDATED" if terminal and terminal.get("state") == "TERMINAL"
                         else "RECORDED_UNVERIFIED")
        except FileNotFoundError:
            entry["state"] = "MISSING"
        except (OSError, Refusal) as error:
            entry.update(state="NOT_OBSERVABLE", detail=str(error))
        entries.append(entry)
    return entries


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
        try:
            if intent_item is None:
                raise Refusal("launch acceptance has no retained intent")
            validate_intent(intent_item[0], expected_intent)
            validate_acceptance(
                accepted, spec, intent_item[1], expected_intent["execution_sha256"]
            )
        except Refusal as error:
            disagreements.append(str(error))
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
    manager_testimony = occurrence
    os_testimony = {"source": "OS process table", "state": "NOT_OBSERVABLE",
                    "reason": "no valid retained process identity"}
    if accepted_for_binding is not None:
        os_testimony = os_occurrence_from_acceptance(
            accepted_for_binding, spec, spec_sha256, occurrence
        )
        if os_testimony.get("state") == "PROCESS_ACTIVE" and os_testimony.get("execution_matches") is not True:
            disagreements.append("OS process occurrence differs from launch acceptance")
        if (manager_testimony.get("state") in {"PROCESS_ACTIVE", "PROCESS_EXITED"}
                and os_testimony.get("state") in {"PROCESS_ACTIVE", "PROCESS_EXITED"}
                and manager_testimony["state"] != os_testimony["state"]):
            disagreements.append("manager and OS process testimony disagree")
        if occurrence.get("state") == "NOT_OBSERVABLE":
            occurrence = os_testimony
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
    if intent_item is not None and accepted_for_binding is None:
        disagreements.append("launch intent has no valid retained Docket acceptance")
        if occurrence.get("execution_matches") is False:
            disagreements.append("active manager process differs from the fixed execution")
    if intent_item is None and (recovery is not None or terminal is not None):
        disagreements.append("runner evidence exists without Docket launch intent")
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
        "controller_custody": {
            "source": "Docket fixed controller",
            "state": ("ACCEPTANCE_VALIDATED" if accepted_for_binding is not None
                      else "INDETERMINATE" if intent_item is not None or disagreements
                      else "NO_INTENT_RECORDED"),
        },
        "runner_durable": {
            "source": "composition owner records",
            "state": (terminal["state"] if terminal is not None
                      else recovery.get("phase", recovery["state"]) if recovery is not None
                      else "NOT_OBSERVABLE"),
            "recovery": recovery,
            "terminal": terminal,
        },
        "live_sources": {"manager": manager_testimony, "os": os_testimony},
        "evidence": evidence_projection(spec, terminal),
        "liveness": occurrence,
        "execution": {
            "identity": "BOUNDED_COMPOSITION_RUNNER",
            "model_provider": "NOT_APPLICABLE",
            "producer_subject": spec["composition_subject"],
            "producer_sha256": spec["runner"]["sha256"],
            "checker_sha256": CHECKER_SHA256,
            "controller_sha256": executed_source_sha256(),
            "code_capsule_sha256": argv[6],
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
        verify_owner_repository(spec["runner"])
        verify_owner_repository(spec["nq_harness"])
        return status_projection(spec, raw, self.expected_sha256, self.manager)

    def start(self) -> dict[str, Any]:
        spec, spec_raw = load_spec(self.spec_path, self.expected_bytes, self.expected_sha256)
        verify_bound_file(spec["runner"], "composition runner")
        verify_bound_file(spec["nq_harness"], "NQ harness")
        verify_owner_repository(spec["runner"])
        verify_owner_repository(spec["nq_harness"])
        for name in INPUT_FIELDS:
            verify_bound_file(spec["inputs"][name], f"{name} input")
        argv = runner_argv(spec)
        intent = intent_record(spec, spec_raw, self.expected_sha256)
        intent_raw = canonical(intent) + b"\n"
        directory = open_state_root(spec)
        lock_descriptor = -1
        try:
            flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            lock_descriptor = os.open("launch.lock", flags, 0o600, dir_fd=directory)
            lock_metadata = os.fstat(lock_descriptor)
            if (
                not stat.S_ISREG(lock_metadata.st_mode)
                or stat.S_IMODE(lock_metadata.st_mode) != 0o600
                or lock_metadata.st_uid != spec["state_root_uid"]
                or lock_metadata.st_gid != spec["state_root_gid"]
                or lock_metadata.st_dev != spec["launch_lock_device"]
                or lock_metadata.st_ino != spec["launch_lock_inode"]
            ):
                raise Refusal("launch lock identity or mode differs")
            def verify_lock_path() -> None:
                current = os.stat("launch.lock", dir_fd=directory, follow_symlinks=False)
                if stat_identity(current) != stat_identity(lock_metadata):
                    raise Refusal("launch lock pathname identity differs")
                root_check = open_state_root(spec)
                os.close(root_check)

            deadline = time.monotonic() + LOCK_WAIT_SECONDS
            while True:
                verify_lock_path()
                try:
                    fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise Refusal("launch lock acquisition timed out")
                    time.sleep(0.01)
            verify_lock_path()
            existing = optional_child_record(directory, "launch-intent.v1.json", "launch intent")
            if existing is not None:
                validate_intent(existing[0], intent)
                return status_projection(spec, spec_raw, self.expected_sha256, self.manager)
            create_exclusive_at(directory, "launch-intent.v1.json", intent_raw)
            self.cut_hook("intent_durable")
            verify_lock_path()
            reopened_spec, reopened_raw = load_spec(self.spec_path, self.expected_bytes, self.expected_sha256)
            if reopened_spec != spec or reopened_raw != spec_raw:
                raise Refusal("installed spec changed before manager invocation")
            self.manager.start(spec, argv, self.expected_sha256)
            self.cut_hook("manager_returned")
            occurrence = await_manager_occurrence(
                self.manager, spec, argv, self.expected_sha256
            )
            accepted = accepted_record(spec, intent_raw, occurrence)
            verify_lock_path()
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
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        raw, metadata = read_nofollow_path(ADMITTED_SPEC_PATH, "installed Docket spec")
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o400:
            raise Refusal("installed Docket spec owner or mode differs")
        if (type(ADMITTED_SPEC_BYTES) is not int or ADMITTED_SPEC_BYTES <= 0
                or not isinstance(ADMITTED_SPEC_SHA256, str)
                or not re.fullmatch(r"[0-9a-f]{64}", ADMITTED_SPEC_SHA256)):
            raise Refusal("fixed physical state enrollment is not admitted")
        if len(raw) != ADMITTED_SPEC_BYTES or digest_bytes(raw) != ADMITTED_SPEC_SHA256:
            raise Refusal("installed Docket spec differs from independently admitted bytes")
        controller = FixedController(ADMITTED_SPEC_PATH, ADMITTED_SPEC_BYTES, ADMITTED_SPEC_SHA256)
        projection = controller.start() if args.command == "start" else controller.status()
    except Exception as error:
        print(f"fixed demo controller refused: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(canonical(projection) + b"\n")
    return 0


if __name__ == "__main__":
    if "__executed_source_sha256__" not in globals():
        # Direct CLI bootstraps the effective controller from captured bytes.
        # AG supplies the same marker after hashing its admitted retained bytes.
        # __file__ remains only a location hint, never executing-byte evidence.
        source, _metadata = read_nofollow_path(pathlib.Path(__file__), "controller source")
        namespace = {"__name__": "__main__", "__file__": __file__,
                     "__executed_source_sha256__": digest_bytes(source)}
        exec(compile(source, __file__, "exec"), namespace)
        raise SystemExit(0)
    raise SystemExit(main())
