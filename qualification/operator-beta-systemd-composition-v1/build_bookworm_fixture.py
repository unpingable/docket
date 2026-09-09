#!/usr/bin/env python3
"""Build and verify the qualification-only Docket composition fixture package."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
from typing import Any

SCHEMA = "constellation.operator_beta.docket_systemd_fixture_build.v1"
AG_HEAD = "bf6adde2792a886d1ba75d97ca77efb8e914f4f5"
AG_TREE = "31b3b15437baffcaa41ae31020f4570599304019"
DOCKET_HEAD = "6c57926d2560c47c681691e006fbbfe244c6993e"
DOCKET_TREE = "fb0b72b74226bfe3e4d39ccf0eca79241bd80fe2"
IMAGE_ID = "sha256:fb7a58d0482a24e269ba85636ce46cb06aaaef3aea0e868154ed0ae7c18fa379"
IMAGE_REPO_DIGEST = "rust@sha256:365468470075493dc4583f47387001854321c5a8583ea9604b297e67f01c5a4f"
SOURCE_DATE_EPOCH = "1700000000"
BUILD_USER = "1000:1000"
PACKAGE_NAME = "constellation-operator-beta-composition-fixture"
PACKAGE_VERSION = "0.1.0-1"
PACKAGE_FILE = f"{PACKAGE_NAME}_{PACKAGE_VERSION}_amd64.deb"
DRIVER_RELATIVE = pathlib.Path(
    "qualification/operator-beta-systemd-composition-v1/composition_driver.rs"
)
BUILDER_RELATIVE = pathlib.Path(
    "qualification/operator-beta-systemd-composition-v1/build_bookworm_fixture.py"
)
BINARIES = {
    "docket": "usr/libexec/constellation-operator-beta/docket",
    "composition-driver": "usr/libexec/constellation-operator-beta/composition-driver",
}
LIMITATIONS = [
    "qualification-only",
    "installs no service or configuration",
    "does not itself grant AG or Docket authority",
    "live VM and systemd effect remain separate qualification gates",
]
RECEIPT_FIELDS = {
    "schema",
    "sources",
    "vendor",
    "builder",
    "build",
    "package",
    "binaries",
    "logs",
    "qualification",
    "limitations",
}
BUILD_ENV = {
    "CARGO_INCREMENTAL": "0",
    "HOME": "/tmp/constellation-composition-builder",
    "LC_ALL": "C.UTF-8",
    "RUSTFLAGS": (
        "--remap-path-prefix=/ag=. --remap-path-prefix=/ag-vendor=/cargo-vendor-ag "
        "--remap-path-prefix=/docket=. --remap-path-prefix=/docket-vendor=/cargo-vendor-docket"
    ),
    "RUSTUP_TOOLCHAIN": "1.94.0",
    "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH,
    "TZ": "UTC",
    "USER": "composition-builder",
}


class Refusal(RuntimeError):
    """Bounded qualification refusal."""


def run(
    command: list[str],
    *,
    cwd: pathlib.Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise Refusal(
            f"command refused ({completed.returncode}): {command!r}\n"
            + completed.stderr.decode(errors="replace")[-4000:]
        )
    return completed


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def regular_file(path: pathlib.Path, label: str) -> os.stat_result:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise Refusal(f"{label} is not one regular non-symlink file")
    return metadata


def source_facts(source: pathlib.Path, head: str, tree: str, label: str) -> dict[str, Any]:
    if not source.is_dir() or source.is_symlink():
        raise Refusal(f"{label} source is not one physical directory")
    observed_head = run(["git", "rev-parse", "HEAD"], cwd=source).stdout.decode().strip()
    observed_tree = run(["git", "rev-parse", "HEAD^{tree}"], cwd=source).stdout.decode().strip()
    if observed_head != head or observed_tree != tree:
        raise Refusal(f"{label} source differs from the admitted head/tree")
    if run(["git", "status", "--porcelain"], cwd=source).stdout:
        raise Refusal(f"{label} source worktree is not clean")
    return {
        "head": head,
        "tree": tree,
        "cargo_lock_sha256": sha256(source / "Cargo.lock"),
        "cargo_toml_sha256": sha256(source / "Cargo.toml"),
    }


def tree_digest(root: pathlib.Path, domain: bytes) -> tuple[str, int]:
    if not root.is_dir() or root.is_symlink():
        raise Refusal("vendor input is not one physical directory")
    digest = hashlib.sha256(domain + b"\0")
    count = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            raise Refusal(f"vendor input contains a non-regular entry: {path}")
        relative = path.relative_to(root).as_posix().encode()
        body = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update((metadata.st_mode & 0o777).to_bytes(4, "big"))
        digest.update(len(body).to_bytes(8, "big"))
        digest.update(body)
        count += 1
    if count == 0:
        raise Refusal("vendor input is empty")
    return digest.hexdigest(), count


def image_facts() -> dict[str, str]:
    records = json.loads(run(["/usr/bin/docker", "image", "inspect", IMAGE_ID]).stdout)
    if len(records) != 1 or records[0].get("Id") != IMAGE_ID:
        raise Refusal("local builder image identity differs")
    if IMAGE_REPO_DIGEST not in records[0].get("RepoDigests", []):
        raise Refusal("local builder repository digest is absent")
    return {
        "image_id": IMAGE_ID,
        "repository_digest": IMAGE_REPO_DIGEST,
        "network": "none",
        "pull": "never",
    }


def cargo_config(vendor: str) -> str:
    return f'''[net]
offline = true

[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "{vendor}"
'''


def docker_prefix() -> list[str]:
    command = [
        "/usr/bin/docker",
        "run",
        "--rm",
        "--pull",
        "never",
        "--network",
        "none",
        "--hostname",
        "docket-composition-builder",
        "--user",
        BUILD_USER,
    ]
    for key, value in sorted(BUILD_ENV.items()):
        command.extend(["-e", f"{key}={value}"])
    return command


def normalized_commands() -> dict[str, list[str]]:
    return {
        "ag": build_command(
            pathlib.Path("<AG_SOURCE>"),
            pathlib.Path("<AG_VENDOR>"),
            pathlib.Path("<CARGO_HOME>"),
            pathlib.Path("<TARGET>"),
            "ag",
        ),
        "docket": build_command(
            pathlib.Path("<DOCKET_SOURCE>"),
            pathlib.Path("<DOCKET_VENDOR>"),
            pathlib.Path("<CARGO_HOME>"),
            pathlib.Path("<TARGET>"),
            "docket",
        ),
    }


def extract_source(source: pathlib.Path, destination: pathlib.Path) -> None:
    archive = run(["git", "archive", "--format=tar", "HEAD"], cwd=source).stdout
    destination.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        for member in tar.getmembers():
            candidate = (destination / member.name).resolve()
            if destination.resolve() not in (candidate, *candidate.parents):
                raise Refusal("source archive contains an unsafe path")
        tar.extractall(destination, filter="data")


def build_command(
    source: pathlib.Path,
    vendor: pathlib.Path,
    cargo_home: pathlib.Path,
    target: pathlib.Path,
    kind: str,
) -> list[str]:
    command = docker_prefix()
    command.extend(
        [
            "-e",
            "CARGO_HOME=/cargo-home",
            "-e",
            "CARGO_TARGET_DIR=/target",
            "-v",
            f"{source}:/{kind}:ro",
            "-v",
            f"{vendor}:/{kind}-vendor:ro",
            "-v",
            f"{cargo_home}:/cargo-home:rw",
            "-v",
            f"{target}:/target:rw",
            "-w",
            f"/{kind}",
            IMAGE_ID,
            "cargo",
            "build",
            "--locked",
            "--offline",
            "--release",
        ]
    )
    if kind == "ag":
        command.extend(
            [
                "-p",
                "ag-app",
                "--example",
                "operator_beta_systemd_composition",
                "--features",
                "systemd-dbus",
            ]
        )
    else:
        command.extend(["-p", "gwr-local", "--bin", "docket"])
    return command


def set_epoch(root: pathlib.Path) -> None:
    epoch = int(SOURCE_DATE_EPOCH)
    for path in sorted(root.rglob("*"), reverse=True):
        os.utime(path, (epoch, epoch), follow_symlinks=False)
    os.utime(root, (epoch, epoch), follow_symlinks=False)


def assemble(case: pathlib.Path) -> pathlib.Path:
    debroot = case / "debroot"
    destination = debroot / "usr/libexec/constellation-operator-beta"
    destination.mkdir(parents=True)
    for directory in (
        debroot,
        debroot / "usr",
        debroot / "usr/libexec",
        destination,
        debroot / "DEBIAN",
    ):
        if directory.exists():
            os.chmod(directory, 0o755)
    binaries = {
        "docket": case / "docket-target/release/docket",
        "composition-driver": case
        / "ag-target/release/examples/operator_beta_systemd_composition",
    }
    for name, source in binaries.items():
        regular_file(source, name)
        shutil.copyfile(source, destination / name)
        os.chmod(destination / name, 0o755)
    control = debroot / "DEBIAN/control"
    control.parent.mkdir()
    control.write_text(
        "\n".join(
            [
                f"Package: {PACKAGE_NAME}",
                f"Version: {PACKAGE_VERSION}",
                "Architecture: amd64",
                "Maintainer: Constellation qualification <noreply@example.invalid>",
                "Depends: python3",
                "Description: bounded operator-beta AG and Docket composition fixture",
                " This package is qualification-only and installs no service or configuration.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    os.chmod(control, 0o644)
    set_epoch(debroot)
    package = case / PACKAGE_FILE
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "TZ": "UTC", "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH}
    run(["dpkg-deb", "--root-owner-group", "--build", str(debroot), str(package)], env=env)
    return package


def package_data_inventory(package: pathlib.Path) -> list[dict[str, Any]]:
    archive = run(["dpkg-deb", "--fsys-tarfile", str(package)]).stdout
    expected: dict[str, tuple[str, int]] = {
        ".": ("directory", 0o755),
        "usr": ("directory", 0o755),
        "usr/libexec": ("directory", 0o755),
        "usr/libexec/constellation-operator-beta": ("directory", 0o755),
    }
    expected.update({relative: ("regular", 0o755) for relative in BINARIES.values()})
    observed: dict[str, tuple[str, int]] = {}
    inventory: list[dict[str, Any]] = []
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as data:
        for member in data.getmembers():
            name = member.name.removeprefix("./").rstrip("/") or "."
            if member.isdir():
                kind = "directory"
            elif member.isfile():
                kind = "regular"
            else:
                raise Refusal(f"fixture package has a non-regular data member: {name}")
            mode = member.mode & 0o777
            if member.uid != 0 or member.gid != 0:
                raise Refusal(f"fixture package member is not root-owned: {name}")
            if name in observed:
                raise Refusal(f"fixture package has a duplicate data member: {name}")
            observed[name] = (kind, mode)
            inventory.append(
                {
                    "path": "/" if name == "." else "/" + name,
                    "kind": kind,
                    "mode": format(mode, "04o"),
                }
            )
    if observed != expected:
        raise Refusal("fixture package data inventory is not the closed two-binary layout")
    return sorted(inventory, key=lambda item: item["path"])


def package_control(package: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    root = scratch / "control"
    root.mkdir(parents=True)
    run(["dpkg-deb", "-e", str(package), str(root)])
    entries = sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file())
    if entries != ["control"]:
        raise Refusal("fixture package contains maintainer scripts or extra control files")
    control = root / "control"
    regular_file(control, "fixture control metadata")
    fields: dict[str, str] = {}
    current: str | None = None
    for line in control.read_text(encoding="utf-8").splitlines():
        if line.startswith(" ") and current is not None:
            fields[current] += "\n" + line
        elif ": " in line:
            current, value = line.split(": ", 1)
            fields[current] = value
        elif line:
            raise Refusal("fixture package control metadata is malformed")
    expected = {
        "Package": PACKAGE_NAME,
        "Version": PACKAGE_VERSION,
        "Architecture": "amd64",
        "Maintainer": "Constellation qualification <noreply@example.invalid>",
        "Depends": "python3",
        "Description": (
            "bounded operator-beta AG and Docket composition fixture\n"
            " This package is qualification-only and installs no service or configuration."
        ),
    }
    if fields != expected:
        raise Refusal("fixture package control metadata differs from the closed contract")
    return {"files": entries, "fields": fields}


def binary_facts(package: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    root = scratch / "inspect"
    root.mkdir(parents=True)
    run(["dpkg-deb", "-x", str(package), str(root)])
    result: dict[str, Any] = {}
    for name, relative in BINARIES.items():
        path = root / relative
        metadata = regular_file(path, name)
        versions = run(["readelf", "--version-info", str(path)]).stdout.decode()
        parsed = [(int(a), int(b)) for a, b in re.findall(r"Name: GLIBC_(\d+)\.(\d+)", versions)]
        newest = max(parsed) if parsed else None
        if newest is not None and newest > (2, 36):
            raise Refusal(f"{name} requires glibc {newest}, beyond Debian 12")
        result[name] = {
            "path": "/" + relative,
            "bytes": metadata.st_size,
            "sha256": sha256(path),
            "mode": format(stat.S_IMODE(metadata.st_mode), "04o"),
            "maximum_glibc": None if newest is None else f"GLIBC_{newest[0]}.{newest[1]}",
        }
    return result


def package_facts(package: pathlib.Path, scratch: pathlib.Path) -> dict[str, Any]:
    return {
        "file": PACKAGE_FILE,
        "bytes": package.stat().st_size,
        "sha256": sha256(package),
        "data_inventory": package_data_inventory(package),
        "control": package_control(package, scratch),
    }


def build_case(
    label: str,
    scratch: pathlib.Path,
    ag_source: pathlib.Path,
    docket_source: pathlib.Path,
    ag_vendor: pathlib.Path,
    docket_vendor: pathlib.Path,
    driver: pathlib.Path,
) -> dict[str, Any]:
    case = scratch / label
    case.mkdir()
    ag = case / "ag"
    docket = case / "docket"
    extract_source(ag_source, ag)
    extract_source(docket_source, docket)
    example = ag / "crates/ag-app/examples/operator_beta_systemd_composition.rs"
    shutil.copyfile(driver, example)
    manifest = ag / "crates/ag-app/Cargo.toml"
    manifest_text = manifest.read_text()
    if manifest_text.count("[features]\n") != 1:
        raise Refusal("AG fixture feature seam differs")
    # Declares the companion-only compile guard; the ordinary composition
    # example remains built without this feature and keeps its fixed contract.
    manifest.write_text(manifest_text.replace("[features]\n", "[features]\nm3-labelwatch = []\n"))
    for source, vendor_path in ((ag, "/ag-vendor"), (docket, "/docket-vendor")):
        config = source / ".cargo/config.toml"
        config.parent.mkdir(exist_ok=True)
        config.write_text(cargo_config(vendor_path), encoding="utf-8")
    for name in ("ag-cargo", "docket-cargo", "ag-target", "docket-target"):
        (case / name).mkdir()
    ag_build = run(build_command(ag, ag_vendor, case / "ag-cargo", case / "ag-target", "ag"))
    docket_build = run(
        build_command(docket, docket_vendor, case / "docket-cargo", case / "docket-target", "docket")
    )
    (case / "ag-build.log").write_bytes(ag_build.stdout + ag_build.stderr)
    (case / "docket-build.log").write_bytes(docket_build.stdout + docket_build.stderr)
    package = assemble(case)
    return {
        "package": package_facts(package, case / "package-inspect"),
        "binaries": binary_facts(package, case),
        "logs": {
            name: {
                "bytes": (case / name).stat().st_size,
                "sha256": sha256(case / name),
            }
            for name in ("ag-build.log", "docket-build.log")
        },
    }


def qualification_facts(repository: pathlib.Path) -> dict[str, Any]:
    builder = repository / BUILDER_RELATIVE
    driver = repository / DRIVER_RELATIVE
    return {
        "builder": {"path": BUILDER_RELATIVE.as_posix(), "sha256": sha256(builder)},
        "driver": {"path": DRIVER_RELATIVE.as_posix(), "sha256": sha256(driver)},
    }


def validate_receipt_structure(receipt: Any, raw: bytes) -> None:
    if (
        not isinstance(receipt, dict)
        or raw != canonical(receipt) + b"\n"
        or set(receipt) != RECEIPT_FIELDS
        or receipt.get("schema") != SCHEMA
        or receipt.get("limitations") != LIMITATIONS
    ):
        raise Refusal("fixture receipt is not exact canonical V1")


def build(args: argparse.Namespace) -> None:
    if args.output.exists():
        raise Refusal("output path already exists")
    if f"{os.getuid()}:{os.getgid()}" != BUILD_USER:
        raise Refusal(f"builder requires host uid:gid {BUILD_USER}")
    repository = pathlib.Path(__file__).resolve().parents[2]
    sources = {
        "ag": source_facts(args.ag_source, AG_HEAD, AG_TREE, "AG"),
        "docket": source_facts(args.docket_source, DOCKET_HEAD, DOCKET_TREE, "Docket"),
    }
    ag_vendor_sha, ag_vendor_files = tree_digest(args.ag_vendor, b"ag-composition-vendor-v1")
    docket_vendor_sha, docket_vendor_files = tree_digest(
        args.docket_vendor, b"docket-composition-vendor-v1"
    )
    builder = image_facts()
    scratch = pathlib.Path(tempfile.mkdtemp(prefix=".docket-composition-build.", dir=args.output.parent))
    try:
        cases = [
            build_case(
                label,
                scratch,
                args.ag_source,
                args.docket_source,
                args.ag_vendor,
                args.docket_vendor,
                repository / DRIVER_RELATIVE,
            )
            for label in ("a", "b")
        ]
        if cases[0]["package"] != cases[1]["package"] or cases[0]["binaries"] != cases[1]["binaries"]:
            raise Refusal("independent fixture builds differ")
        args.output.mkdir(mode=0o700)
        shutil.copyfile(scratch / "a" / PACKAGE_FILE, args.output / PACKAGE_FILE)
        for label in ("a", "b"):
            for name in ("ag-build.log", "docket-build.log"):
                shutil.copyfile(scratch / label / name, args.output / f"{label}-{name}")
        receipt = {
            "schema": SCHEMA,
            "sources": sources,
            "vendor": {
                "ag": {"tree_sha256": ag_vendor_sha, "regular_files": ag_vendor_files},
                "docket": {
                    "tree_sha256": docket_vendor_sha,
                    "regular_files": docket_vendor_files,
                },
            },
            "builder": builder,
            "build": {
                "environment": BUILD_ENV,
                "commands": normalized_commands(),
                "source_date_epoch": SOURCE_DATE_EPOCH,
                "clean_builds": 2,
            },
            "package": cases[0]["package"] | {"file": PACKAGE_FILE},
            "binaries": cases[0]["binaries"],
            "logs": {
                f"{label}-{name}": {
                    "bytes": (args.output / f"{label}-{name}").stat().st_size,
                    "sha256": sha256(args.output / f"{label}-{name}"),
                }
                for label in ("a", "b")
                for name in ("ag-build.log", "docket-build.log")
            },
            "qualification": qualification_facts(repository),
            "limitations": LIMITATIONS,
        }
        (args.output / "fixture-build-receipt.v1.json").write_bytes(canonical(receipt) + b"\n")
        print(json.dumps({"result": "REPRODUCIBLE_COMPOSITION_FIXTURE", "package_sha256": receipt["package"]["sha256"]}, sort_keys=True))
    except Exception:
        if args.output.exists():
            shutil.rmtree(args.output)
        raise
    finally:
        shutil.rmtree(scratch)


def verify(args: argparse.Namespace) -> None:
    repository = pathlib.Path(__file__).resolve().parents[2]
    output = args.output.resolve(strict=True)
    receipt_path = output / "fixture-build-receipt.v1.json"
    regular_file(receipt_path, "fixture receipt")
    raw = receipt_path.read_bytes()
    receipt = json.loads(raw)
    validate_receipt_structure(receipt, raw)
    expected_sources = {
        "ag": source_facts(args.ag_source, AG_HEAD, AG_TREE, "AG"),
        "docket": source_facts(args.docket_source, DOCKET_HEAD, DOCKET_TREE, "Docket"),
    }
    ag_vendor_sha, ag_vendor_files = tree_digest(args.ag_vendor, b"ag-composition-vendor-v1")
    docket_vendor_sha, docket_vendor_files = tree_digest(
        args.docket_vendor, b"docket-composition-vendor-v1"
    )
    package = output / PACKAGE_FILE
    regular_file(package, "fixture package")
    with tempfile.TemporaryDirectory(prefix="docket-composition-verify.") as temporary:
        verify_root = pathlib.Path(temporary)
        binaries = binary_facts(package, verify_root / "binaries")
        package_record = package_facts(package, verify_root / "package")
    checks = {
        "sources": expected_sources,
        "vendor": {
            "ag": {"tree_sha256": ag_vendor_sha, "regular_files": ag_vendor_files},
            "docket": {"tree_sha256": docket_vendor_sha, "regular_files": docket_vendor_files},
        },
        "builder": image_facts(),
        "build": {
            "environment": BUILD_ENV,
            "commands": normalized_commands(),
            "source_date_epoch": SOURCE_DATE_EPOCH,
            "clean_builds": 2,
        },
        "package": package_record,
        "binaries": binaries,
        "qualification": qualification_facts(repository),
    }
    for key, value in checks.items():
        if receipt.get(key) != value:
            raise Refusal(f"fixture receipt {key} differs from authoritative input")
    expected_logs = {
        f"{label}-{name}": {
            "bytes": (output / f"{label}-{name}").stat().st_size,
            "sha256": sha256(output / f"{label}-{name}"),
        }
        for label in ("a", "b")
        for name in ("ag-build.log", "docket-build.log")
    }
    if receipt.get("logs") != expected_logs:
        raise Refusal("fixture receipt logs differ")
    expected_output = {
        PACKAGE_FILE,
        "fixture-build-receipt.v1.json",
        *expected_logs,
    }
    actual_output = {
        path.relative_to(output).as_posix()
        for path in output.rglob("*")
        if path.is_file()
    }
    if actual_output != expected_output:
        raise Refusal("fixture output directory is not one closed artifact inventory")
    print(json.dumps({"result": "COMPOSITION_FIXTURE_RECEIPT_VERIFIED", "package_sha256": sha256(package)}, sort_keys=True))


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    for name in ("build", "verify"):
        command = commands.add_parser(name)
        command.add_argument("--ag-source", type=pathlib.Path, required=True)
        command.add_argument("--docket-source", type=pathlib.Path, required=True)
        command.add_argument("--ag-vendor", type=pathlib.Path, required=True)
        command.add_argument("--docket-vendor", type=pathlib.Path, required=True)
        command.add_argument("--output", type=pathlib.Path, required=True)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "build":
            build(args)
        else:
            verify(args)
        return 0
    except (OSError, ValueError, Refusal, tarfile.TarError) as error:
        print(f"REFUSED: {error}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
