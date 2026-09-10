#!/usr/bin/env python3
"""Prepare one exact Linux-target vendor closure from local Cargo archives."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import stat
import subprocess
import tarfile
import tempfile
import tomllib
from typing import Any

AG_HEAD = "ae993551349eb23e3b833caecffb4e352bcd983b"
AG_TREE = "8628d327e14436a20592c813dd9b7a678f8e78c8"
LOCK_SHA256 = "68205a7d2319b648ed5ebcbc42c015222dba2257286012af44b4d9d9e073bcad"
TARGET = "x86_64-unknown-linux-gnu"
FEATURES = "ag-app/systemd-dbus"
SCHEMA = "constellation.operator_beta.target_vendor_closure.v1"
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_MEMBERS = 200_000
CACHE_ROOTS = (
    pathlib.Path("/home/jbeck/.cargo/registry/cache/index.crates.io-1949cf8c6b5b557f"),
    pathlib.Path("/home/jbeck/.cargo/registry/cache/index.crates.io-6f17d22bba15001f"),
)


class Refusal(RuntimeError):
    """Bounded qualification refusal."""


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def run(command: list[str], cwd: pathlib.Path) -> bytes:
    completed = subprocess.run(
        command,
        cwd=cwd,
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
    return completed.stdout


def exact_source(source: pathlib.Path) -> pathlib.Path:
    source = source.resolve(strict=True)
    if not source.is_dir() or source.is_symlink():
        raise Refusal("AG source is not one physical directory")
    head = run(["git", "rev-parse", "HEAD"], source).decode().strip()
    tree = run(["git", "rev-parse", "HEAD^{tree}"], source).decode().strip()
    dirty = run(["git", "status", "--porcelain"], source)
    if head != AG_HEAD or tree != AG_TREE or dirty:
        raise Refusal("AG source differs from the admitted clean head/tree")
    if sha256(source / "Cargo.lock") != LOCK_SHA256:
        raise Refusal("AG Cargo.lock differs from the admitted digest")
    return source


def lock_packages(lock: pathlib.Path) -> dict[tuple[str, str, str], str]:
    parsed = tomllib.loads(lock.read_text(encoding="utf-8"))
    result: dict[tuple[str, str, str], str] = {}
    for package in parsed.get("package", []):
        source = package.get("source")
        checksum = package.get("checksum")
        if isinstance(source, str) and source.startswith("registry+"):
            if not isinstance(checksum, str) or len(checksum) != 64:
                raise Refusal("registry lock entry lacks an exact checksum")
            key = (package["name"], package["version"], source)
            if key in result:
                raise Refusal("duplicate registry identity in Cargo.lock")
            result[key] = checksum
    return result


def resolved_registry(source: pathlib.Path) -> set[tuple[str, str, str]]:
    raw = run(
        [
            "cargo",
            "metadata",
            "--locked",
            "--offline",
            "--filter-platform",
            TARGET,
            "--features",
            FEATURES,
            "--format-version",
            "1",
        ],
        source,
    )
    metadata = json.loads(raw)
    resolved = {node["id"] for node in metadata["resolve"]["nodes"]}
    return {
        (package["name"], package["version"], package["source"])
        for package in metadata["packages"]
        if package["id"] in resolved
        and isinstance(package.get("source"), str)
        and package["source"].startswith("registry+")
    }


def exact_archive(name: str, version: str, expected: str) -> pathlib.Path:
    filename = f"{name}-{version}.crate"
    candidates = [root / filename for root in CACHE_ROOTS if (root / filename).is_file()]
    matching = [path for path in candidates if sha256(path) == expected]
    if not matching:
        raise Refusal(f"no exact local crate archive for {name} {version}")
    return matching[0]


def extract_archive(
    archive: pathlib.Path,
    destination: pathlib.Path,
    expected_root: str,
) -> tuple[dict[str, str], int, int]:
    metadata = archive.lstat()
    if not stat.S_ISREG(metadata.st_mode) or archive.is_symlink():
        raise Refusal("crate archive is not one regular non-symlink file")
    if metadata.st_size <= 0 or metadata.st_size > MAX_ARCHIVE_BYTES:
        raise Refusal("crate archive exceeds its per-file bound")
    files: dict[str, str] = {}
    total = 0
    members = 0
    with tarfile.open(archive, "r:gz") as source:
        for member in source:
            members += 1
            if members > MAX_MEMBERS:
                raise Refusal("vendor member count exceeds its bound")
            pure = pathlib.PurePosixPath(member.name)
            if pure.is_absolute() or ".." in pure.parts or not pure.parts:
                raise Refusal("crate archive contains an unsafe path")
            if pure.parts[0] != expected_root or len(pure.parts) == 1:
                if member.isdir() and pure.parts == (expected_root,):
                    continue
                raise Refusal("crate archive root differs from lock identity")
            relative = pathlib.PurePosixPath(*pure.parts[1:])
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise Refusal("crate archive contains a non-regular member")
            if member.mode & 0o7000:
                raise Refusal("crate archive member has special mode bits")
            body = source.extractfile(member)
            if body is None:
                raise Refusal("crate archive regular member cannot be read")
            content = body.read(MAX_ARCHIVE_BYTES + 1)
            if len(content) != member.size or len(content) > MAX_ARCHIVE_BYTES:
                raise Refusal("crate archive member exceeds its bound")
            total += len(content)
            if total > MAX_TOTAL_BYTES:
                raise Refusal("vendor content exceeds its aggregate bound")
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as output:
                output.write(content)
            os.chmod(target, member.mode & 0o777)
            files[relative.as_posix()] = hashlib.sha256(content).hexdigest()
    if "Cargo.toml" not in files:
        raise Refusal("crate archive lacks Cargo.toml")
    return files, total, members


def tree_digest(root: pathlib.Path) -> tuple[str, int]:
    digest = hashlib.sha256(b"ag-composition-vendor-v1\0")
    count = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            raise Refusal(f"vendor contains a non-regular entry: {path}")
        relative = path.relative_to(root).as_posix().encode()
        body = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update((metadata.st_mode & 0o777).to_bytes(4, "big"))
        digest.update(len(body).to_bytes(8, "big"))
        digest.update(body)
        count += 1
    return digest.hexdigest(), count


def prepare(args: argparse.Namespace) -> None:
    source = exact_source(args.source)
    if args.output.exists():
        raise Refusal("vendor output already exists")
    if args.receipt.exists():
        raise Refusal("vendor receipt already exists")
    locked = lock_packages(source / "Cargo.lock")
    resolved = resolved_registry(source)
    if not resolved or not resolved.issubset(locked):
        raise Refusal("filtered Cargo resolution is not a subset of the admitted lock")
    scratch = pathlib.Path(tempfile.mkdtemp(prefix=".final-pin-ag-vendor.", dir=args.output.parent))
    completed = False
    packages: list[dict[str, Any]] = []
    aggregate = 0
    aggregate_members = 0
    try:
        for name, version, package_source in sorted(resolved):
            checksum = locked[(name, version, package_source)]
            archive = exact_archive(name, version, checksum)
            destination = scratch / f"{name}-{version}"
            destination.mkdir()
            files, size, members = extract_archive(
                archive, destination, f"{name}-{version}"
            )
            aggregate += size
            aggregate_members += members
            if aggregate > MAX_TOTAL_BYTES:
                raise Refusal("vendor content exceeds its aggregate bound")
            if aggregate_members > MAX_MEMBERS:
                raise Refusal("vendor member count exceeds its aggregate bound")
            checksum_record = {"files": files, "package": checksum}
            (destination / ".cargo-checksum.json").write_bytes(
                canonical(checksum_record) + b"\n"
            )
            packages.append(
                {
                    "name": name,
                    "version": version,
                    "checksum": checksum,
                    "archive": str(archive),
                    "archive_bytes": archive.stat().st_size,
                    "content_bytes": size,
                    "members": members,
                }
            )
        scratch.rename(args.output)
        completed = True
        digest, files = tree_digest(args.output)
        excluded = []
        for (name, version, package_source), checksum in sorted(locked.items()):
            if (name, version, package_source) not in resolved:
                candidates = [root / f"{name}-{version}.crate" for root in CACHE_ROOTS]
                excluded.append(
                    {
                        "name": name,
                        "version": version,
                        "checksum": checksum,
                        "reason": f"NOT_IN_CARGO_{TARGET}_RESOLUTION",
                        "exact_archive_available": any(
                            path.is_file() and sha256(path) == checksum for path in candidates
                        ),
                    }
                )
        receipt = {
            "schema": SCHEMA,
            "source": {"head": AG_HEAD, "tree": AG_TREE, "cargo_lock_sha256": LOCK_SHA256},
            "target": TARGET,
            "features": FEATURES,
            "network": "OFFLINE_NO_RETRIEVAL",
            "packages": packages,
            "excluded_lock_packages": excluded,
            "vendor": {
                "tree_sha256": digest,
                "regular_files": files,
                "content_bytes": aggregate,
            },
            "limits": {
                "archive_bytes_each": MAX_ARCHIVE_BYTES,
                "content_bytes_aggregate": MAX_TOTAL_BYTES,
                "members_aggregate": MAX_MEMBERS,
            },
        }
        args.receipt.write_bytes(canonical(receipt) + b"\n")
        print(canonical({"result": "TARGET_VENDOR_CLOSURE_PREPARED", "vendor": receipt["vendor"]}).decode())
    except BaseException:
        if not completed:
            (scratch / "PREPARATION_FAILURE.json").write_bytes(
                canonical({"state": "INCOMPLETE", "automatic_retry": False}) + b"\n"
            )
        raise


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--source", required=True, type=pathlib.Path)
    result.add_argument("--output", required=True, type=pathlib.Path)
    result.add_argument("--receipt", required=True, type=pathlib.Path)
    return result


def main() -> int:
    try:
        prepare(parser().parse_args())
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError, tarfile.TarError, Refusal) as error:
        print(f"REFUSED: {error}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
