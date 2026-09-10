#!/usr/bin/env python3
"""Freeze a bounded local Cargo registry seed for the final AG Linux build."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import stat
import tempfile
import tomllib
from typing import Any

AG_HEAD = "ae993551349eb23e3b833caecffb4e352bcd983b"
AG_TREE = "8628d327e14436a20592c813dd9b7a678f8e78c8"
LOCK_SHA256 = "68205a7d2319b648ed5ebcbc42c015222dba2257286012af44b4d9d9e073bcad"
TARGET = "x86_64-unknown-linux-gnu"
SCHEMA = "constellation.operator_beta.cargo_registry_seed.v1"
SOURCE_REGISTRY = pathlib.Path("/home/jbeck/.cargo/registry")
MAX_INDEX_BYTES = 512 * 1024 * 1024
MAX_INDEX_FILES = 100_000
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_TOTAL = 1024 * 1024 * 1024


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


def copy_regular(source: pathlib.Path, destination: pathlib.Path) -> int:
    metadata = source.lstat()
    if not stat.S_ISREG(metadata.st_mode) or source.is_symlink():
        raise Refusal(f"input is not regular: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as reader, destination.open("xb") as writer:
        total = 0
        while block := reader.read(1024 * 1024):
            writer.write(block)
            total += len(block)
    os.chmod(destination, stat.S_IMODE(metadata.st_mode) & 0o777)
    return total


def tree_digest(root: pathlib.Path, domain: bytes) -> tuple[str, int, int]:
    digest = hashlib.sha256(domain + b"\0")
    count = 0
    total = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            raise Refusal(f"registry seed contains a non-regular entry: {path}")
        relative = path.relative_to(root).as_posix().encode()
        body = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update((metadata.st_mode & 0o777).to_bytes(4, "big"))
        digest.update(len(body).to_bytes(8, "big"))
        digest.update(body)
        count += 1
        total += len(body)
    return digest.hexdigest(), count, total


def exact_source(source: pathlib.Path) -> pathlib.Path:
    source = source.resolve(strict=True)
    import subprocess

    def git(*args: str) -> bytes:
        result = subprocess.run(
            ["git", *args], cwd=source, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
        )
        if result.returncode != 0:
            raise Refusal("cannot inspect AG source")
        return result.stdout

    if git("rev-parse", "HEAD").decode().strip() != AG_HEAD:
        raise Refusal("AG HEAD differs")
    if git("rev-parse", "HEAD^{tree}").decode().strip() != AG_TREE:
        raise Refusal("AG tree differs")
    if git("status", "--porcelain"):
        raise Refusal("AG source is dirty")
    if sha256(source / "Cargo.lock") != LOCK_SHA256:
        raise Refusal("AG Cargo.lock differs")
    return source


def lock_registry(lock: pathlib.Path) -> list[dict[str, str]]:
    parsed = tomllib.loads(lock.read_text(encoding="utf-8"))
    result = []
    for package in parsed.get("package", []):
        source = package.get("source")
        if not isinstance(source, str) or not source.startswith("registry+"):
            continue
        checksum = package.get("checksum")
        if not isinstance(checksum, str) or len(checksum) != 64:
            raise Refusal("registry lock entry lacks checksum")
        result.append({
            "name": package["name"], "version": package["version"],
            "source": source, "checksum": checksum,
        })
    identities = {(item["name"], item["version"], item["source"]) for item in result}
    if len(identities) != len(result):
        raise Refusal("duplicate registry identity")
    return sorted(result, key=lambda item: (item["name"], item["version"], item["source"]))


def prepare(args: argparse.Namespace) -> None:
    source = exact_source(args.source)
    if args.output.exists() or args.receipt.exists():
        raise Refusal("registry seed output already exists")
    scratch = pathlib.Path(tempfile.mkdtemp(prefix=".final-pin-cargo-registry.", dir=args.output.parent))
    complete = False
    try:
        source_index = SOURCE_REGISTRY / "index"
        index_output = scratch / "registry/index"
        index_total = 0
        index_files = 0
        for path in sorted(source_index.rglob("*"), key=lambda item: item.relative_to(source_index).as_posix()):
            metadata = path.lstat()
            relative = path.relative_to(source_index)
            if stat.S_ISDIR(metadata.st_mode):
                (index_output / relative).mkdir(parents=True, exist_ok=True)
                continue
            index_files += 1
            if index_files > MAX_INDEX_FILES:
                raise Refusal("registry index file count exceeds bound")
            index_total += copy_regular(path, index_output / relative)
            if index_total > MAX_INDEX_BYTES:
                raise Refusal("registry index bytes exceed bound")

        archive_records = []
        unavailable = []
        archive_total = 0
        cache_roots = sorted((SOURCE_REGISTRY / "cache").iterdir())
        for package in lock_registry(source / "Cargo.lock"):
            filename = f"{package['name']}-{package['version']}.crate"
            candidates = [root / filename for root in cache_roots if (root / filename).is_file()]
            exact = [path for path in candidates if sha256(path) == package["checksum"]]
            if not exact:
                unavailable.append(package)
                continue
            selected = exact[0]
            size = selected.stat().st_size
            if size <= 0 or size > MAX_ARCHIVE_BYTES:
                raise Refusal("crate archive exceeds bound")
            archive_total += size
            if archive_total > MAX_ARCHIVE_TOTAL:
                raise Refusal("crate archive aggregate exceeds bound")
            relative = pathlib.Path("registry/cache") / selected.parent.name / filename
            copied = copy_regular(selected, scratch / relative)
            if copied != size or sha256(scratch / relative) != package["checksum"]:
                raise Refusal("copied crate archive differs")
            archive_records.append(package | {"path": relative.as_posix(), "bytes": size})

        scratch.rename(args.output)
        complete = True
        digest, files, total = tree_digest(args.output, b"operator-beta-cargo-registry-seed-v1")
        receipt = {
            "schema": SCHEMA,
            "source": {"head": AG_HEAD, "tree": AG_TREE, "cargo_lock_sha256": LOCK_SHA256},
            "target": TARGET,
            "network": "OFFLINE_LOCAL_CACHE_COPY",
            "archives": archive_records,
            "unavailable_lock_archives": unavailable,
            "index": {"files": index_files, "bytes": index_total},
            "seed": {"tree_sha256": digest, "regular_files": files, "bytes": total},
            "limits": {
                "index_files": MAX_INDEX_FILES, "index_bytes": MAX_INDEX_BYTES,
                "archive_bytes_each": MAX_ARCHIVE_BYTES,
                "archive_bytes_aggregate": MAX_ARCHIVE_TOTAL,
            },
        }
        args.receipt.write_bytes(canonical(receipt) + b"\n")
        print(canonical({"result": "CARGO_REGISTRY_SEED_PREPARED", "seed": receipt["seed"], "archives": len(archive_records), "unavailable": len(unavailable)}).decode())
    except BaseException:
        if not complete:
            (scratch / "PREPARATION_FAILURE.json").write_bytes(
                canonical({"state": "INCOMPLETE", "automatic_retry": False}) + b"\n"
            )
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--receipt", required=True, type=pathlib.Path)
    try:
        prepare(parser.parse_args())
        return 0
    except (OSError, ValueError, KeyError, Refusal) as error:
        print(f"REFUSED: {error}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
