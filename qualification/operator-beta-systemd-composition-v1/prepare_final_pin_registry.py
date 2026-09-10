#!/usr/bin/env python3
"""Freeze a bounded local Cargo registry seed for the final AG Linux build."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import stat
import tomllib
from typing import Any

AG_HEAD = "ae993551349eb23e3b833caecffb4e352bcd983b"
AG_TREE = "8628d327e14436a20592c813dd9b7a678f8e78c8"
LOCK_SHA256 = "68205a7d2319b648ed5ebcbc42c015222dba2257286012af44b4d9d9e073bcad"
TARGET = "x86_64-unknown-linux-gnu"
SCHEMA = "constellation.operator_beta.cargo_registry_seed.v2"
TREE_DOMAIN = b"operator-beta-cargo-registry-seed-v2"
SOURCE_REGISTRY = pathlib.Path("/home/jbeck/.cargo/registry")
MAX_INDEX_BYTES = 512 * 1024 * 1024
MAX_INDEX_FILES = 100_000
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_TOTAL = 1024 * 1024 * 1024


class Refusal(RuntimeError):
    """Bounded qualification refusal."""


def require_absent(path: pathlib.Path) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        return
    raise Refusal(f"one-use path already exists: {path}")


def physical_directory(path: pathlib.Path) -> None:
    for component in reversed((path, *path.parents)):
        if not stat.S_ISDIR(component.lstat().st_mode):
            raise Refusal(f"not a physical directory: {component}")


def exclusive_file(path: pathlib.Path) -> int:
    physical_directory(path.parent)
    return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)


def read_regular(path: pathlib.Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise Refusal(f"not a regular file: {path}")
        with os.fdopen(descriptor, "rb", closefd=False) as reader:
            body = reader.read()
        after = os.fstat(descriptor)
        signature = lambda value: (value.st_dev, value.st_ino, value.st_size,
                                   value.st_mtime_ns, value.st_ctime_ns, value.st_mode)
        if signature(before) != signature(after) or signature(after) != signature(path.lstat()):
            raise Refusal(f"file changed during read: {path}")
        return body
    finally:
        os.close(descriptor)


def finalize_readonly(root: pathlib.Path) -> None:
    physical_directory(root)
    paths = list(root.rglob("*"))
    for path in paths:
        mode = path.lstat().st_mode
        if stat.S_ISREG(mode):
            os.chmod(path, 0o444, follow_symlinks=False)
        elif not stat.S_ISDIR(mode):
            raise Refusal(f"registry seed contains a non-regular entry: {path}")
    for path in sorted(paths, key=lambda item: len(item.parts), reverse=True):
        if stat.S_ISDIR(path.lstat().st_mode):
            os.chmod(path, 0o555, follow_symlinks=False)
    os.chmod(root, 0o555, follow_symlinks=False)


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
    physical_directory(root)
    digest = hashlib.sha256(domain + b"\0")
    count = 0
    total = 0
    for path in [root, *sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix())]:
        metadata = path.lstat()
        directory = stat.S_ISDIR(metadata.st_mode)
        if not directory and not stat.S_ISREG(metadata.st_mode):
            raise Refusal(f"registry seed contains a non-regular entry: {path}")
        relative = path.relative_to(root).as_posix().encode()
        body = b"" if directory else read_regular(path)
        digest.update(b"D" if directory else b"F")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update((metadata.st_mode & 0o777).to_bytes(4, "big"))
        digest.update(len(body).to_bytes(8, "big"))
        digest.update(body)
        count += not directory
        total += len(body)
    return digest.hexdigest(), count, total


def validate_seed(root: pathlib.Path, receipt_path: pathlib.Path,
                  receipt_sha256: str, lock: pathlib.Path) -> dict[str, Any]:
    physical_directory(root)
    raw = read_regular(receipt_path)
    if hashlib.sha256(raw).hexdigest() != receipt_sha256:
        raise Refusal("registry receipt hash differs")
    receipt = json.loads(raw)
    if raw != canonical(receipt) + b"\n" or receipt.get("schema") != SCHEMA:
        raise Refusal("registry receipt is not canonical V2")
    if receipt.get("source") != {"head": AG_HEAD, "tree": AG_TREE, "cargo_lock_sha256": LOCK_SHA256}:
        raise Refusal("registry receipt source differs")
    if sha256(lock) != LOCK_SHA256 or receipt.get("target") != TARGET:
        raise Refusal("registry lock or target differs")
    if receipt.get("network") != "OFFLINE_LOCAL_CACHE_COPY":
        raise Refusal("registry input mode differs")
    if receipt.get("limits") != {"index_files": MAX_INDEX_FILES, "index_bytes": MAX_INDEX_BYTES,
                                 "archive_bytes_each": MAX_ARCHIVE_BYTES,
                                 "archive_bytes_aggregate": MAX_ARCHIVE_TOTAL}:
        raise Refusal("registry receipt limits differ")
    for path in [root, *root.rglob("*")]:
        metadata = path.lstat()
        if metadata.st_mode & 0o222:
            raise Refusal("registry seed is writable")
    digest, count, total = tree_digest(root, TREE_DOMAIN)
    if receipt.get("seed") != {"tree_sha256": digest, "regular_files": count, "bytes": total}:
        raise Refusal("registry seed final tree differs")
    expected = lock_registry(lock)
    archives = receipt.get("archives", [])
    unavailable = receipt.get("unavailable_lock_archives", [])
    keys = ("name", "version", "source", "checksum")
    observed = [{key: item[key] for key in keys} for item in archives] + unavailable
    if sorted(observed, key=lambda item: (item["name"], item["version"], item["source"])) != expected:
        raise Refusal("registry archive partition differs from lock")
    paths = set()
    archive_total = 0
    for item in archives:
        relative = pathlib.PurePosixPath(item["path"])
        if (relative.is_absolute() or ".." in relative.parts or len(relative.parts) != 4
                or relative.parts[:2] != ("registry", "cache")
                or relative.name != f"{item['name']}-{item['version']}.crate"
                or relative.as_posix() in paths):
            raise Refusal("registry archive path differs")
        paths.add(relative.as_posix())
        body = read_regular(root / relative)
        archive_total += len(body)
        if (len(body) != item["bytes"] or not 0 < len(body) <= MAX_ARCHIVE_BYTES
                or hashlib.sha256(body).hexdigest() != item["checksum"]):
            raise Refusal("registry archive bytes differ")
    actual = {path.relative_to(root).as_posix() for path in (root / "registry/cache").rglob("*") if path.is_file()}
    if actual != paths or archive_total > MAX_ARCHIVE_TOTAL:
        raise Refusal("registry archive inventory differs")
    index_paths = [path for path in (root / "registry/index").rglob("*") if path.is_file()]
    index_bytes = sum(path.stat().st_size for path in index_paths)
    if (receipt.get("index") != {"files": len(index_paths), "bytes": index_bytes}
            or len(index_paths) > MAX_INDEX_FILES or index_bytes > MAX_INDEX_BYTES):
        raise Refusal("registry index inventory differs")
    return {"receipt_sha256": receipt_sha256, "seed": receipt["seed"], "target": TARGET}


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
    require_absent(args.output)
    require_absent(args.receipt)
    physical_directory(args.output.parent)
    physical_directory(args.receipt.parent)
    source = exact_source(args.source)
    receipt_fd = exclusive_file(args.receipt)
    # Exclusive directory admission cannot replace a concurrent or dangling name.
    try:
        args.output.mkdir(mode=0o700)
    except BaseException:
        os.close(receipt_fd)
        raise
    scratch = args.output
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

        finalize_readonly(args.output)
        digest, files, total = tree_digest(args.output, TREE_DOMAIN)
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
        with os.fdopen(receipt_fd, "wb", closefd=False) as stream:
            stream.write(canonical(receipt) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.fchmod(receipt_fd, 0o444)
        print(canonical({"result": "CARGO_REGISTRY_SEED_PREPARED", "seed": receipt["seed"], "archives": len(archive_records), "unavailable": len(unavailable)}).decode())
    except BaseException:
        # All partially admitted paths are retained; no cleanup or retry.
        raise
    finally:
        os.close(receipt_fd)


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
