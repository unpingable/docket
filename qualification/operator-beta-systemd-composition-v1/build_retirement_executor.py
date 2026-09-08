#!/usr/bin/env python3
"""Build the bounded derivative AG executor package; no installation or VM launch."""

import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile

import build_bookworm_fixture as shared

VERSION = "0.1.0-1+classicretirement1"
PACKAGE = f"agent-governor-ng-systemd-executor_{VERSION}_amd64.deb"
SCHEMA = "constellation.classic_retirement.executor_build.v1"
LIMITATIONS = ["qualification-only", "no installation or execution qualification", "no inherited M2 acceptance"]


def logged_build(arguments, destination):
    """Retain command output before reporting failure or supervisor loss."""
    with destination.open("xb", buffering=0) as log:
        result = subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
        os.fsync(log.fileno())
    terminal = destination.with_suffix(".exit")
    terminal.write_text(f"{result.returncode}\n")
    if result.returncode != 0:
        raise shared.Refusal(f"build exited {result.returncode}; retained output: {destination}")


def command(source, vendor, cargo_home, target):
    result = shared.build_command(source, vendor, cargo_home, target, "ag")
    index = result.index("--example")
    result[index:index + 2] = ["--bin", "ag-effectd"]
    return result


def package_binary(binary, case):
    shared.regular_file(binary, "AG executor")
    root = case / "debroot"
    destination = root / "usr/libexec/agent-governor-ng/ag-effectd"
    destination.parent.mkdir(parents=True)
    shutil.copyfile(binary, destination)
    destination.chmod(0o755)
    control = root / "DEBIAN/control"
    control.parent.mkdir()
    control.write_text(
        f"Package: agent-governor-ng-systemd-executor\nVersion: {VERSION}\n"
        "Section: admin\nPriority: optional\nArchitecture: amd64\n"
        "Maintainer: Constellation qualification <noreply@example.invalid>\n"
        "Depends: libc6 (>= 2.36), libgcc-s1, systemd (>= 252)\n"
        "Description: qualification-only target-local AG systemd adapter\n"
        " Installs no service, configuration, authority state or mutable store.\n"
    )
    control.chmod(0o644)
    for path in (root, *root.rglob("*")):
        if path.is_dir():
            path.chmod(0o755)
    shared.set_epoch(root)
    package = case / PACKAGE
    shared.run(["dpkg-deb", "--root-owner-group", "--build", str(root), str(package)],
               env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC", "SOURCE_DATE_EPOCH": shared.SOURCE_DATE_EPOCH})
    return package


def build(args):
    if args.output.exists():
        raise shared.Refusal("output already exists")
    if f"{os.getuid()}:{os.getgid()}" != shared.BUILD_USER:
        raise shared.Refusal("builder uid/gid differs")
    source = shared.source_facts(args.source, shared.AG_HEAD, shared.AG_TREE, "AG")
    vendor = shared.tree_digest(args.vendor, b"ag-composition-vendor-v1")
    image = shared.image_facts()
    args.output.mkdir(mode=0o700)
    # Two independent offline builds, with only one temporary campaign-owned root.
    with tempfile.TemporaryDirectory(prefix=".retirement-executor-", dir=args.output.parent) as temporary:
        scratch = pathlib.Path(temporary)
        facts = []
        for label in ("a", "b"):
            case = scratch / label
            case.mkdir()
            checkout = case / "ag"
            shared.extract_source(args.source, checkout)
            config = checkout / ".cargo/config.toml"
            config.parent.mkdir(exist_ok=True)
            config.write_text(shared.cargo_config("/ag-vendor"))
            cargo_home, target = case / "cargo", case / "target"
            cargo_home.mkdir()
            target.mkdir()
            print(f"BUILD_STARTED {label}", flush=True)
            logged_build(command(checkout, args.vendor, cargo_home, target), args.output / f"{label}-build.log")
            print(f"BUILD_COMPLETED {label}", flush=True)
            binary = target / "release/ag-effectd"
            versions = shared.run(["readelf", "--version-info", str(binary)]).stdout.decode()
            parsed = [(int(a), int(b)) for a, b in re.findall(r"Name: GLIBC_(\d+)\.(\d+)", versions)]
            if parsed and max(parsed) > (2, 36):
                raise shared.Refusal("executor exceeds Debian 12 glibc boundary")
            package = package_binary(binary, case)
            facts.append({"binary_sha256": shared.sha256(binary), "binary_bytes": binary.stat().st_size,
                          "package_sha256": shared.sha256(package), "package_bytes": package.stat().st_size})
        if facts[0] != facts[1]:
            raise shared.Refusal("independent executor builds differ")
        shutil.copyfile(scratch / "a" / PACKAGE, args.output / PACKAGE)
        logs = {}
        for label in ("a", "b"):
            destination = args.output / f"{label}-build.log"
            logs[destination.name] = shared.sha256(destination)
        receipt = {"schema": SCHEMA, "source": source, "vendor": list(vendor), "image": image,
                   "environment": shared.BUILD_ENV, "clean_builds": 2, "version": VERSION,
                   "package": PACKAGE, "facts": facts[0], "logs": logs, "limitations": LIMITATIONS,
                   "builder_sha256": shared.sha256(pathlib.Path(__file__)),
                   "shared_builder_sha256": shared.sha256(pathlib.Path(shared.__file__)),
                   "command": command(pathlib.Path("<AG_SOURCE>"), pathlib.Path("<AG_VENDOR>"),
                                      pathlib.Path("<CARGO_HOME>"), pathlib.Path("<TARGET>"))}
        (args.output / "executor-build-receipt.json").write_bytes(shared.canonical(receipt) + b"\n")
        print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=pathlib.Path, required=True)
    parser.add_argument("--vendor", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    build(parser.parse_args())
