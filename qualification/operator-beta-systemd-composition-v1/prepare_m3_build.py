#!/usr/bin/env python3
"""Prepare an isolated exact-source M3 companion build; never compile or launch.

The integration owner must separately resolve/vendor the resulting Cargo graph,
build twice offline in the admitted Bookworm toolchain and review exact receipts.
"""
import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess
import tarfile


def prepare(sources, output):
    output.mkdir(mode=0o700, exist_ok=False)
    recorded = {}
    for role, (source, expected) in sources.items():
        head = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
        dirty = subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain=v1'])
        if head != expected or len(expected) != 40 or dirty:
            raise RuntimeError(role + ': source is not the exact clean candidate')
        archive = output / (role + '.tar')
        with archive.open('xb') as stream:
            subprocess.run(['git', '-C', str(source), 'archive', '--format=tar', head], stdout=stream, check=True)
        destination = output / role
        destination.mkdir()
        with tarfile.open(archive) as bundle:
            bundle.extractall(destination, filter='data')
        recorded[role] = {'head': head, 'tree': subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD^{tree}'], text=True).strip(), 'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest()}
    crate = output / 'm3-driver'
    (crate / 'src').mkdir(parents=True)
    docket_sources = output / 'docket/qualification/operator-beta-systemd-composition-v1'
    for name in ('m3_composition_driver.rs', 'composition_driver.rs'):
        shutil.copyfile(docket_sources / name, crate / 'src' / name)
    shutil.copyfile(output / 'labelwatch/qualification/m3-admission/observation_resolver.rs', crate / 'src/m3_observation_resolver.rs')
    (crate / 'Cargo.toml').write_text('''[package]
name = "constellation-m3-driver"
version = "0.1.0"
edition = "2021"
[workspace]
[features]
default = ["m3-labelwatch"]
m3-labelwatch = []
[[bin]]
name = "m3-composition-driver"
path = "src/m3_composition_driver.rs"
[dependencies]
ag-app = { path = "../ag/crates/ag-app", features = ["systemd-dbus"] }
ag-campaign = { path = "../ag/crates/ag-campaign" }
ag-effect = { path = "../ag/crates/ag-effect" }
ag-primitives = { path = "../ag/crates/ag-primitives" }
nq-app = { path = "../nq/crates/nq-app" }
nq-core = { path = "../nq/crates/nq-core" }
nq-protocol = { path = "../nq/crates/nq-protocol" }
base64 = "0.22"
ring = "0.17"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha2 = "0.10"
uuid = { version = "1", features = ["v4"] }
[dev-dependencies]
tempfile = "3"
''')
    (output / 'PREPARATION.json').write_text(json.dumps({'schema': 'constellation.m3-build-preparation/v1', 'sources': recorded, 'compiled': False, 'qualified': False, 'next': 'resolve exact lock/vendor; two offline Bookworm builds; independent replay and composition qualification'}, sort_keys=True) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for role in ('ag', 'nq', 'docket', 'labelwatch'):
        parser.add_argument('--' + role, type=pathlib.Path, required=True)
        parser.add_argument('--' + role + '-head', required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    prepare({role: (getattr(args, role), getattr(args, role + '_head')) for role in ('ag', 'nq', 'docket', 'labelwatch')}, args.output)
