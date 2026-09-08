#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)
ag_source=${AG_SOURCE:-/data/git/.worktrees/ag-operator-beta-receipt-store-audit}
docket_source=${DOCKET_SOURCE:-/data/git/.worktrees/ag-ng-docket-adoption-docket-c49}
nq_source=${NQ_SOURCE:-/data/git/.worktrees/nq-ng-operator-beta-profile-v1}
ag_vendor=${AG_VENDOR:-/data/git/.campaign-artifacts/docket-systemd-composition-v1/build-inputs/ag-vendor}
docket_vendor=${DOCKET_VENDOR:-/data/git/.campaign-artifacts/docket-systemd-composition-v1/build-inputs/docket-vendor}
fixture=${COMPOSITION_FIXTURE:-/data/git/.campaign-artifacts/docket-systemd-composition-v1/fixture-build-003}
ag_deb=${AG_SYSTEMD_DEB:-/data/git/.campaign-artifacts/nq-ng-operator-beta-m1b-20260908/operator-beta-m1b-v1/run-012/input/agent-governor-ng-systemd-executor_amd64.deb}
qualification="$repo/qualification/operator-beta-systemd-composition-v1"
package="$fixture/constellation-operator-beta-composition-fixture_0.1.0-1_amd64.deb"

test "$(git -C "$ag_source" rev-parse HEAD)" = 837de287497942c79966aa05c083acee9c312261
test -z "$(git -C "$ag_source" status --porcelain)"
test "$(git -C "$docket_source" rev-parse HEAD)" = c49ad8d0f26fb2a13b9dbafdde84d7abfe1f867b
test -z "$(git -C "$docket_source" status --porcelain)"
test "$(git -C "$nq_source" rev-parse HEAD)" = 9f1b081b7fc5b2d99fb92ee6b0ac4107c7e7dfe4
test -z "$(git -C "$nq_source" status --porcelain)"

python3 -B -m unittest discover -s "$qualification" -p 'test_*.py'
rustfmt --edition 2021 --check "$qualification/composition_driver.rs"
python3 -B "$qualification/build_bookworm_fixture.py" verify \
  --ag-source "$ag_source" \
  --docket-source "$docket_source" \
  --ag-vendor "$ag_vendor" \
  --docket-vendor "$docket_vendor" \
  --output "$fixture"
python3 -B - "$qualification/run_composed_two_vm.py" "$package" \
  "$nq_source/qualification/operator-beta-m1b-v1/run_two_vm.py" \
  "$fixture/fixture-build-receipt.v1.json" <<'PY'
import argparse,importlib.util,pathlib,sys
source=pathlib.Path(sys.argv[1]).resolve()
spec=importlib.util.spec_from_file_location('composition_gate_adapter',source)
module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
nq=module.load_module('composition_gate_nq',pathlib.Path(sys.argv[3]))
facts=module.verify_fixture_inputs(argparse.Namespace(composition_deb=pathlib.Path(sys.argv[2]),composition_receipt=pathlib.Path(sys.argv[4])),nq)
assert facts['package_sha256']==module.COMPOSITION_PACKAGE_SHA256
assert facts['receipt_sha256']==module.COMPOSITION_RECEIPT_SHA256
PY

cargo test --locked --manifest-path "$docket_source/Cargo.toml" \
  -p gwr-local governed_loop::tests
cargo test --locked --manifest-path "$ag_source/Cargo.toml" \
  -p ag-app --test governed_loop_engine
cargo test --locked --manifest-path "$ag_source/Cargo.toml" \
  -p ag-app --test docket_issuance
cargo test --locked --manifest-path "$ag_source/Cargo.toml" \
  -p ag-app --test governed_docket_process

expected_package=990dc8709862ffa5be429cde9ae16cb5c8d11dfcdce93567dc4af1b51987f8cb
if test "${COMPOSITION_INJECT_BOUNDARY_FAILURE:-0}" = 1; then
  expected_package=0000000000000000000000000000000000000000000000000000000000000000
fi
test "$(sha256sum "$package" | cut -d ' ' -f1)" = "$expected_package"
test "$(sha256sum "$ag_deb" | cut -d ' ' -f1)" = 98a4f31f0b6c13653ae95ce55586dbac6d0826b649cd7612882f3716b80e2279

scratch=$(mktemp -d /tmp/docket-composition-gate.XXXXXX)
trap 'rm -rf "$scratch"' EXIT
dpkg-deb -x "$package" "$scratch/composition"
dpkg-deb -x "$ag_deb" "$scratch/ag"
test "$(sha256sum "$scratch/ag/usr/libexec/agent-governor-ng/ag-effectd" | cut -d ' ' -f1)" = \
  668bdd26646ef6a5ba5502b64984844b84c1f70024a76eb5236af2b17702d068
AG_DOCKET_BIN="$scratch/composition/usr/libexec/constellation-operator-beta/docket" \
AG_EFFECTD_BIN="$scratch/ag/usr/libexec/agent-governor-ng/ag-effectd" \
  cargo test --locked --manifest-path "$ag_source/Cargo.toml" \
  -p ag-app --test governed_docket_process \
  signed_issuance_crosses_docket_and_effectd_once_then_settles -- --ignored --exact
"$scratch/composition/usr/libexec/constellation-operator-beta/composition-driver" \
  "$scratch/composition/usr/libexec/constellation-operator-beta/docket" \
  "$scratch/ag/usr/libexec/agent-governor-ng/ag-effectd" \
  "$scratch/result" \
  local-known-no-effect \
  00000000000000000000000000000000 \
  constellation-beta-http-fixture.service \
  sha256:1111111111111111111111111111111111111111111111111111111111111111 \
  sha256:2222222222222222222222222222222222222222222222222222222222222222
python3 -B - "$scratch/result" <<'PY'
import json,pathlib,sys
root=pathlib.Path(sys.argv[1])
result=json.loads((root/'composition-result.json').read_bytes())
outcome=json.loads((root/'executor-outcome.json').read_bytes())
evidence=json.loads((root/'systemd-evidence.json').read_bytes())
assert result['disposition']=='SETTLED'
assert (result['ag_spends'],result['docket_attempts'],result['settlements'])==(1,1,1)
assert result['duplicate_same_custody'] is True
assert result['ag_restart_exact'] is True
assert result['executor_reconcile_exact'] is True
assert outcome['outcome']=='failure'
assert evidence['outcome_code']=='systemd_machine_identity_mismatch'
assert evidence['job_path'] is None and evidence['job_result'] is None
assert [item['kind'] for item in evidence['messages']]==['get_machine_id_reply']
PY

echo COMPOSITION_LOCAL_QUALIFICATION_PASSED
