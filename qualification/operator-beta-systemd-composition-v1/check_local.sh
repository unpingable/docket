#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)
ag_source=${AG_SOURCE:-/data/git/.worktrees/ag-ng-classic-retirement-integration}
docket_source=${DOCKET_SOURCE:-/data/git/.worktrees/docket-nq-purpose-fixtures-20260908}
nq_source=${NQ_SOURCE:-/data/git/.worktrees/nq-ng-classic-retirement-composition-20260908}
ag_vendor=${AG_VENDOR:-/data/git/.campaign-artifacts/docket-systemd-composition-v1/build-inputs/ag-vendor}
docket_vendor=${DOCKET_VENDOR:-/data/git/.campaign-artifacts/docket-systemd-composition-v1/build-inputs/docket-vendor}
fixture=${COMPOSITION_FIXTURE:-/data/git/.campaign-artifacts/classic-retirement-full-20260908/composition-fixture-package-002}
ag_deb=${AG_SYSTEMD_DEB:-/data/git/.campaign-artifacts/classic-retirement-full-20260908/composition-executor-package-002/agent-governor-ng-systemd-executor_0.1.0-1+classicretirement1_amd64.deb}
qualification="$repo/qualification/operator-beta-systemd-composition-v1"
package="$fixture/constellation-operator-beta-composition-fixture_0.1.0-1_amd64.deb"

test "$(git -C "$ag_source" rev-parse HEAD)" = bf6adde2792a886d1ba75d97ca77efb8e914f4f5
test -z "$(git -C "$ag_source" status --porcelain)"
test "$(git -C "$docket_source" rev-parse HEAD)" = 6c57926d2560c47c681691e006fbbfe244c6993e
test -z "$(git -C "$docket_source" status --porcelain)"
test "$(git -C "$nq_source" rev-parse HEAD)" = 7886222f20ebc76516300985cbf09b36c2b294e0
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

expected_package=45a18d7c0d7a70933c6a7e2f6c56c190203d1a4afee9b1ec5097065d848d168e
if test "${COMPOSITION_INJECT_BOUNDARY_FAILURE:-0}" = 1; then
  expected_package=0000000000000000000000000000000000000000000000000000000000000000
fi
test "$(sha256sum "$package" | cut -d ' ' -f1)" = "$expected_package"
test "$(sha256sum "$ag_deb" | cut -d ' ' -f1)" = 80ea7ad067da9d5ed1f07b39fb7ee41eef58680f3af15fad64c6b1bf05c1045c

scratch=$(mktemp -d /tmp/docket-composition-gate.XXXXXX)
trap 'rm -rf "$scratch"' EXIT
dpkg-deb -x "$package" "$scratch/composition"
dpkg-deb -x "$ag_deb" "$scratch/ag"
test "$(sha256sum "$scratch/ag/usr/libexec/agent-governor-ng/ag-effectd" | cut -d ' ' -f1)" = \
  7c45c79de452ab838cf79575872b0797eafbe27c7904b113e560967d11eef75e
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
python3 -B - "$scratch/result" \
  "$scratch/composition/usr/libexec/constellation-operator-beta/docket" \
  "$scratch/ag/usr/libexec/agent-governor-ng/ag-effectd" <<'PY'
import hashlib,json,pathlib,shutil,sqlite3,subprocess,sys
root=pathlib.Path(sys.argv[1])
docket=pathlib.Path(sys.argv[2])
effectd=pathlib.Path(sys.argv[3])
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
for relative in ('composition-result.json','executor-outcome.json','docket-inspection.json'):
    assert (root/relative).read_bytes().endswith(b'\n')
store=root/'occurrence/ag-effectd-attempts.sqlite'
connection=sqlite3.connect(store)
checkpoint=connection.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()
connection.close()
assert checkpoint is not None and checkpoint[0]==0
wal=pathlib.Path(str(store)+'-wal')
assert not wal.exists() or wal.stat().st_size==0
cut=root/'ag-effectd-attempts-cut.sqlite'
shutil.copyfile(store,cut)
cut.chmod(0o400)
store_sha='sha256:'+hashlib.sha256(cut.read_bytes()).hexdigest()
audited=subprocess.run(
    [str(effectd),'audit-store',str(root/'occurrence/systemd-plan-v2.json'),
     '--store-cut',str(cut),'--store-bytes',str(cut.stat().st_size),
     '--store-sha256',store_sha],
    input=(root/'executor-dispatch.json').read_bytes(),capture_output=True,check=True,
)
assert audited.stderr==b''
assert audited.stdout==(root/'executor-outcome.json').read_bytes()
inspected=subprocess.run(
    [str(docket),'governed-loop','inspect','--state',str(root/'occurrence/docket-state'),
     '--issuance',result['issuance']],capture_output=True,check=True,
)
assert inspected.stderr==b''
assert inspected.stdout==(root/'docket-inspection.json').read_bytes()
PY

echo COMPOSITION_LOCAL_QUALIFICATION_PASSED
