#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")" && pwd)
nq_harness=${NQ_HARNESS:-/data/git/.worktrees/nq-ng-operator-beta-profile-v1/qualification/operator-beta-m1b-v1/run_two_vm.py}
authoritative=/var/tmp/constellation-operator-beta-composed-m1b-run-002
preserved=/data/git/.campaign-artifacts/docket-systemd-composition-v1/operator-beta-composed-m1b-v1/run-002

python3 -B -m unittest "$root/test_qualification_receipt.py"
python3 -B "$root/run_composed_two_vm.py" check-run "$authoritative" --nq-harness "$nq_harness"
python3 -B "$root/run_composed_two_vm.py" check-run "$preserved" --nq-harness "$nq_harness"

expected=f776017d605ba12daded00e658819a0ba0fa20c40e7bf25aae8d765431b5dfce
if test "${COMPOSITION_CLOSEOUT_INJECT_BOUNDARY_FAILURE:-0}" = 1; then
  expected=0000000000000000000000000000000000000000000000000000000000000000
fi
test "$(sha256sum "$authoritative/ARTIFACTS.sha256" | cut -d ' ' -f1)" = "$expected"

echo COMPOSITION_CLOSEOUT_QUALIFICATION_PASSED
