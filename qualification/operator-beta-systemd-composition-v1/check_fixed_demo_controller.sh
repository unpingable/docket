#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)
qualification="$repo/qualification/operator-beta-systemd-composition-v1"

python3 -B -m unittest \
  "$qualification/test_fixed_demo_controller.py" \
  "$qualification/test_run_composed_two_vm.py"
python3 -B "$qualification/fixed_demo_controller.py" --help >/dev/null
python3 -B "$qualification/run_composed_two_vm.py" check-refusal --help >/dev/null

rg -q 'launch-intent\.v1\.json' "$qualification/fixed_demo_controller.py"
rg -q 'fcntl\.LOCK_EX' "$qualification/fixed_demo_controller.py"
rg -q 'check_refusal' "$qualification/run_composed_two_vm.py"
rg -q 'test_concurrent_starts_serialize_to_one_manager_call' \
  "$qualification/test_fixed_demo_controller.py"

expected_schema=constellation.operator_beta.fixed_demo_status.v1
if test "${FIXED_DEMO_INJECT_BOUNDARY_FAILURE:-0}" = 1; then
  expected_schema=constellation.operator_beta.substituted.v1
fi
test "$(python3 -B - "$qualification/fixed_demo_controller.py" <<'PY'
import importlib.util,pathlib,sys
path=pathlib.Path(sys.argv[1])
spec=importlib.util.spec_from_file_location('fixed_demo_gate',path)
module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
print(module.PROJECTION_SCHEMA)
PY
)" = "$expected_schema"

echo FIXED_DEMO_CONTROLLER_LOCAL_QUALIFICATION_PASSED
