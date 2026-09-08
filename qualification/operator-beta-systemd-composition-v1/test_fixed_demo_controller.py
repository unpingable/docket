#!/usr/bin/env python3
"""Direct qualification cases for the fixed M2 launch controller."""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


HERE = pathlib.Path(__file__).resolve().parent


def load(name: str, path: pathlib.Path):
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


controller = load("fixed_demo_controller_test", HERE / "fixed_demo_controller.py")


class FakeManager:
    def __init__(self, *, delay: float = 0, lose_acknowledgement: bool = False) -> None:
        self.delay = delay
        self.lose_acknowledgement = lose_acknowledgement
        self.starts = 0
        self.active = False
        self.argv: list[str] | None = None

    def start(self, _spec, argv, _spec_sha256) -> None:
        self.starts += 1
        self.argv = argv
        self.active = True
        if self.delay:
            time.sleep(self.delay)
        if self.lose_acknowledgement:
            raise TimeoutError("manager acknowledgement not observed")

    def query(self, _unit: str):
        return {
            "source": "user-systemd",
            "state": "OBSERVED",
            "properties": {
                "LoadState": "loaded" if self.active else "not-found",
                "ActiveState": "active" if self.active else "inactive",
                "SubState": "running" if self.active else "dead",
                "InvocationID": "1" * 32 if self.active else "",
                "MainPID": "1234" if self.active else "0",
            },
        }


class UnobservableManager(FakeManager):
    def query(self, _unit: str):
        return {"source": "user-systemd", "state": "NOT_OBSERVABLE", "reason": "fixture"}


class FixedDemoControllerTests(unittest.TestCase):
    def test_checker_substitution_refuses_before_import(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            spec, _path, _size, _digest = self.fixture(pathlib.Path(temporary).resolve())
            changed = pathlib.Path(temporary) / "checker.py"
            changed.write_bytes(b" " * controller.CHECKER_BYTES)
            with mock.patch.object(controller, "RUNNER_PATH", changed):
                with self.assertRaisesRegex(controller.Refusal, "admitted validator"):
                    controller.load_owner_modules(spec)

    def test_admitted_capsule_loads_real_frozen_runner_and_builder(self) -> None:
        spec = controller.ADMITTED_COHORT
        controller.verify_owner_repository(spec["runner"])
        controller.verify_owner_repository(spec["nq_harness"])
        argv = controller.runner_argv(spec)
        self.assertLess(len(argv[5]), 100000)
        result = controller.subprocess.run(argv[:8] + ["--help"], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b"check-run", result.stdout)

    def test_capsule_executes_captured_runner_and_imports_after_path_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            spec, _path, _size, _digest = self.fixture(pathlib.Path(temporary).resolve())
            module_paths = [spec[name]["path"] for name in ("builder", "nq_harness")]
            runner = (
                "import importlib.util,sys\n"
                f"paths={module_paths!r}\n"
                "values=[]\n"
                "for i,path in enumerate(paths):\n"
                " s=importlib.util.spec_from_file_location('frozen'+str(i),path)\n"
                " m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;s.loader.exec_module(m)\n"
                " values.append(m.VALUE)\n"
                "print('captured-runner:'+','.join(values))\n"
            )
            for name, body in (("runner", runner), ("builder", "VALUE='builder'\n"),
                               ("nq_harness", "VALUE='nq-ng'\n")):
                path = pathlib.Path(spec[name]["path"])
                path.write_text(body)
                spec[name]["bytes"] = path.stat().st_size
                spec[name]["sha256"] = controller.digest_path(path)
            argv = controller.runner_argv(spec)
            for name in ("runner", "builder", "nq_harness"):
                path = pathlib.Path(spec[name]["path"])
                path.rename(path.with_suffix(".retained"))
                path.write_text("raise SystemExit('replacement must never execute')\n")
            result = controller.subprocess.run(argv, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(result.stdout, b"captured-runner:builder,nq-ng\n")
            self.assertEqual(result.stderr, b"")
            changed = list(argv)
            changed[6] = "0" * 64
            refused = controller.subprocess.run(changed, capture_output=True, timeout=10)
            self.assertNotEqual(refused.returncode, 0)
            self.assertEqual(refused.stdout, b"")
            self.assertIn(b"capsule identity differs", refused.stderr)

    def test_capsule_source_mutation_before_capture_refuses(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            spec, _path, _size, _digest = self.fixture(pathlib.Path(temporary).resolve())
            pathlib.Path(spec["builder"]["path"]).write_bytes(b"changed\n")
            with self.assertRaises(controller.Refusal):
                controller.runner_argv(spec)

    def test_recovery_keeps_missing_acceptance_disagreement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            spec, path, size, digest = self.fixture(pathlib.Path(temporary).resolve())
            fixed = controller.FixedController(path, size, digest, FakeManager(),
                lambda _cut: (_ for _ in ()).throw(RuntimeError("interrupted")))
            with self.assertRaises(RuntimeError):
                fixed.start()
            recovery = {"state": "REOPENED", "phase": "configured", "producer": {}}
            with mock.patch.object(controller, "runner_recovery", return_value=recovery):
                result = fixed.status()
            self.assertEqual(result["runner_durable"]["state"], "configured")
            self.assertEqual(result["controller_custody"]["state"], "INDETERMINATE")
            self.assertIn("launch intent has no valid retained Docket acceptance", result["disagreements"])

    def test_manager_query_failures_are_not_observable(self) -> None:
        for error in (OSError("fixture"), controller.subprocess.TimeoutExpired("systemctl", 10)):
            with self.subTest(error=type(error).__name__):
                with mock.patch.object(controller.subprocess, "run", side_effect=error):
                    self.assertEqual(controller.SystemdUserManager().query("fixture.service")["state"], "NOT_OBSERVABLE")
        with mock.patch.object(controller.subprocess, "run", return_value=mock.Mock(returncode=0, stdout=b"\xff")):
            self.assertEqual(controller.SystemdUserManager().query("fixture.service")["state"], "NOT_OBSERVABLE")

    def test_owner_repository_checks_head_tree_and_cleanliness(self) -> None:
        record = {"path": "/fixture/repo/qualification/lane/runner.py", "subject": "a" * 40, "tree": "b" * 40}
        for substitution in (None, 0, 1, 2):
            replies = [mock.Mock(returncode=0, stdout=("a" * 40 + "\n").encode(), stderr=b""),
                       mock.Mock(returncode=0, stdout=("b" * 40 + "\n").encode(), stderr=b""),
                       mock.Mock(returncode=0, stdout=b"", stderr=b"")]
            if substitution is not None:
                replies[substitution].stdout = b"different"
            with mock.patch.object(controller.subprocess, "run", side_effect=replies):
                if substitution is None:
                    controller.verify_owner_repository(record)
                else:
                    with self.assertRaises(controller.Refusal):
                        controller.verify_owner_repository(record)

    def test_runner_terminal_does_not_replace_missing_controller_custody(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            spec, path, size, digest = self.fixture(pathlib.Path(temporary).resolve())
            terminal = {"state": "TERMINAL", "owner": "Docket", "disposition": "fixture"}
            with mock.patch.object(controller, "owner_terminal", return_value=terminal):
                projection = controller.FixedController(path, size, digest, FakeManager()).status()
            self.assertEqual(projection["runner_durable"]["state"], "TERMINAL")
            self.assertEqual(projection["controller_custody"]["state"], "INDETERMINATE")
            self.assertIn("runner evidence exists without Docket launch intent", projection["disagreements"])

    def test_inactive_acceptance_substitutions_remain_visible(self) -> None:
        substitutions = {"scenario": "other", "invocation_id": "invalid", "main_pid": -1,
                         "start_ticks": False, "execution_sha256": "0" * 64}
        for field, value in substitutions.items():
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                spec, path, size, digest = self.fixture(pathlib.Path(temporary).resolve())
                manager = FakeManager()
                with self.execution_observation(spec, digest):
                    controller.FixedController(path, size, digest, manager).start()
                acceptance = pathlib.Path(spec["state_root"]) / "launch-accepted.v1.json"
                record = json.loads(acceptance.read_bytes())
                record[field] = value
                acceptance.chmod(0o600)
                acceptance.write_bytes(controller.canonical(record) + b"\n")
                acceptance.chmod(0o400)
                manager.active = False
                result = controller.FixedController(path, size, digest, manager).status()
                self.assertEqual(result["controller_custody"]["state"], "INDETERMINATE")
                self.assertTrue(result["disagreements"])

    def test_manager_inactive_does_not_suppress_live_os_testimony(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            spec, path, size, digest = self.fixture(pathlib.Path(temporary).resolve())
            manager = FakeManager()
            fixed = controller.FixedController(path, size, digest, manager)
            with self.execution_observation(spec, digest):
                fixed.start()
                manager.active = False
                result = fixed.status()
            self.assertEqual(result["live_sources"]["manager"]["state"], "PROCESS_EXITED")
            self.assertEqual(result["live_sources"]["os"]["state"], "PROCESS_ACTIVE")
            self.assertIn("manager and OS process testimony disagree", result["disagreements"])

    def test_lock_replacement_after_intent_prevents_manager_call(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            spec, path, size, digest = self.fixture(pathlib.Path(temporary).resolve())
            manager = FakeManager()
            lock = pathlib.Path(spec["state_root"]) / "launch.lock"
            def replace(name):
                if name == "intent_durable":
                    lock.rename(lock.with_suffix(".retained"))
                    lock.touch(mode=0o600)
            with self.assertRaisesRegex(controller.Refusal, "pathname identity"):
                controller.FixedController(path, size, digest, manager, replace).start()
            self.assertEqual(manager.starts, 0)

    def test_lock_contention_times_out_before_intent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            spec, path, size, digest = self.fixture(pathlib.Path(temporary).resolve())
            manager = FakeManager()
            with (pathlib.Path(spec["state_root"]) / "launch.lock").open("rb") as lock:
                controller.fcntl.flock(lock, controller.fcntl.LOCK_EX)
                with mock.patch.object(controller, "LOCK_WAIT_SECONDS", 0.02):
                    with self.assertRaisesRegex(controller.Refusal, "timed out"):
                        controller.FixedController(path, size, digest, manager).start()
            self.assertEqual(manager.starts, 0)
            self.assertFalse((pathlib.Path(spec["state_root"]) / "launch-intent.v1.json").exists())

    def test_unadmitted_coherent_spec_cannot_start(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            spec, path, size, digest = self.fixture(pathlib.Path(temporary).resolve())
            manager = FakeManager()
            with mock.patch.object(controller, "ADMITTED_COHORT", None):
                with self.assertRaisesRegex(controller.Refusal, "not admitted"):
                    controller.FixedController(path, size, digest, manager).start()
            self.assertEqual(manager.starts, 0)

    def fixture(self, root: pathlib.Path):
        state = root / "controller-state"
        state.mkdir(mode=0o700)
        run_root = root / "run-001"
        working = root / "working"
        working.mkdir()
        records = root / "records"
        records.mkdir()
        files: dict[str, pathlib.Path] = {}
        for name in ("runner", "builder", "nq_harness", *controller.INPUT_FIELDS):
            path = records / name
            path.write_bytes((name + "\n").encode())
            files[name] = path
        metadata = state.stat()
        lock_path = state / "launch.lock"
        lock_path.touch(mode=0o600)
        lock_metadata = lock_path.stat()

        def bound(path: pathlib.Path) -> dict:
            return {
                "path": str(path),
                "bytes": path.stat().st_size,
                "sha256": controller.digest_path(path),
            }

        spec = {
            "schema": controller.SPEC_SCHEMA,
            "scenario": controller.SCENARIO,
            "controller_base_subject": "a" * 40,
            "controller_base_tree": "b" * 40,
            "state_root": str(state),
            "state_root_device": metadata.st_dev,
            "state_root_inode": metadata.st_ino,
            "state_root_uid": metadata.st_uid,
            "state_root_gid": metadata.st_gid,
            "state_root_mode": 0o700,
            "launch_lock_device": lock_metadata.st_dev,
            "launch_lock_inode": lock_metadata.st_ino,
            "run_id": "operator-beta-composed-m2-run-001",
            "run_root": str(run_root),
            "producer_unit": "constellation-operator-beta-composed-m2-run-001.service",
            "controller_ssh_port": 23155,
            "target_ssh_port": 23156,
            "fixture_link_port": 24579,
            "run_bound_seconds": controller.RUN_BOUND_SECONDS,
            "working_directory": str(working),
            "runner": {
                **bound(files["runner"]),
                "subject": "c" * 40,
                "tree": "d" * 40,
            },
            "builder": {
                **bound(files["builder"]),
                "subject": "c" * 40,
                "tree": "d" * 40,
            },
            "nq_harness": {
                **bound(files["nq_harness"]),
                "subject": "e" * 40,
                "tree": "f" * 40,
                "qualified_harness_subject": "0" * 40,
            },
            "composition_subject": "1" * 40,
            "composition_tree": "2" * 40,
            "inputs": {name: bound(files[name]) for name in controller.INPUT_FIELDS},
        }
        spec_path = root / "fixed-demo-spec.json"
        raw = controller.canonical(spec) + b"\n"
        spec_path.write_bytes(raw)
        admission = mock.patch.object(controller, "ADMITTED_COHORT", controller.admitted_cohort(spec))
        admission.start()
        self.addCleanup(admission.stop)
        repository = mock.patch.object(controller, "verify_owner_repository")
        repository.start()
        self.addCleanup(repository.stop)
        return spec, spec_path, len(raw), controller.digest_bytes(raw)

    def execution_observation(self, spec, spec_sha256):
        return mock.patch.multiple(
            controller,
            process_start_ticks=mock.Mock(return_value=9001),
            process_execution=mock.Mock(
                side_effect=lambda _pid, _sha: controller.expected_execution(
                    spec, controller.runner_argv(spec), spec_sha256
                )
            ),
        )

    def test_start_is_one_manager_call_and_duplicate_is_query_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            spec, path, size, digest = self.fixture(pathlib.Path(temporary).resolve())
            manager = FakeManager()
            fixed = controller.FixedController(path, size, digest, manager)
            with self.execution_observation(spec, digest):
                first = fixed.start()
                second = fixed.start()
            self.assertEqual(manager.starts, 1)
            self.assertEqual(first["durable"]["state"], "STARTED_AWAITING_RUNNER_CUSTODY")
            self.assertEqual(second, first)
            self.assertEqual(manager.argv, controller.runner_argv(spec))
            state = pathlib.Path(spec["state_root"])
            self.assertTrue((state / "launch-intent.v1.json").is_file())
            self.assertTrue((state / "launch-accepted.v1.json").is_file())

    def test_systemd_launch_envelope_is_fixed_and_nonblocking(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            spec, _path, _size, digest = self.fixture(pathlib.Path(temporary).resolve())
            argv = controller.runner_argv(spec)
            completed = mock.Mock(returncode=0, stdout=b"", stderr=b"")
            with mock.patch.object(controller.subprocess, "run", return_value=completed) as run:
                controller.SystemdUserManager().start(spec, argv, digest)
            command = run.call_args.args[0]
            self.assertEqual(command[:5], ["systemd-run", "--user", "--quiet", "--no-block", "--collect"])
            self.assertEqual(command[command.index("--unit") + 1], spec["producer_unit"])
            self.assertIn(f"WorkingDirectory={spec['working_directory']}", command)
            self.assertIn("RuntimeMaxSec=7200", command)
            self.assertIn("TimeoutStopSec=30", command)
            self.assertIn(f"CONSTELLATION_FIXED_DEMO_SPEC_SHA256={digest}", command)
            self.assertEqual(command[command.index("--") + 1 :], argv)

    def test_concurrent_starts_serialize_to_one_manager_call(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            spec, path, size, digest = self.fixture(pathlib.Path(temporary).resolve())
            manager = FakeManager(delay=0.1)
            outcomes = []
            errors = []

            def invoke() -> None:
                try:
                    outcomes.append(controller.FixedController(path, size, digest, manager).start())
                except Exception as error:  # pragma: no cover - asserted below
                    errors.append(error)

            with self.execution_observation(spec, digest):
                threads = [threading.Thread(target=invoke) for _ in range(2)]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()
            self.assertEqual(errors, [])
            self.assertEqual(manager.starts, 1)
            self.assertEqual(len(outcomes), 2)
            self.assertEqual({item["subject"]["run_id"] for item in outcomes}, {spec["run_id"]})

    def test_durable_intent_cut_forbids_a_second_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            spec, path, size, digest = self.fixture(pathlib.Path(temporary).resolve())
            manager = FakeManager()

            def cut(name: str) -> None:
                if name == "intent_durable":
                    raise RuntimeError("controller stopped after durable intent")

            fixed = controller.FixedController(path, size, digest, manager, cut)
            with self.assertRaisesRegex(RuntimeError, "durable intent"):
                fixed.start()
            with self.execution_observation(spec, digest):
                reopened = controller.FixedController(path, size, digest, manager).start()
            self.assertEqual(manager.starts, 0)
            self.assertEqual(reopened["durable"]["state"], "INDETERMINATE")
            self.assertEqual(reopened["liveness"]["state"], "PROCESS_EXITED")

    def test_acknowledgement_loss_exposes_activity_without_second_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            spec, path, size, digest = self.fixture(pathlib.Path(temporary).resolve())
            manager = FakeManager(lose_acknowledgement=True)
            with self.assertRaises(TimeoutError), self.execution_observation(spec, digest):
                controller.FixedController(path, size, digest, manager).start()
            with self.execution_observation(spec, digest):
                reopened = controller.FixedController(path, size, digest, manager).start()
            self.assertEqual(manager.starts, 1)
            self.assertEqual(reopened["durable"]["state"], "INDETERMINATE")
            self.assertEqual(reopened["liveness"]["state"], "PROCESS_ACTIVE")

    def test_spec_content_and_state_root_replacement_refuse(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            _spec, path, size, digest = self.fixture(root)
            path.write_bytes(path.read_bytes() + b" ")
            with self.assertRaisesRegex(controller.Refusal, "length differs"):
                controller.FixedController(path, size, digest, FakeManager()).status()

    def test_wrong_spec_digest_and_partial_intent_never_call_manager(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            spec, path, size, _digest = self.fixture(root)
            manager = FakeManager()
            with self.assertRaisesRegex(controller.Refusal, "digest differs"):
                controller.FixedController(path, size, "9" * 64, manager).start()
            self.assertEqual(manager.starts, 0)

            intent = pathlib.Path(spec["state_root"]) / "launch-intent.v1.json"
            intent.write_bytes(b'{"schema":')
            os.chmod(intent, 0o400)
            digest = controller.digest_path(path)
            with self.assertRaisesRegex(controller.Refusal, "launch intent"):
                controller.FixedController(path, size, digest, manager).start()
            self.assertEqual(manager.starts, 0)
            projection = controller.FixedController(path, size, digest, manager).status()
            self.assertEqual(projection["durable"]["state"], "INDETERMINATE")

    def test_liveness_unavailable_does_not_change_not_started_durable_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _spec, path, size, digest = self.fixture(pathlib.Path(temporary).resolve())
            projection = controller.FixedController(
                path, size, digest, UnobservableManager()
            ).status()
            self.assertEqual(projection["durable"]["state"], "NOT_STARTED")
            self.assertEqual(projection["liveness"]["state"], "NOT_OBSERVABLE")

    def test_accepted_process_exit_is_distinct_from_nonterminal_durable_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            spec, path, size, digest = self.fixture(pathlib.Path(temporary).resolve())
            manager = FakeManager()
            with self.execution_observation(spec, digest):
                controller.FixedController(path, size, digest, manager).start()
            with mock.patch.object(
                controller,
                "process_start_ticks",
                side_effect=controller.Refusal("recorded process exited"),
            ):
                projection = controller.FixedController(
                    path, size, digest, UnobservableManager()
                ).status()
            self.assertEqual(
                projection["durable"]["state"], "STARTED_AWAITING_RUNNER_CUSTODY"
            )
            self.assertEqual(projection["liveness"]["state"], "PROCESS_EXITED")

    def test_active_process_execution_disagreement_is_not_active_implementation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            spec, path, size, digest = self.fixture(root)
            manager = FakeManager()

            def cut(name: str) -> None:
                if name == "intent_durable":
                    raise RuntimeError("cut")

            with self.assertRaises(RuntimeError):
                controller.FixedController(path, size, digest, manager, cut).start()
            manager.active = True
            with mock.patch.object(controller, "process_start_ticks", return_value=9001), mock.patch.object(
                controller,
                "process_execution",
                return_value={"argv": ["different"], "working_directory": "/", "environment": {}},
            ):
                projection = controller.FixedController(path, size, digest, manager).status()
            self.assertEqual(projection["durable"]["state"], "INDETERMINATE")
            self.assertEqual(projection["liveness"]["state"], "PROCESS_ACTIVE")
            self.assertIn(
                "active manager process differs from the fixed execution",
                projection["disagreements"],
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            spec, path, size, digest = self.fixture(root)
            state = pathlib.Path(spec["state_root"])
            state.rename(root / "replaced-state")
            state.mkdir(mode=0o700)
            with self.assertRaisesRegex(controller.Refusal, "identity differs"):
                controller.FixedController(path, size, digest, FakeManager()).status()

    def test_intent_and_acceptance_substitution_are_visible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            spec, path, size, digest = self.fixture(root)
            manager = FakeManager()
            with self.execution_observation(spec, digest):
                controller.FixedController(path, size, digest, manager).start()
            state = pathlib.Path(spec["state_root"])
            accepted_path = state / "launch-accepted.v1.json"
            accepted = json.loads(accepted_path.read_bytes())
            accepted["run_id"] = "other"
            os.chmod(accepted_path, 0o600)
            accepted_path.write_bytes(controller.canonical(accepted) + b"\n")
            os.chmod(accepted_path, 0o400)
            with self.execution_observation(spec, digest):
                projection = controller.FixedController(path, size, digest, manager).status()
            self.assertEqual(projection["durable"]["state"], "INDETERMINATE")
            self.assertIn("launch acceptance names another occurrence", projection["disagreements"])


if __name__ == "__main__":
    unittest.main()
