//! Real-process qualification for the Docket-owned executor host.

use gwr_local::executor_process;
use gwr_local::governed_loop::{
    ExecutorDispatchWireV1, ExecutorOutcomeWireV1, MAX_EXECUTOR_DOCUMENT_BYTES,
};
use gwr_runtime::governed_loop::hash_domain;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

struct Fixture {
    root: PathBuf,
    state_database: PathBuf,
    operation_log: PathBuf,
    adapter_config: PathBuf,
    host_config: PathBuf,
    adapter_program: PathBuf,
    staged_path: PathBuf,
    adapter_pid: PathBuf,
    release_adapter: PathBuf,
}

impl Fixture {
    fn new(execute_behavior: &str, reconcile_behavior: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "docket-river-clerk-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let state_database = root.join("executor.sqlite");
        let operation_log = root.join("operations.log");
        let adapter_config = root.join("adapter.json");
        let host_config = root.join("host.json");
        let adapter_program = root.join("fixture-adapter");
        let adapter_pid = root.join("adapter.pid");
        let release_adapter = root.join("release-adapter");
        std::fs::copy(
            env!("CARGO_BIN_EXE_docket-local-executor-fixture-adapter"),
            &adapter_program,
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&adapter_program).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&adapter_program, permissions).unwrap();
        let program_digest = hash_domain(
            "docket.local-governed-executor.adapter-program/v1",
            &std::fs::read(&adapter_program).unwrap(),
        );
        let staged_path = root
            .join(".docket-governed-executor-programs")
            .join(program_digest.strip_prefix("sha256:").unwrap());

        let adapter = json!({
            "schema": executor_process::LOCAL_EXECUTOR_ADAPTER_SCHEMA_V1,
            "state_database": state_database,
            "operation_log": operation_log,
            "require_reservation": true,
            "source_program": adapter_program,
            "source_config": adapter_config,
            "staged_path": staged_path,
            "adapter_pid": adapter_pid,
            "release_adapter": release_adapter,
            "execute_behavior": execute_behavior,
            "execute_receipt": digest('6'),
            "reconcile_behavior": reconcile_behavior,
            "reconcile_receipt": digest('7'),
        });
        std::fs::write(&adapter_config, serde_json::to_vec(&adapter).unwrap()).unwrap();
        let host = json!({
            "schema": executor_process::LOCAL_EXECUTOR_CONFIG_SCHEMA_V1,
            "state_database": state_database,
            "work_schema": "fixture.executor-work/v1",
            "subject": digest('4'),
            "scope": digest('5'),
            "adapter_program": adapter_program,
            "adapter_config": adapter_config,
        });
        std::fs::write(&host_config, serde_json::to_vec(&host).unwrap()).unwrap();
        Self {
            root,
            state_database,
            operation_log,
            adapter_config,
            host_config,
            adapter_program,
            staged_path,
            adapter_pid,
            release_adapter,
        }
    }

    fn plan_id(&self) -> String {
        let output = Command::new(env!("CARGO_BIN_EXE_docket-governed-executor"))
            .args(["plan-id", self.host_config.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn dispatch(&self) -> ExecutorDispatchWireV1 {
        ExecutorDispatchWireV1 {
            attempt: digest('1'),
            marker: digest('2'),
            work_schema: "fixture.executor-work/v1".to_owned(),
            work: self.plan_id(),
            subject: digest('4'),
            scope: digest('5'),
        }
    }

    fn invoke(&self, operation: &str, dispatch: &ExecutorDispatchWireV1) -> Output {
        let child = self.spawn(operation, dispatch);
        child.wait_with_output().unwrap()
    }

    fn spawn(&self, operation: &str, dispatch: &ExecutorDispatchWireV1) -> Child {
        let mut child = Command::new(env!("CARGO_BIN_EXE_docket-governed-executor"))
            .args([operation, self.host_config.to_str().unwrap()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(dispatch).unwrap())
            .unwrap();
        child
    }

    fn operations(&self) -> Vec<String> {
        match std::fs::read_to_string(&self.operation_log) {
            Ok(value) => value.lines().map(str::to_owned).collect(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => panic!("read operation log: {error}"),
        }
    }

    fn wait_for_operations(&self, expected: &[&str]) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let operations = self.operations();
            if operations == expected {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {expected:?}; observed {operations:?}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait_for_adapter_pid(&self) -> u32 {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(text) = std::fs::read_to_string(&self.adapter_pid) {
                return text.trim().parse().unwrap();
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for adapter pid"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn release_adapter(&self) {
        std::fs::write(&self.release_adapter, b"release\n").unwrap();
    }

    fn wait_for_pid_exit(&self, pid: u32) {
        let deadline = Instant::now() + Duration::from_secs(5);
        let process = PathBuf::from(format!("/proc/{pid}"));
        while process.exists() {
            assert!(
                Instant::now() < deadline,
                "adapter process {pid} remained live"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::write(&self.release_adapter, b"release\n");
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn outcome(output: &Output) -> ExecutorOutcomeWireV1 {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn plan_identity_is_content_bound_and_plan_id_creates_no_state() {
    let fixture = Fixture::new("success", "success");
    let first = fixture.plan_id();
    assert!(first.starts_with("sha256:"));
    assert!(!fixture.state_database.exists());

    let mut config: Value =
        serde_json::from_slice(&std::fs::read(&fixture.adapter_config).unwrap()).unwrap();
    config["execute_receipt"] = Value::String(digest('8'));
    std::fs::write(
        &fixture.adapter_config,
        serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    assert_ne!(first, fixture.plan_id());
    assert!(!fixture.state_database.exists());
}

#[test]
fn reservation_precedes_effect_and_terminal_replay_is_inert_and_byte_exact() {
    let fixture = Fixture::new("success", "failure");
    let dispatch = fixture.dispatch();
    let first = fixture.invoke("execute", &dispatch);
    let first_outcome = outcome(&first);
    assert_eq!(
        first_outcome.outcome,
        gwr_local::governed_loop::ExecutorOutcomeClassWireV1::Success
    );
    assert_eq!(fixture.operations(), ["execute"]);

    let replay = fixture.invoke("execute", &dispatch);
    assert!(replay.status.success());
    assert_eq!(first.stdout, replay.stdout);
    assert_eq!(fixture.operations(), ["execute"]);
    let text = String::from_utf8(first.stdout).unwrap();
    assert_eq!(
        text,
        format!(
            "{{\"attempt\":\"{}\",\"marker\":\"{}\",\"outcome\":\"success\",\"receipt\":\"{}\"}}\n",
            dispatch.attempt,
            dispatch.marker,
            digest('6')
        )
    );
    let connection = Connection::open(&fixture.state_database).unwrap();
    let (row_count, status): (i64, String) = connection
        .query_row(
            "SELECT COUNT(*), MIN(status) FROM local_governed_executor_attempt",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(row_count, 1);
    assert_eq!(status, "settled");
}

#[test]
fn changed_binding_on_consumed_attempt_refuses_without_adapter_access() {
    let fixture = Fixture::new("success", "success");
    let dispatch = fixture.dispatch();
    assert!(fixture.invoke("execute", &dispatch).status.success());
    let mut changed = dispatch.clone();
    changed.marker = digest('9');
    let output = fixture.invoke("execute", &changed);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("attempt-substitution"));
    assert_eq!(fixture.operations(), ["execute"]);
}

#[test]
fn transport_refusal_leaves_one_reservation_and_reconcile_never_reexecutes() {
    let fixture = Fixture::new("refuse", "success");
    let dispatch = fixture.dispatch();
    let first = fixture.invoke("execute", &dispatch);
    assert!(!first.status.success());
    assert!(first.stdout.is_empty());
    assert_eq!(fixture.operations(), ["execute"]);

    let replay = fixture.invoke("execute", &dispatch);
    assert!(!replay.status.success());
    assert!(String::from_utf8_lossy(&replay.stderr).contains("reconciliation-required"));
    assert_eq!(fixture.operations(), ["execute"]);

    let reconciled = outcome(&fixture.invoke("reconcile", &dispatch));
    assert_eq!(reconciled.receipt, digest('7'));
    assert_eq!(fixture.operations(), ["execute", "reconcile"]);

    let terminal = fixture.invoke("reconcile", &dispatch);
    assert!(terminal.status.success());
    assert_eq!(fixture.operations(), ["execute", "reconcile"]);
}

#[test]
fn indeterminate_is_replayed_without_mechanics_and_can_later_settle() {
    let fixture = Fixture::new("indeterminate", "failure");
    let dispatch = fixture.dispatch();
    let first = outcome(&fixture.invoke("execute", &dispatch));
    assert_eq!(
        first.outcome,
        gwr_local::governed_loop::ExecutorOutcomeClassWireV1::Indeterminate
    );
    let replay = outcome(&fixture.invoke("execute", &dispatch));
    assert_eq!(first, replay);
    assert_eq!(fixture.operations(), ["execute"]);

    let settled = outcome(&fixture.invoke("reconcile", &dispatch));
    assert_eq!(
        settled.outcome,
        gwr_local::governed_loop::ExecutorOutcomeClassWireV1::Failure
    );
    assert_eq!(fixture.operations(), ["execute", "reconcile"]);
}

#[test]
fn terminated_adapter_is_outcome_unknown_until_reconciliation() {
    let fixture = Fixture::new("cancel", "success");
    let dispatch = fixture.dispatch();
    let cancelled = fixture.invoke("execute", &dispatch);
    assert!(!cancelled.status.success());
    assert!(cancelled.stdout.is_empty());
    assert_eq!(fixture.operations(), ["execute"]);

    let reconciled = outcome(&fixture.invoke("reconcile", &dispatch));
    assert_eq!(
        reconciled.outcome,
        gwr_local::governed_loop::ExecutorOutcomeClassWireV1::Success
    );
    assert_eq!(fixture.operations(), ["execute", "reconcile"]);
}

#[test]
fn changed_adapter_outcome_binding_is_not_retained_and_reconcile_can_settle() {
    let fixture = Fixture::new("substitute_marker", "success");
    let dispatch = fixture.dispatch();
    let substituted = fixture.invoke("execute", &dispatch);
    assert!(!substituted.status.success());
    assert!(String::from_utf8_lossy(&substituted.stderr).contains("outcome-substitution"));
    assert_eq!(fixture.operations(), ["execute"]);

    let reconciled = outcome(&fixture.invoke("reconcile", &dispatch));
    assert_eq!(reconciled.marker, dispatch.marker);
    assert_eq!(fixture.operations(), ["execute", "reconcile"]);
}

#[test]
fn concurrent_duplicate_dispatch_invokes_one_adapter_execute() {
    let fixture = Fixture::new("slow_success", "success");
    let dispatch = fixture.dispatch();
    let first = fixture.spawn("execute", &dispatch);
    std::thread::sleep(Duration::from_millis(50));
    let duplicate = fixture.invoke("execute", &dispatch);
    let first = first.wait_with_output().unwrap();
    assert!(first.status.success());
    assert!(duplicate.status.success());
    assert_eq!(first.stdout, duplicate.stdout);
    assert!(duplicate.stderr.is_empty());
    assert_eq!(fixture.operations(), ["execute"]);
}

#[test]
fn reconcile_missing_attempt_is_state_free_and_does_not_invoke_adapter() {
    let fixture = Fixture::new("success", "success");
    let dispatch = fixture.dispatch();
    let output = fixture.invoke("reconcile", &dispatch);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!fixture.state_database.exists());
    assert!(fixture.operations().is_empty());
}

#[test]
fn reconcile_refuses_while_execute_mechanics_are_live() {
    let fixture = Fixture::new("wait_for_release", "success");
    let dispatch = fixture.dispatch();
    let execute = fixture.spawn("execute", &dispatch);
    fixture.wait_for_operations(&["execute"]);

    let concurrent = fixture.invoke("reconcile", &dispatch);
    assert!(!concurrent.status.success());
    assert!(concurrent.stdout.is_empty());
    assert!(String::from_utf8_lossy(&concurrent.stderr).contains("operation-in-flight"));
    assert_eq!(fixture.operations(), ["execute"]);

    fixture.release_adapter();
    let completed = execute.wait_with_output().unwrap();
    assert!(completed.status.success());
    let terminal = fixture.invoke("reconcile", &dispatch);
    assert!(terminal.status.success());
    assert_eq!(fixture.operations(), ["execute"]);
}

#[test]
fn child_held_fence_survives_host_sigkill_until_mechanics_exit() {
    let fixture = Fixture::new("wait_for_release", "success");
    let dispatch = fixture.dispatch();
    let mut host = fixture.spawn("execute", &dispatch);
    fixture.wait_for_operations(&["execute"]);
    let adapter_pid = fixture.wait_for_adapter_pid();
    assert_ne!(host.id(), adapter_pid);

    host.kill().unwrap();
    let killed = host.wait_with_output().unwrap();
    assert!(!killed.status.success());
    assert!(Path::new(&format!("/proc/{adapter_pid}")).exists());

    let while_orphan_mechanics_live = fixture.invoke("reconcile", &dispatch);
    assert!(!while_orphan_mechanics_live.status.success());
    assert!(while_orphan_mechanics_live.stdout.is_empty());
    assert!(String::from_utf8_lossy(&while_orphan_mechanics_live.stderr)
        .contains("operation-in-flight"));
    assert_eq!(fixture.operations(), ["execute"]);

    fixture.release_adapter();
    fixture.wait_for_pid_exit(adapter_pid);
    let reconciled = fixture.invoke("reconcile", &dispatch);
    assert!(reconciled.status.success());
    assert_eq!(fixture.operations(), ["execute", "reconcile"]);
}

#[test]
fn staged_pathname_replacement_cannot_change_opened_executable() {
    let fixture = Fixture::new("replace_staged_and_refuse", "success");
    let dispatch = fixture.dispatch();
    let first = fixture.invoke("execute", &dispatch);
    assert!(!first.status.success());
    assert!(first.stdout.is_empty());
    assert_eq!(fixture.operations(), ["execute"]);
    assert_eq!(
        std::fs::read(&fixture.staged_path).unwrap(),
        b"unbound staged pathname fixture\n"
    );

    let reconcile = fixture.invoke("reconcile", &dispatch);
    assert!(!reconcile.status.success());
    assert!(reconcile.stdout.is_empty());
    assert!(String::from_utf8_lossy(&reconcile.stderr).contains("staged-program-substitution"));
    assert_eq!(fixture.operations(), ["execute"]);
}

#[test]
fn source_pathname_replacement_cannot_change_resolved_invocation() {
    let fixture = Fixture::new("replace_sources_and_refuse", "success");
    let dispatch = fixture.dispatch();
    let first = fixture.invoke("execute", &dispatch);
    assert!(!first.status.success());
    assert!(first.stdout.is_empty());
    assert_eq!(fixture.operations(), ["execute"]);
    assert_eq!(
        std::fs::read(&fixture.adapter_program).unwrap(),
        b"unbound source program fixture\n"
    );
    assert_eq!(std::fs::read(&fixture.adapter_config).unwrap(), b"{}\n");

    let reconcile = fixture.invoke("reconcile", &dispatch);
    assert!(!reconcile.status.success());
    assert!(reconcile.stdout.is_empty());
    assert_eq!(fixture.operations(), ["execute"]);
}

#[test]
fn duplicate_adapter_outcome_key_is_strictly_refused() {
    let fixture = Fixture::new("duplicate_outcome", "success");
    let dispatch = fixture.dispatch();
    let duplicate = fixture.invoke("execute", &dispatch);
    assert!(!duplicate.status.success());
    assert!(duplicate.stdout.is_empty());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("duplicate field"));
    assert_eq!(fixture.operations(), ["execute"]);

    let reconciled = fixture.invoke("reconcile", &dispatch);
    assert!(reconciled.status.success());
    assert_eq!(fixture.operations(), ["execute", "reconcile"]);
}

#[test]
fn invalid_preexisting_state_content_refuses_before_adapter() {
    let fixture = Fixture::new("success", "success");
    let dispatch = fixture.dispatch();
    std::fs::write(&fixture.state_database, b"not a sqlite database\n").unwrap();
    std::fs::set_permissions(
        &fixture.state_database,
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let output = fixture.invoke("execute", &dispatch);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(fixture.operations().is_empty());
}

#[test]
fn operation_fence_pathname_replacement_refuses_before_reconcile() {
    let fixture = Fixture::new("refuse", "success");
    let dispatch = fixture.dispatch();
    let execute = fixture.invoke("execute", &dispatch);
    assert!(!execute.status.success());
    assert_eq!(fixture.operations(), ["execute"]);

    let fence = fixture
        .root
        .join(".docket-governed-executor-operation-fences")
        .join("1".repeat(64));
    let replacement = fence.with_extension("replacement");
    std::fs::write(&replacement, b"replacement fence inode\n").unwrap();
    std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::rename(replacement, fence).unwrap();

    let reconcile = fixture.invoke("reconcile", &dispatch);
    assert!(!reconcile.status.success());
    assert!(reconcile.stdout.is_empty());
    assert!(String::from_utf8_lossy(&reconcile.stderr).contains("fence-substitution"));
    assert_eq!(fixture.operations(), ["execute"]);
}
#[test]
fn canonical_dispatch_corpus_is_accepted_or_refused_without_actuation() {
    let corpus_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/executor-transport-v1/corpus.json");
    let corpus: Value = serde_json::from_slice(&std::fs::read(corpus_path).unwrap()).unwrap();
    for case in corpus["decode_cases"].as_array().unwrap() {
        if case["kind"] != "dispatch" {
            continue;
        }
        let input = case["input"].as_str().unwrap().as_bytes();
        let decoded = executor_process::decode_dispatch(input);
        match case["expect"].as_str().unwrap() {
            "accept" => {
                let decoded = decoded
                    .unwrap_or_else(|error| panic!("{} unexpectedly refused: {error}", case["id"]));
                if let Some(expected) = case.get("canonical_output") {
                    let projected =
                        serde_json::to_string(&serde_json::to_value(decoded).unwrap()).unwrap();
                    assert_eq!(projected, expected.as_str().unwrap(), "{}", case["id"]);
                }
            }
            "refuse" => assert!(decoded.is_err(), "{} unexpectedly accepted", case["id"]),
            value => panic!("unknown corpus expectation {value}"),
        }
    }
    assert!(
        executor_process::decode_dispatch(&vec![b' '; MAX_EXECUTOR_DOCUMENT_BYTES + 1]).is_err()
    );
}
