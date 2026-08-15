use gwr_local::governed_loop::{
    accept, reconcile_signed_round_with_checkpoint_verifier, AdmissionDecisionWireV1,
    AdmissionDispositionWireV1, AgIssuanceWireV2, AgIssuerTrustConfigV1,
    CanonicalEffectOperationWireV1, CanonicalEffectResourceWireV1, CanonicalEffectScopeWireV1,
    DocketExecutionResponseWireV1, DocketReconciliationRoundStateWireV1,
    ExecutionStandingResolutionV1, ExecutionStandingStatusV1, IssuanceAuthenticationWireV1,
    OccurrenceKeyWireV1, ReconciliationRoundRequestWireV1, SignedIssuanceEnvelopeWireV1,
    SignedReconciliationRoundRequestEnvelopeWireV1, TrustedAgIssuerV1, AG_ISSUANCE_SCHEMA_V2,
    RECONCILIATION_ROUND_REQUEST_SCHEMA_V1, SIGNED_ISSUANCE_SCHEMA_V2,
    SIGNED_RECONCILIATION_ROUND_REQUEST_SCHEMA_V1, STANDING_RESOLUTION_SCHEMA_V1,
};
use gwr_local::store::SqliteStore;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use rusqlite::{params, Connection};
use sha2::{Digest as _, Sha256};
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

const ISSUANCE_PREFIX: &[u8] = b"ag-ng\0governed-loop-issuance-signature\0v2\0";
const ROUND_PREFIX: &[u8] = b"ag-ng\0governed-loop-reconciliation-round-signature\0v1\0";
const MAX_SAFE: u64 = 9_007_199_254_740_991;
static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

struct Fixture {
    root: PathBuf,
    state: PathBuf,
    trust_path: PathBuf,
    standing_program: PathBuf,
    executor: PathBuf,
    config: PathBuf,
    issuance_envelope: Vec<u8>,
    envelope: Vec<u8>,
    effectd_store: Option<PathBuf>,
}

enum ExecutorFixture {
    Shell,
    ActualAgEffectd(PathBuf),
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn two_processes_make_one_physical_reconciliation_call() {
    concurrent_duplicate_round(2);
}

#[test]
fn eight_processes_make_one_physical_reconciliation_call() {
    concurrent_duplicate_round(8);
}

#[test]
fn initial_execute_and_explicit_round_race_resolves_from_one_durable_source() {
    let fixture = fixture_with_executor_and_acceptance(ExecutorFixture::Shell, false);
    write_mixed_process_executor(&fixture);
    let executable = env!("CARGO_BIN_EXE_docket");
    let mut initial = Command::new(executable)
        .args([
            "governed-loop",
            "accept",
            "--state",
            fixture.state.to_str().unwrap(),
            "--trust",
            fixture.trust_path.to_str().unwrap(),
            "--standing-resolver",
            fixture.standing_program.to_str().unwrap(),
            "--executor",
            fixture.executor.to_str().unwrap(),
            "--executor-config",
            fixture.config.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    initial
        .stdin
        .take()
        .unwrap()
        .write_all(&fixture.issuance_envelope)
        .unwrap();
    wait_for_path(&fixture.executor.with_extension("execute-started"));

    let mut round = Command::new(executable)
        .args([
            "governed-loop",
            "reconcile-attempt",
            "--state",
            fixture.state.to_str().unwrap(),
            "--trust",
            fixture.trust_path.to_str().unwrap(),
            "--executor",
            fixture.executor.to_str().unwrap(),
            "--executor-config",
            fixture.config.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    round
        .stdin
        .take()
        .unwrap()
        .write_all(&fixture.envelope)
        .unwrap();
    wait_for_path(&fixture.executor.with_extension("reconcile-started"));

    std::fs::write(
        fixture.executor.with_extension("execute-release"),
        b"release",
    )
    .unwrap();
    let initial = initial.wait_with_output().unwrap();
    assert!(
        initial.status.success(),
        "initial process refused: {}",
        String::from_utf8_lossy(&initial.stderr)
    );
    std::fs::write(
        fixture.executor.with_extension("reconcile-release"),
        b"release",
    )
    .unwrap();
    let round = round.wait_with_output().unwrap();
    assert!(
        round.status.success(),
        "round process refused: {}",
        String::from_utf8_lossy(&round.stderr)
    );
    let response: serde_json::Value = serde_json::from_slice(&round.stdout).unwrap();
    assert_eq!(response["status"], "completed");
    assert_eq!(response["record"]["response"]["status"], "indeterminate");
    assert_eq!(
        std::fs::read(fixture.executor.with_extension("execute-calls")).unwrap(),
        b"x"
    );
    assert_eq!(
        std::fs::read(fixture.executor.with_extension("calls")).unwrap(),
        b"x",
        "mixed initial/round race must make exactly one physical reconciliation call"
    );

    let mut replay = Command::new(executable)
        .args([
            "governed-loop",
            "reconcile-attempt",
            "--state",
            fixture.state.to_str().unwrap(),
            "--trust",
            fixture.trust_path.to_str().unwrap(),
            "--executor",
            fixture.executor.to_str().unwrap(),
            "--executor-config",
            fixture.config.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    replay
        .stdin
        .take()
        .unwrap()
        .write_all(&fixture.envelope)
        .unwrap();
    let replay = replay.wait_with_output().unwrap();
    assert!(replay.status.success());
    assert_eq!(replay.stdout, round.stdout);
    assert_eq!(
        std::fs::read(fixture.executor.with_extension("calls")).unwrap(),
        b"x"
    );
}

#[test]
#[ignore = "requires exact adjacent AG R5 ag-effectd binary in AG_EFFECTD_BIN"]
fn actual_ag_effectd_consumes_the_exact_docket_reconciliation_wrapper() {
    let effectd = PathBuf::from(std::env::var_os("AG_EFFECTD_BIN").expect("AG_EFFECTD_BIN"));
    assert!(effectd.is_absolute());
    let fixture = fixture_with_executor(ExecutorFixture::ActualAgEffectd(effectd));
    let first = reconcile_signed_round_with_checkpoint_verifier(
        &fixture.state.join("state.sqlite"),
        &fixture.envelope,
        &std::fs::read(&fixture.trust_path).unwrap(),
        &fixture.executor,
        &fixture.config,
        None,
    )
    .unwrap();
    assert!(matches!(
        first.state,
        DocketReconciliationRoundStateWireV1::Completed { .. }
    ));
    let store = fixture.effectd_store.as_ref().unwrap();
    let connection = Connection::open(store).unwrap();
    let (contexts, dispatch_jcs): (i64, Vec<u8>) = connection
        .query_row(
            "SELECT COUNT(*),dispatch_jcs FROM docket_reconciliation_context",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(contexts, 1);
    let dispatch: serde_json::Value = serde_json::from_slice(&dispatch_jcs).unwrap();
    assert_eq!(
        dispatch["schema"],
        "docket.governed-loop.executor-reconciliation-dispatch/v1"
    );
    assert!(dispatch["dispatch"].is_object());
    drop(connection);

    let replay = reconcile_signed_round_with_checkpoint_verifier(
        &fixture.state.join("state.sqlite"),
        &fixture.envelope,
        &std::fs::read(&fixture.trust_path).unwrap(),
        &fixture.executor,
        &fixture.config,
        None,
    )
    .unwrap();
    assert_eq!(replay, first);
    let connection = Connection::open(store).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM docket_reconciliation_context",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1,
        "Docket durable replay must not call ag-effectd a second time"
    );
}

fn concurrent_duplicate_round(fanout: usize) {
    assert!(fanout >= 2);
    let fixture = fixture();
    let executable = env!("CARGO_BIN_EXE_docket");
    let spawn = || {
        let mut child = Command::new(executable)
            .args([
                "governed-loop",
                "reconcile-attempt",
                "--state",
                fixture.state.to_str().unwrap(),
                "--trust",
                fixture.trust_path.to_str().unwrap(),
                "--executor",
                fixture.executor.to_str().unwrap(),
                "--executor-config",
                fixture.config.to_str().unwrap(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&fixture.envelope)
            .unwrap();
        child
    };

    // Hold the claim winner inside the external adapter so every other
    // process necessarily observes the durable claimed row rather than a
    // conveniently completed replay.
    let mut winner = Some(spawn());
    let calls = fixture.executor.with_extension("calls");
    // A fresh CLI process also runs the bounded SQLite migration/open path;
    // allow more than its five-second writer-contention budget before
    // classifying absence of the external call as failure.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while !calls.exists() {
        if std::time::Instant::now() >= deadline {
            std::fs::write(fixture.executor.with_extension("release"), b"release").unwrap();
            let output = winner.take().unwrap().wait_with_output().unwrap();
            let entries = std::fs::read_dir(&fixture.root)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            panic!(
                "claim winner never crossed the external reconciliation boundary; status={:?}; entries={entries:?}; program={}; operations={}; stdout={}; stderr={}",
                output.status.code(),
                std::fs::read_to_string(&fixture.executor).unwrap(),
                std::fs::read_to_string(fixture.executor.with_extension("operations"))
                    .unwrap_or_else(|error| format!("unavailable:{error}")),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let losers = (1..fanout).map(|_| spawn()).collect::<Vec<_>>();
    let mut loser_outputs = Vec::new();
    for child in losers {
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "concurrent Docket process refused unexpectedly: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["status"], "unresolved");
        loser_outputs.push(value);
    }
    assert_eq!(loser_outputs.len(), fanout - 1);
    std::fs::write(fixture.executor.with_extension("release"), b"release").unwrap();
    let output = winner.take().unwrap().wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "claim winner refused unexpectedly: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let winner_value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(winner_value["status"], "completed");
    assert_eq!(
        std::fs::read(fixture.executor.with_extension("calls")).unwrap(),
        b"x"
    );
    assert_eq!(
        std::fs::read(fixture.executor.with_extension("plans")).unwrap(),
        b"x",
        "acceptance alone may invoke plan-id; reconciliation losers must not"
    );
}

fn fixture() -> Fixture {
    fixture_with_executor(ExecutorFixture::Shell)
}

fn fixture_with_executor(executor_fixture: ExecutorFixture) -> Fixture {
    fixture_with_executor_and_acceptance(executor_fixture, true)
}

fn fixture_with_executor_and_acceptance(
    executor_fixture: ExecutorFixture,
    accept_now: bool,
) -> Fixture {
    let root = std::env::temp_dir().join(format!(
        "docket-r4-reconcile-process-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let state = root.join("state");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let database = state.join("state.sqlite");
    drop(SqliteStore::open(&database).unwrap());

    let actual_effectd = matches!(executor_fixture, ExecutorFixture::ActualAgEffectd(_));
    let operation = if actual_effectd {
        CanonicalEffectOperationWireV1::Create
    } else {
        CanonicalEffectOperationWireV1::Modify
    };
    let scope = CanonicalEffectScopeWireV1 {
        schema: "ag.governed-loop.canonical-effect-scope/v1".to_owned(),
        effect_class: "repository-write/v1".to_owned(),
        resources: vec![CanonicalEffectResourceWireV1 {
            resource: "repository".to_owned(),
            path: "fixture/path".to_owned(),
            operations: vec![operation],
        }],
    };
    let scope_identity = hash_domain(
        "ag.governed-loop.canonical-effect-scope/v1",
        &serde_jcs::to_vec(&scope).unwrap(),
    );
    let key = OccurrenceKeyWireV1 {
        campaign: digest("campaign"),
        occurrence: "00000000-0000-0000-0000-000000000777".to_owned(),
    };
    let subject = digest("subject");
    let (executor, config, work_schema, work, effectd_store) = match &executor_fixture {
        ExecutorFixture::Shell => {
            let executor = root.join("executor");
            let config = root.join("executor-config");
            let work = digest("executor-plan");
            std::fs::write(&config, work.as_bytes()).unwrap();
            (
                executor,
                config,
                "fixture.executor/v1".to_owned(),
                work,
                None,
            )
        }
        ExecutorFixture::ActualAgEffectd(executor) => {
            let artifact_path = root.join("effect-artifact");
            let artifact_bytes = b"actual-ag-effectd-process-specimen\n";
            std::fs::write(&artifact_path, artifact_bytes).unwrap();
            let content = sha256_bytes(artifact_bytes);
            let attempt_store = root.join("ag-effectd-attempt.sqlite");
            let target = root.join("actual-effect-target");
            let config = root.join("ag-effectd-plan.json");
            let plan = serde_json::json!({
                "artifacts": [{"digest": content, "path": artifact_path}],
                "attempt_store": attempt_store,
                "effect": {
                    "content": content,
                    "expected_content": null,
                    "gid": std::fs::metadata(&root).unwrap().gid(),
                    "kind": "managed_file_put",
                    "mode": 384,
                    "path": target,
                    "target": "docket-r4-actual-ag-effectd",
                    "uid": std::fs::metadata(&root).unwrap().uid()
                },
                "effect_index": 0,
                "file_policy": {
                    "max_content_bytes": 1024,
                    "require_private_parent_writes": true,
                    "trusted_ancestor_uid": std::fs::metadata("/").unwrap().uid(),
                    "trusted_parent_uid": std::fs::metadata(&root).unwrap().uid()
                },
                "journal_binding": {
                    "operation": "create",
                    "path": "fixture/path",
                    "resource": "repository"
                },
                "preparation_checkpoint": null,
                "schema": "ag-effectd.docket-executor-plan/v1",
                "scope": scope_identity,
                "subject": subject
            });
            std::fs::write(&config, serde_jcs::to_vec(&plan).unwrap()).unwrap();
            let output = Command::new(executor)
                .args(["plan-id", config.to_str().unwrap()])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "actual ag-effectd rejected its fixture plan: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let work = String::from_utf8(output.stdout).unwrap().trim().to_owned();
            (
                executor.clone(),
                config,
                "ag-effectd.docket-executor-work/v1".to_owned(),
                work,
                Some(attempt_store),
            )
        }
    };
    let mut issuance = AgIssuanceWireV2 {
        schema: AG_ISSUANCE_SCHEMA_V2.to_owned(),
        issuance: digest("placeholder"),
        key: key.clone(),
        program: digest("program"),
        proposal: digest("proposal"),
        work_schema,
        work,
        nonclaims: vec![digest("fixture-not-authority")],
        expires_at_unix_ms: 4_000_000_000_000,
        subject,
        effect_scope: scope,
        effect_scope_digest: scope_identity,
        governed_repair_checkpoint: None,
        observation: digest("observation"),
        standing_resolution: digest("ag-standing"),
        admission_decision: AdmissionDecisionWireV1 {
            decision: digest("decision"),
            key,
            observation: digest("observation"),
            proposal: digest("proposal"),
            standing_resolution: digest("ag-standing"),
            disposition: AdmissionDispositionWireV1::Admitted,
            policy_basis: digest("policy"),
        },
        mandate: digest("mandate"),
        spend: digest("spend"),
    };
    issuance.issuance = issuance_identity(&issuance);
    let attempt = hash_domain(
        "ag.governed-loop.docket-attempt/v1",
        &serde_jcs::to_vec(&issuance.issuance).unwrap(),
    );
    let marker = hash_domain(
        "docket.governed-loop.executor-marker/v1",
        attempt.as_bytes(),
    );

    let signing_document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let signing_key = Ed25519KeyPair::from_pkcs8(signing_document.as_ref()).unwrap();
    let public_key = b64(signing_key.public_key().as_ref());
    let authentication = |prefix: &[u8], body: &[u8]| {
        let mut signed = prefix.to_vec();
        signed.extend_from_slice(body);
        IssuanceAuthenticationWireV1 {
            issuer_principal: "ag.fixture".to_owned(),
            signer_key_id: "ag-fixture-key".to_owned(),
            signer_public_key: public_key.clone(),
            signature: b64(signing_key.sign(&signed).as_ref()),
        }
    };
    let issuance_body = serde_jcs::to_vec(&issuance).unwrap();
    let issuance_envelope = serde_jcs::to_vec(&SignedIssuanceEnvelopeWireV1 {
        schema: SIGNED_ISSUANCE_SCHEMA_V2.to_owned(),
        body_b64: b64(&issuance_body),
        authentication: authentication(ISSUANCE_PREFIX, &issuance_body),
    })
    .unwrap();
    let trust = serde_jcs::to_vec(&AgIssuerTrustConfigV1 {
        issuers: vec![TrustedAgIssuerV1 {
            issuer_principal: "ag.fixture".to_owned(),
            key_id: "ag-fixture-key".to_owned(),
            public_key: public_key.clone(),
        }],
    })
    .unwrap();
    let trust_path = root.join("trust.json");
    std::fs::write(&trust_path, &trust).unwrap();
    let standing = ExecutionStandingResolutionV1 {
        schema: STANDING_RESOLUTION_SCHEMA_V1.to_owned(),
        resolution: digest("standing-resolution"),
        currentness: digest("standing-currentness"),
        execution_standing: digest("execution-standing"),
        issuance: issuance.issuance.clone(),
        campaign: issuance.key.campaign.clone(),
        occurrence: issuance.key.occurrence.clone(),
        subject: issuance.subject.clone(),
        scope: issuance.effect_scope_digest.clone(),
        status: ExecutionStandingStatusV1::Current,
        resolved_at_unix_ms: 0,
        expires_at_unix_ms: MAX_SAFE,
    };
    let standing_program = root.join("standing");
    write_static_program(
        &standing_program,
        &serde_json::to_string(&standing).unwrap(),
    );
    let initial = serde_json::json!({
        "attempt": attempt,
        "effect_journal": [],
        "marker": marker,
        "outcome": "indeterminate",
        "receipt": digest("initial-indeterminate")
    });
    let reconciliation = serde_json::json!({
        "attempt": attempt,
        "effect_journal": [],
        "marker": marker,
        "outcome": "indeterminate",
        "receipt": digest("round-indeterminate")
    });
    if let Some(attempt_store) = &effectd_store {
        seed_started_ag_effectd_attempt(
            attempt_store,
            &attempt,
            &marker,
            &issuance.work,
            &issuance.subject,
            &issuance.effect_scope_digest,
        );
    } else {
        let initial_path = root.join("initial.json");
        let reconciliation_path = root.join("reconciliation.json");
        std::fs::write(&initial_path, serde_jcs::to_vec(&initial).unwrap()).unwrap();
        std::fs::write(
            &reconciliation_path,
            serde_jcs::to_vec(&reconciliation).unwrap(),
        )
        .unwrap();
        write_executor(&executor, &initial_path, &reconciliation_path);
    }

    if accept_now {
        let accepted = accept(
            &database,
            &issuance_envelope,
            &trust,
            &standing_program,
            &executor,
            &config,
        )
        .unwrap();
        assert!(matches!(
            accepted,
            DocketExecutionResponseWireV1::Custody(_)
        ));
    }

    let idempotency = digest("round-idempotency");
    let caller_state = digest("caller-state");
    let mut round = ReconciliationRoundRequestWireV1 {
        schema: RECONCILIATION_ROUND_REQUEST_SCHEMA_V1.to_owned(),
        request: String::new(),
        round: String::new(),
        issuance: issuance.issuance,
        attempt,
        caller_state_digest: caller_state,
        predecessor_round: None,
        predecessor_reconciliation: None,
        idempotency,
    };
    let mut round_basis = serde_json::to_value(&round).unwrap();
    round_basis.as_object_mut().unwrap().remove("request");
    round_basis.as_object_mut().unwrap().remove("round");
    round.round = hash_domain(
        "ag.governed-loop.reconciliation-round/v1",
        &serde_jcs::to_vec(&round_basis).unwrap(),
    );
    let mut request_basis = serde_json::to_value(&round).unwrap();
    request_basis.as_object_mut().unwrap().remove("request");
    round.request = hash_domain(
        "ag.governed-loop.reconciliation-round-request/v1",
        &serde_jcs::to_vec(&request_basis).unwrap(),
    );
    let round_body = serde_jcs::to_vec(&round).unwrap();
    let envelope = serde_jcs::to_vec(&SignedReconciliationRoundRequestEnvelopeWireV1 {
        schema: SIGNED_RECONCILIATION_ROUND_REQUEST_SCHEMA_V1.to_owned(),
        body_b64: b64(&round_body),
        authentication: authentication(ROUND_PREFIX, &round_body),
    })
    .unwrap();
    Fixture {
        root,
        state,
        trust_path,
        standing_program,
        executor,
        config,
        issuance_envelope,
        envelope,
        effectd_store,
    }
}

fn issuance_identity(value: &AgIssuanceWireV2) -> String {
    let mut basis = serde_json::to_value(value).unwrap();
    basis.as_object_mut().unwrap().remove("schema");
    basis.as_object_mut().unwrap().remove("issuance");
    hash_domain(
        "ag.governed-loop.issuance/v2",
        &serde_jcs::to_vec(&basis).unwrap(),
    )
}

fn write_static_program(path: &Path, output: &str) {
    std::fs::write(
        path,
        format!(
            "#!/bin/sh\ncat >/dev/null\nprintf '%s' '{}'\n",
            shell(output)
        ),
    )
    .unwrap();
    executable(path);
}

fn write_executor(path: &Path, initial: &Path, reconciliation: &Path) {
    let calls = path.with_extension("calls");
    let plans = path.with_extension("plans");
    let release = path.with_extension("release");
    let operations = path.with_extension("operations");
    std::fs::write(
        path,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$1\" >> '{}'\nif [ \"$1\" = plan-id ]; then printf x >> '{}'; cat \"$2\"; exit $?; fi\nif [ \"$1\" = execute ]; then cat >/dev/null; cat '{}'; exit $?; fi\nif [ \"$1\" = reconcile ]; then cat >/dev/null; printf x >> '{}'; while [ ! -f '{}' ]; do sleep 0.01; done; cat '{}'; exit $?; fi\nexit 64\n",
            shell(&operations.display().to_string()),
            shell(&plans.display().to_string()),
            shell(&initial.display().to_string()),
            shell(&calls.display().to_string()),
            shell(&release.display().to_string()),
            shell(&reconciliation.display().to_string())
        ),
    )
    .unwrap();
    executable(path);
}

fn write_mixed_process_executor(fixture: &Fixture) {
    let path = &fixture.executor;
    let initial = fixture.root.join("initial.json");
    let reconciliation = fixture.root.join("reconciliation.json");
    let calls = path.with_extension("calls");
    let plans = path.with_extension("plans");
    let execute_calls = path.with_extension("execute-calls");
    let execute_started = path.with_extension("execute-started");
    let execute_release = path.with_extension("execute-release");
    let reconcile_started = path.with_extension("reconcile-started");
    let reconcile_release = path.with_extension("reconcile-release");
    std::fs::write(
        path,
        format!(
            "#!/bin/sh\nif [ \"$1\" = plan-id ]; then printf x >> '{}'; cat \"$2\"; exit $?; fi\nif [ \"$1\" = execute ]; then cat >/dev/null; printf x >> '{}'; : > '{}'; while [ ! -f '{}' ]; do sleep 0.01; done; cat '{}'; exit $?; fi\nif [ \"$1\" = reconcile ]; then cat >/dev/null; printf x >> '{}'; : > '{}'; while [ ! -f '{}' ]; do sleep 0.01; done; cat '{}'; exit $?; fi\nexit 64\n",
            shell(&plans.display().to_string()),
            shell(&execute_calls.display().to_string()),
            shell(&execute_started.display().to_string()),
            shell(&execute_release.display().to_string()),
            shell(&initial.display().to_string()),
            shell(&calls.display().to_string()),
            shell(&reconcile_started.display().to_string()),
            shell(&reconcile_release.display().to_string()),
            shell(&reconciliation.display().to_string())
        ),
    )
    .unwrap();
    executable(path);
}

fn wait_for_path(path: &Path) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while !path.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn seed_started_ag_effectd_attempt(
    store: &Path,
    attempt: &str,
    marker: &str,
    work: &str,
    subject: &str,
    scope: &str,
) {
    let connection = Connection::open(store).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE docket_effect_attempt (
               attempt TEXT PRIMARY KEY NOT NULL,
               marker TEXT UNIQUE NOT NULL,
               work TEXT NOT NULL,
               subject TEXT NOT NULL,
               scope TEXT NOT NULL,
               status TEXT NOT NULL CHECK (status IN ('started','success','failure','indeterminate')),
               receipt TEXT,
               receipt_body BLOB,
               CHECK ((status='started' AND receipt IS NULL AND receipt_body IS NULL)
                      OR (status!='started' AND receipt IS NOT NULL AND receipt_body IS NOT NULL))
             ) STRICT;
             CREATE TABLE docket_reconciliation_context (
               round TEXT PRIMARY KEY NOT NULL,
               request TEXT UNIQUE NOT NULL,
               reservation TEXT UNIQUE NOT NULL,
               source_cut TEXT NOT NULL,
               attempt TEXT NOT NULL,
               dispatch_jcs BLOB NOT NULL
             ) STRICT;",
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO docket_effect_attempt
             (attempt,marker,work,subject,scope,status)
             VALUES (?1,?2,?3,?4,?5,'started')",
            params![attempt, marker, work, subject, scope],
        )
        .unwrap();
}

fn executable(path: &Path) {
    let mut permissions = std::fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions).unwrap();
}

fn shell(value: &str) -> String {
    value.replace('\'', "'\\''")
}

fn digest(label: &str) -> String {
    hash_domain("docket-r4-process-fixture/v1", label.as_bytes())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", lower_hex(&Sha256::digest(bytes)))
}

fn hash_domain(domain: &str, payload: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"ag-ng\0digest\0v1\0");
    hash.update((domain.len() as u128).to_be_bytes());
    hash.update(domain.as_bytes());
    hash.update((payload.len() as u128).to_be_bytes());
    hash.update(payload);
    format!("sha256:{}", lower_hex(&hash.finalize()))
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(value, "{byte:02x}").unwrap();
    }
    value
}

fn b64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (chunk.get(1).copied().map_or(0, u32::from) << 8)
            | chunk.get(2).copied().map_or(0, u32::from);
        out.push(TABLE[((value >> 18) & 63) as usize] as char);
        out.push(TABLE[((value >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((value >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(TABLE[(value & 63) as usize] as char);
        }
    }
    out
}
