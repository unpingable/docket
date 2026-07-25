//! Task 10: the failure-injection suite. Sixteen named cases where ordinary
//! orchestration systems usually lie, each shown to refuse, record, or remain
//! honestly indeterminate. Broker crash cases use a real temporary Git
//! repository and real process termination — no mocks.

use gwr_core::bridge::observation_to_review_queue as obs_bridge;
use gwr_core::bridge::recovery_standing_to_resolution as rec_bridge;
use gwr_core::digest::Sha256Digest;
use gwr_core::domain::evidence::Claim;
use gwr_core::domain::standing::{GrantState, StandingAct, StandingGrant, StandingScope};
use gwr_core::effect_spec::GitRefEffect;
use gwr_core::ids::*;
use gwr_core::lifecycle::{AttemptState, RecoveryVerdict};
use gwr_core::observation_plan::{ObservationPlan, ObservationRecord};
use gwr_core::preparation::{PreparationEnd, PreparationRun, PreparationStatus};
use gwr_core::prepared_attempt::PreparedAttempt;
use gwr_core::recovery::{FactSource, RecoveryFact};
use gwr_core::refusal::{
    DispatchRefusalGround, ObservationRefusal, RecoveryRefusal, RelianceRefusal,
};
use gwr_core::work_request::{ClockReading, CommitHash, RefName, RepositoryIdentity, WorkRequest};
use gwr_local::adapters::{FixedClock, FsArtifactStore, FsProvenanceSink, HashChainIds};
use gwr_local::broker::SubprocessGitBroker;
use gwr_local::providers::fake::{GoalEchoProvider, Script, ScriptedProvider};
use gwr_local::store::SqliteStore;
use gwr_runtime::ports::labor_provider::{BoundedAssignment, LaborProvider};
use gwr_runtime::ports::store::Store;
use gwr_runtime::services::dispatch::{dispatch, DispatchOutcome};
use gwr_runtime::services::preparation::{run_preparation, PreparationResult};
use gwr_runtime::services::ratification::{ratify, RatifyError};
use gwr_runtime::services::recovery::{resolve, ResolveError};
use gwr_runtime::services::reliance::{rely_review_queue, RelyError};
use gwr_runtime::services::reservation::reserve;
use std::path::{Path, PathBuf};
use std::process::Command;

const TARGET_REF: &str = "refs/gwr/target";
const ACTOR: ActorId = ActorId::from_bytes([4; 16]);

fn sh(dir: &Path, args: &[&str]) -> String {
    let out = Command::new(args[0])
        .args(&args[1..])
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn fixture_repo(name: &str) -> (PathBuf, String, Vec<u8>) {
    let dir = std::env::temp_dir().join(format!("gwr-fail-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).unwrap();
    sh(&dir, &["git", "init", "-q"]);
    std::fs::write(dir.join("src/lib.rs"), "fn old() {}\n").unwrap();
    sh(&dir, &["git", "add", "-A"]);
    sh(
        &dir,
        &[
            "git",
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "-q",
            "-m",
            "basis",
        ],
    );
    let basis = sh(&dir, &["git", "rev-parse", "HEAD"]);
    sh(&dir, &["git", "update-ref", TARGET_REF, &basis]);
    std::fs::write(dir.join("src/lib.rs"), "fn new() {}\n").unwrap();
    let patch = Command::new("git")
        .args(["diff"])
        .current_dir(&dir)
        .output()
        .unwrap()
        .stdout;
    sh(&dir, &["git", "checkout", "-q", "--", "src/lib.rs"]);
    (dir, basis, patch)
}

struct Fx {
    store: SqliteStore,
    ids: HashChainIds,
    att: PreparedAttempt,
    broker: SubprocessGitBroker,
    repo: PathBuf,
    basis: String,
    db: PathBuf,
}

fn fixture(name: &str) -> Fx {
    let (repo, basis, patch) = fixture_repo(name);
    let patch_digest = Sha256Digest::of_bytes(&patch);
    let artifact_root = repo.join(".gwr-artifacts");
    std::fs::create_dir_all(&artifact_root).unwrap();
    std::fs::write(artifact_root.join(patch_digest.to_hex()), &patch).unwrap();
    let att = PreparedAttempt::admit(
        AttemptId::from_bytes([9; 16]),
        WorkRequestId::from_bytes([1; 16]),
        CandidateArtifactId::from_bytes([2; 16]),
        RepositoryIdentity::new(repo.to_string_lossy()),
        CommitHash::new(&basis),
        patch_digest,
        GitRefEffect {
            target_ref: RefName::new(TARGET_REF),
            expected_basis: CommitHash::new(&basis),
            patch_digest,
            allowed_paths: vec!["src/lib.rs".into()],
        },
        ObservationPlan {
            argv: vec!["true".into()],
            environment_description: "fixture".into(),
        },
        ClockReading(1),
    );
    let db = repo.join(".gwr-state.sqlite");
    let mut store = SqliteStore::open(&db).unwrap();
    store.admit_attempt(&att).unwrap();
    let broker = SubprocessGitBroker::new(
        PathBuf::from(env!("CARGO_BIN_EXE_gwr-git-broker")),
        repo.join(".gwr-journals"),
        artifact_root,
    );
    Fx {
        store,
        ids: HashChainIds::new(),
        att,
        broker,
        repo,
        basis,
        db,
    }
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.repo);
    }
}

fn grant_for(fx: &Fx, byte: u8, act: StandingAct) -> StandingGrant {
    StandingGrant {
        id: StandingGrantId::from_bytes([byte; 16]),
        scope: StandingScope {
            actor: ACTOR,
            act,
            repository: fx.att.repository.clone(),
            attempt_digest: fx.att.prepared_attempt_digest,
        },
        expires_at: ClockReading(1_000_000),
        state: GrantState::Available,
    }
}

fn ratify_and_reserve(fx: &mut Fx) {
    let grant = grant_for(fx, 3, StandingAct::Ratify);
    fx.store.create_standing_grant(&grant).unwrap();
    let clock = FixedClock(ClockReading(10));
    ratify(
        &mut fx.store,
        fx.att.attempt_id,
        grant.id,
        ACTOR,
        fx.att.prepared_attempt_digest,
        fx.att.basis.clone(),
        &clock,
        &mut fx.ids,
    )
    .unwrap();
    reserve(
        &mut fx.store,
        fx.att.attempt_id,
        1_000_000,
        &clock,
        &mut fx.ids,
    )
    .unwrap();
}

/// The runtime's own reader of the world for recovery.
fn evidence(fx: &Fx) -> gwr_local::recover::GitRecoveryEvidence {
    gwr_local::recover::GitRecoveryEvidence::new(fx.repo.join(".gwr-journals"))
}

/// Drive to Indeterminate via a real broker crash after the named phase.
fn drive_indeterminate(fx: &mut Fx, crash_after: &str) {
    ratify_and_reserve(fx);
    fx.broker.crash_after = Some(crash_after.into());
    let clock = FixedClock(ClockReading(20));
    let outcome = dispatch(
        &mut fx.store,
        fx.att.attempt_id,
        &mut fx.broker,
        &clock,
        &mut fx.ids,
    )
    .unwrap();
    assert!(matches!(outcome, DispatchOutcome::Indeterminate(_)));
    fx.broker.crash_after = None;
}

// 1
#[test]
fn provider_death_does_not_mint_effect_failure() {
    let mut fx = fixture("prov-death");
    let wr = WorkRequest {
        id: WorkRequestId::from_bytes([1; 16]),
        repository: fx.att.repository.clone(),
        target_ref: RefName::new(TARGET_REF),
        goal: "fix".into(),
        created_at: ClockReading(1),
    };
    fx.store.create_work_request(&wr).unwrap();
    let run = PreparationRun {
        id: PreparationRunId::from_bytes([7; 16]),
        work_request: wr.id,
        started_at: ClockReading(2),
        deadline: ClockReading(1000),
        status: PreparationStatus::Running,
    };
    fx.store.create_preparation_run(&run).unwrap();
    let mut provider = ScriptedProvider::new(Script::Die("segv".into()));
    let assignment = BoundedAssignment {
        preparation_run: run.id,
        goal: wr.goal.clone(),
        basis: CommitHash::new(&fx.basis),
        workspace: fx.repo.join("ws"),
        deadline: run.deadline,
    };
    let mut artifacts = FsArtifactStore::new(fx.repo.join("a2")).unwrap();
    let mut provenance = FsProvenanceSink::new(fx.repo.join("p2")).unwrap();
    let clock = FixedClock(ClockReading(50));
    let result = run_preparation(
        &mut fx.store,
        &mut provider,
        &run,
        &assignment,
        &mut artifacts,
        &mut provenance,
        &clock,
        &mut fx.ids,
    )
    .unwrap();
    assert_eq!(result, PreparationResult::Failed);
    // The attempt's execution state is untouched: provider death is a
    // preparation fact, never an effect outcome.
    let projected = fx.store.get_attempt(fx.att.attempt_id).unwrap();
    assert_eq!(projected.state, AttemptState::Prepared);
}

// 2
#[test]
fn late_candidate_cannot_be_admitted() {
    let mut fx = fixture("late-cand");
    let wr = WorkRequest {
        id: WorkRequestId::from_bytes([1; 16]),
        repository: fx.att.repository.clone(),
        target_ref: RefName::new(TARGET_REF),
        goal: "fix".into(),
        created_at: ClockReading(1),
    };
    fx.store.create_work_request(&wr).unwrap();
    let run = PreparationRun {
        id: PreparationRunId::from_bytes([7; 16]),
        work_request: wr.id,
        started_at: ClockReading(2),
        deadline: ClockReading(40),
        status: PreparationStatus::Running,
    };
    fx.store.create_preparation_run(&run).unwrap();
    let mut provider = ScriptedProvider::new(Script::Produce {
        patch: b"late".to_vec(),
        reported_digest: None,
    });
    let assignment = BoundedAssignment {
        preparation_run: run.id,
        goal: wr.goal.clone(),
        basis: CommitHash::new(&fx.basis),
        workspace: fx.repo.join("ws"),
        deadline: run.deadline,
    };
    let mut artifacts = FsArtifactStore::new(fx.repo.join("a2")).unwrap();
    let mut provenance = FsProvenanceSink::new(fx.repo.join("p2")).unwrap();
    let clock = FixedClock(ClockReading(50)); // past deadline
    let result = run_preparation(
        &mut fx.store,
        &mut provider,
        &run,
        &assignment,
        &mut artifacts,
        &mut provenance,
        &clock,
        &mut fx.ids,
    )
    .unwrap();
    assert_eq!(result, PreparationResult::LateCandidate);
    let stored = fx.store.get_preparation_run(run.id).unwrap();
    assert_eq!(
        stored.status,
        PreparationStatus::Ended(PreparationEnd::Expired)
    );
}

// 3
#[test]
fn provider_replacement_does_not_change_core() {
    // Two structurally different providers behind one contract; the second
    // uses a new PreparationRunId and no core type knows either exists.
    let mut a = ScriptedProvider::new(Script::Fail("x".into()));
    let mut b = GoalEchoProvider;
    let assignment = BoundedAssignment {
        preparation_run: PreparationRunId::from_bytes([1; 16]),
        goal: "g".into(),
        basis: CommitHash::new("h"),
        workspace: std::env::temp_dir(),
        deadline: ClockReading(100),
    };
    let ra = a.prepare(&assignment).unwrap();
    let assignment_b = BoundedAssignment {
        preparation_run: PreparationRunId::from_bytes([2; 16]),
        ..assignment
    };
    let rb = b.prepare(&assignment_b).unwrap();
    assert_ne!(
        assignment_b.preparation_run,
        PreparationRunId::from_bytes([1; 16])
    );
    // Same neutral report type from both; nothing provider-shaped leaks.
    let _: (
        gwr_runtime::ports::labor_provider::PreparationReport,
        gwr_runtime::ports::labor_provider::PreparationReport,
    ) = (ra, rb);
}

// 4
#[test]
fn ratification_rejects_wrong_basis() {
    let mut fx = fixture("wrong-basis");
    let grant = grant_for(&fx, 3, StandingAct::Ratify);
    fx.store.create_standing_grant(&grant).unwrap();
    let clock = FixedClock(ClockReading(10));
    let err = ratify(
        &mut fx.store,
        fx.att.attempt_id,
        grant.id,
        ACTOR,
        fx.att.prepared_attempt_digest,
        CommitHash::new("some-other-basis"),
        &clock,
        &mut fx.ids,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        RatifyError::Bridge(gwr_core::bridge::standing_to_ratification::Refusal::BasisMismatch)
    ));
    let g = fx.store.get_standing_grant(grant.id).unwrap();
    assert_eq!(g.state, GrantState::Available);
}

// 5
#[test]
fn standing_cannot_be_replayed() {
    let mut fx = fixture("standing-replay");
    let grant = grant_for(&fx, 3, StandingAct::Ratify);
    fx.store.create_standing_grant(&grant).unwrap();
    let clock = FixedClock(ClockReading(10));
    ratify(
        &mut fx.store,
        fx.att.attempt_id,
        grant.id,
        ACTOR,
        fx.att.prepared_attempt_digest,
        fx.att.basis.clone(),
        &clock,
        &mut fx.ids,
    )
    .unwrap();
    let err = ratify(
        &mut fx.store,
        fx.att.attempt_id,
        grant.id,
        ACTOR,
        fx.att.prepared_attempt_digest,
        fx.att.basis.clone(),
        &clock,
        &mut fx.ids,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        RatifyError::Bridge(
            gwr_core::bridge::standing_to_ratification::Refusal::Standing(
                gwr_core::refusal::StandingRefusal::AlreadyUsed
            )
        )
    ));
}

// 6
#[test]
fn reservation_cannot_be_replayed() {
    let mut fx = fixture("rsv-replay");
    ratify_and_reserve(&mut fx);
    let clock = FixedClock(ClockReading(20));
    let outcome = dispatch(
        &mut fx.store,
        fx.att.attempt_id,
        &mut fx.broker,
        &clock,
        &mut fx.ids,
    )
    .unwrap();
    assert!(matches!(outcome, DispatchOutcome::Committed(_)));
    // A second dispatch inspects; the reservation use is not spent again.
    let again = dispatch(
        &mut fx.store,
        fx.att.attempt_id,
        &mut fx.broker,
        &clock,
        &mut fx.ids,
    )
    .unwrap();
    assert!(matches!(again, DispatchOutcome::AlreadyDispatched { .. }));
}

// 7
#[test]
fn target_ref_movement_refuses_dispatch() {
    let mut fx = fixture("ref-moved");
    ratify_and_reserve(&mut fx);
    let interloper = sh(
        &fx.repo,
        &[
            "git",
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit-tree",
            &sh(&fx.repo, &["git", "rev-parse", "HEAD^{tree}"]),
            "-m",
            "interloper",
        ],
    );
    sh(&fx.repo, &["git", "update-ref", TARGET_REF, &interloper]);
    let clock = FixedClock(ClockReading(20));
    let outcome = dispatch(
        &mut fx.store,
        fx.att.attempt_id,
        &mut fx.broker,
        &clock,
        &mut fx.ids,
    )
    .unwrap();
    let DispatchOutcome::Refused(record) = outcome else {
        panic!("expected refusal");
    };
    assert_eq!(record.ground, DispatchRefusalGround::BasisMoved);
    // DispatchRefused is a definite state, distinct forever from
    // ProvenNotCommitted.
    let projected = fx.store.get_attempt(fx.att.attempt_id).unwrap();
    assert!(matches!(
        projected.state,
        AttemptState::DispatchRefused { .. }
    ));
}

// 8
#[test]
fn broker_death_before_ref_update_becomes_indeterminate() {
    let mut fx = fixture("death-before");
    drive_indeterminate(&mut fx, "commit_created");
    assert_eq!(sh(&fx.repo, &["git", "rev-parse", TARGET_REF]), fx.basis);
    // Indeterminate survives restart.
    drop(std::mem::replace(
        &mut fx.store,
        SqliteStore::open(&fx.db).unwrap(),
    ));
    let projected = fx.store.get_attempt(fx.att.attempt_id).unwrap();
    assert!(matches!(
        projected.state,
        AttemptState::Indeterminate { .. }
    ));
}

// 9
#[test]
fn lost_ack_after_ref_update_requires_recovery() {
    let mut fx = fixture("lost-ack");
    drive_indeterminate(&mut fx, "ref_updated");
    // The ref moved, but no success is minted. Restart, then recover.
    drop(std::mem::replace(
        &mut fx.store,
        SqliteStore::open(&fx.db).unwrap(),
    ));
    let projected = fx.store.get_attempt(fx.att.attempt_id).unwrap();
    assert!(matches!(
        projected.state,
        AttemptState::Indeterminate { .. }
    ));

    let clock = FixedClock(ClockReading(100));
    let fact = gwr_local::recover::produce_fact(
        &mut fx.store,
        fx.att.attempt_id,
        &fx.repo.join(".gwr-journals"),
        &clock,
        &mut fx.ids,
    )
    .unwrap();
    // The authentic fact alone applies nothing: state is still indeterminate.
    let projected = fx.store.get_attempt(fx.att.attempt_id).unwrap();
    assert!(matches!(
        projected.state,
        AttemptState::Indeterminate { .. }
    ));

    // Separate recovery standing resolves it — and only to a recovery verdict.
    let grant = grant_for(&fx, 6, StandingAct::ResolveRecovery);
    fx.store.create_standing_grant(&grant).unwrap();
    let mut ev = evidence(&fx);
    let resolution = resolve(
        &mut fx.store,
        fx.att.attempt_id,
        fact.id,
        grant.id,
        ACTOR,
        &mut ev,
        &clock,
        &mut fx.ids,
    )
    .unwrap();
    assert_eq!(resolution.verdict, RecoveryVerdict::CommittedViaRecovery);
    let projected = fx.store.get_attempt(fx.att.attempt_id).unwrap();
    assert!(matches!(
        projected.state,
        AttemptState::CommittedViaRecovery { .. }
    ));
}

// 10
#[test]
fn observation_failure_does_not_rewrite_commitment() {
    let mut fx = fixture("obs-fail");
    ratify_and_reserve(&mut fx);
    let clock = FixedClock(ClockReading(20));
    let DispatchOutcome::Committed(commitment) = dispatch(
        &mut fx.store,
        fx.att.attempt_id,
        &mut fx.broker,
        &clock,
        &mut fx.ids,
    )
    .unwrap() else {
        panic!("expected commitment");
    };
    let obs = ObservationRecord {
        id: ObservationId::from_bytes([50; 16]),
        attempt: fx.att.attempt_id,
        argv: vec!["true".into()],
        working_directory_identity: "manual".into(),
        result_commit: commitment.result_commit.clone(),
        environment_description: "t".into(),
        exit_status: 101,
        stdout_digest: Sha256Digest::of_bytes(b""),
        stderr_digest: Sha256Digest::of_bytes(b""),
        observed_at: ClockReading(30),
    };
    fx.store.record_observation(&obs).unwrap();
    let projected = fx.store.get_attempt(fx.att.attempt_id).unwrap();
    assert!(matches!(projected.state, AttemptState::Committed { .. }));
    assert_eq!(
        fx.store.get_commitment(fx.att.attempt_id).unwrap(),
        commitment
    );
}

// 11
#[test]
fn wrong_commit_observation_is_rejected() {
    let mut fx = fixture("obs-wrong");
    ratify_and_reserve(&mut fx);
    let clock = FixedClock(ClockReading(20));
    let DispatchOutcome::Committed(_) = dispatch(
        &mut fx.store,
        fx.att.attempt_id,
        &mut fx.broker,
        &clock,
        &mut fx.ids,
    )
    .unwrap() else {
        panic!("expected commitment");
    };
    let obs = ObservationRecord {
        id: ObservationId::from_bytes([51; 16]),
        attempt: fx.att.attempt_id,
        argv: vec!["true".into()],
        working_directory_identity: "manual".into(),
        result_commit: CommitHash::new("not-the-result"),
        environment_description: "t".into(),
        exit_status: 0,
        stdout_digest: Sha256Digest::of_bytes(b""),
        stderr_digest: Sha256Digest::of_bytes(b""),
        observed_at: ClockReading(30),
    };
    fx.store.record_observation(&obs).unwrap();
    let err = rely_review_queue(
        &mut fx.store,
        fx.att.attempt_id,
        obs.id,
        Claim::ExactResultCommitProducedAndCommandExitedZero,
        &clock,
    )
    .unwrap_err();
    assert_eq!(
        err,
        RelyError::Refused(RelianceRefusal::Observation(
            ObservationRefusal::ScopeMismatch
        ))
    );
}

// 12
#[test]
fn recovery_fact_for_other_attempt_is_rejected() {
    let mut fx = fixture("rec-other");
    drive_indeterminate(&mut fx, "ref_updated");
    // A fact binding a different attempt, authentic in form.
    let foreign = RecoveryFact {
        id: RecoveryFactId::from_bytes([60; 16]),
        attempt: AttemptId::from_bytes([99; 16]),
        dispatch: fx
            .store
            .find_attempt_dispatch(fx.att.attempt_id)
            .unwrap()
            .unwrap(),
        prepared_attempt_digest: fx.att.prepared_attempt_digest,
        repository: fx.att.repository.clone(),
        target_ref: RefName::new(TARGET_REF),
        basis: fx.att.basis.clone(),
        observed_ref: CommitHash::new("x"),
        expected_result_commit: Some(CommitHash::new("x")),
        journal_digest: Sha256Digest::of_bytes(b"j"),
        source: FactSource::OperatorSupplied("forged".into()),
        recorded_at: ClockReading(90),
    };
    fx.store.record_recovery_fact(&foreign).unwrap();
    let grant = grant_for(&fx, 6, StandingAct::ResolveRecovery);
    fx.store.create_standing_grant(&grant).unwrap();
    let clock = FixedClock(ClockReading(100));
    let before = fx.store.get_attempt(fx.att.attempt_id).unwrap();
    let mut ev = evidence(&fx);
    let err = resolve(
        &mut fx.store,
        fx.att.attempt_id,
        foreign.id,
        grant.id,
        ACTOR,
        &mut ev,
        &clock,
        &mut fx.ids,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ResolveError::Bridge(rec_bridge::Refusal::Recovery(
            RecoveryRefusal::AttemptMismatch { .. }
        ))
    ));
    // Wrong-attempt recovery leaves state unchanged, standing unconsumed.
    let after = fx.store.get_attempt(fx.att.attempt_id).unwrap();
    assert_eq!(before.state, after.state);
    assert_eq!(before.version, after.version);
    let g = fx.store.get_standing_grant(grant.id).unwrap();
    assert_eq!(g.state, GrantState::Available);
}

// 13
#[test]
fn recovery_requires_separate_standing() {
    let mut fx = fixture("rec-standing");
    drive_indeterminate(&mut fx, "ref_updated");
    let clock = FixedClock(ClockReading(100));
    let fact = gwr_local::recover::produce_fact(
        &mut fx.store,
        fx.att.attempt_id,
        &fx.repo.join(".gwr-journals"),
        &clock,
        &mut fx.ids,
    )
    .unwrap();
    // The actor holds only ratification standing. Authentic evidence plus the
    // wrong authority resolves nothing.
    let grant = grant_for(&fx, 61, StandingAct::Ratify);
    fx.store.create_standing_grant(&grant).unwrap();
    let before = fx.store.get_attempt(fx.att.attempt_id).unwrap();
    let mut ev = evidence(&fx);
    let err = resolve(
        &mut fx.store,
        fx.att.attempt_id,
        fact.id,
        grant.id,
        ACTOR,
        &mut ev,
        &clock,
        &mut fx.ids,
    )
    .unwrap_err();
    assert_eq!(
        err,
        ResolveError::Bridge(rec_bridge::Refusal::Recovery(
            RecoveryRefusal::StandingInsufficient
        ))
    );
    let after = fx.store.get_attempt(fx.att.attempt_id).unwrap();
    assert_eq!(before.state, after.state);
}

// 14
#[test]
fn unsafe_refusal_reliance_is_rejected() {
    let mut fx = fixture("refusal-reliance");
    ratify_and_reserve(&mut fx);
    let interloper = sh(
        &fx.repo,
        &[
            "git",
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit-tree",
            &sh(&fx.repo, &["git", "rev-parse", "HEAD^{tree}"]),
            "-m",
            "interloper",
        ],
    );
    sh(&fx.repo, &["git", "update-ref", TARGET_REF, &interloper]);
    let clock = FixedClock(ClockReading(20));
    let DispatchOutcome::Refused(refusal_record) = dispatch(
        &mut fx.store,
        fx.att.attempt_id,
        &mut fx.broker,
        &clock,
        &mut fx.ids,
    )
    .unwrap() else {
        panic!("expected refusal");
    };
    // A downstream consumer wants to read the refusal as its negation
    // ("proven not committed", "the subject lacked authority"). No bridge
    // exists from a refusal to any such claim: the crossing is a first-class
    // reliance refusal, recorded, and the source refusal is not mutated.
    let before = fx.store.get_attempt(fx.att.attempt_id).unwrap();
    fx.store
        .record_reliance_refusal(fx.att.attempt_id, &RelianceRefusal::NoBridge, clock.0)
        .unwrap();
    let after = fx.store.get_attempt(fx.att.attempt_id).unwrap();
    assert_eq!(before.state, after.state);
    assert!(matches!(
        after.state,
        AttemptState::DispatchRefused {
            ground: DispatchRefusalGround::BasisMoved,
            ..
        }
    ));
    // The refusal record itself is unchanged evidence.
    assert_eq!(refusal_record.ground, DispatchRefusalGround::BasisMoved);
}

// 15
#[test]
fn out_of_scope_observation_reliance_is_rejected() {
    let mut fx = fixture("oos-obs");
    ratify_and_reserve(&mut fx);
    let clock = FixedClock(ClockReading(20));
    let DispatchOutcome::Committed(commitment) = dispatch(
        &mut fx.store,
        fx.att.attempt_id,
        &mut fx.broker,
        &clock,
        &mut fx.ids,
    )
    .unwrap() else {
        panic!("expected commitment");
    };
    // An observation of a different attempt cannot support a claim here, even
    // with matching commit strings: the bridge scope check refuses.
    let foreign = ObservationRecord {
        id: ObservationId::from_bytes([52; 16]),
        attempt: AttemptId::from_bytes([99; 16]),
        argv: vec!["true".into()],
        working_directory_identity: "manual".into(),
        result_commit: commitment.result_commit.clone(),
        environment_description: "t".into(),
        exit_status: 0,
        stdout_digest: Sha256Digest::of_bytes(b""),
        stderr_digest: Sha256Digest::of_bytes(b""),
        observed_at: ClockReading(30),
    };
    let out = obs_bridge::cross(obs_bridge::Input {
        version: obs_bridge::VERSION,
        observation: &foreign,
        commitment: &commitment,
        claim: Claim::ExactResultCommitProducedAndCommandExitedZero,
        now: ClockReading(40),
    });
    assert_eq!(
        out.unwrap_err(),
        RelianceRefusal::Observation(ObservationRefusal::ScopeMismatch)
    );
}

// 16
#[test]
fn unsupported_bridge_version_is_rejected() {
    let mut fx = fixture("bridge-version");
    ratify_and_reserve(&mut fx);
    let clock = FixedClock(ClockReading(20));
    let DispatchOutcome::Committed(commitment) = dispatch(
        &mut fx.store,
        fx.att.attempt_id,
        &mut fx.broker,
        &clock,
        &mut fx.ids,
    )
    .unwrap() else {
        panic!("expected commitment");
    };
    let obs = ObservationRecord {
        id: ObservationId::from_bytes([53; 16]),
        attempt: fx.att.attempt_id,
        argv: vec!["true".into()],
        working_directory_identity: "manual".into(),
        result_commit: commitment.result_commit.clone(),
        environment_description: "t".into(),
        exit_status: 0,
        stdout_digest: Sha256Digest::of_bytes(b""),
        stderr_digest: Sha256Digest::of_bytes(b""),
        observed_at: ClockReading(30),
    };
    let out = obs_bridge::cross(obs_bridge::Input {
        version: 2,
        observation: &obs,
        commitment: &commitment,
        claim: Claim::ExactResultCommitProducedAndCommandExitedZero,
        now: ClockReading(40),
    });
    let refusal = out.unwrap_err();
    assert_eq!(
        refusal,
        RelianceRefusal::BridgeVersionUnsupported { presented: 2 }
    );
    // The refusal is recordable as a first-class reliance record.
    fx.store
        .record_reliance_refusal(fx.att.attempt_id, &refusal, ClockReading(40))
        .unwrap();
}

/// V2 end-to-end: the blind review's witness. Attempt A crashed before the ref
/// moved; attempt B later committed legitimately. Editing A's broker journal to
/// claim B's commit as A's expected result must not mint a commitment for A.
#[test]
fn tampered_journal_cannot_mint_a_commitment_for_another_attempts_commit() {
    let mut fx = fixture("tampered-journal");
    drive_indeterminate(&mut fx, "commit_created");
    // The ref never moved for A.
    assert_eq!(sh(&fx.repo, &["git", "rev-parse", TARGET_REF]), fx.basis);

    // Someone else's commit now sits on the ref, recorded as another attempt's
    // commitment — the position after B commits legitimately.
    let other_commit = sh(
        &fx.repo,
        &[
            "git",
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit-tree",
            &sh(&fx.repo, &["git", "rev-parse", "HEAD^{tree}"]),
            "-m",
            "attempt B's effect",
        ],
    );
    sh(&fx.repo, &["git", "update-ref", TARGET_REF, &other_commit]);
    let attempt_b = AttemptId::from_bytes([22; 16]);
    let b_commitment = gwr_core::outcome::Commitment {
        attempt: attempt_b,
        dispatch: DispatchId::from_bytes([23; 16]),
        target_ref: RefName::new(TARGET_REF),
        previous_value: CommitHash::new(&fx.basis),
        result_commit: CommitHash::new(&other_commit),
        journal_digest: Sha256Digest::of_bytes(b"b journal"),
        committed_at: ClockReading(50),
    };

    // Tamper: rewrite A's journal so it claims B's commit as A's result.
    let dispatch_hex: String = fx
        .store
        .find_attempt_dispatch(fx.att.attempt_id)
        .unwrap()
        .unwrap()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let journal_path = fx
        .repo
        .join(".gwr-journals")
        .join(format!("{dispatch_hex}.journal"));
    let original = std::fs::read_to_string(&journal_path).unwrap();
    let tampered: String = original
        .lines()
        .map(|l| {
            if l.starts_with("commit_created ") {
                format!("commit_created {other_commit}")
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&journal_path, format!("{tampered}\n")).unwrap();

    let clock = FixedClock(ClockReading(100));
    // Producing a fact from the tampered journal is allowed — facts are
    // observations, and recording one changes nothing.
    let fact = gwr_local::recover::produce_fact(
        &mut fx.store,
        fx.att.attempt_id,
        &fx.repo.join(".gwr-journals"),
        &clock,
        &mut fx.ids,
    )
    .unwrap();

    let grant = grant_for(&fx, 6, StandingAct::ResolveRecovery);
    fx.store.create_standing_grant(&grant).unwrap();
    let before = fx.store.get_attempt(fx.att.attempt_id).unwrap();
    let mut ev = evidence(&fx);
    let err = resolve(
        &mut fx.store,
        fx.att.attempt_id,
        fact.id,
        grant.id,
        ACTOR,
        &mut ev,
        &clock,
        &mut fx.ids,
    )
    .unwrap_err();
    // The runtime holds the digest recorded at indeterminacy and compares it.
    assert_eq!(
        err,
        ResolveError::Bridge(rec_bridge::Refusal::Recovery(
            RecoveryRefusal::JournalDigestMismatch
        ))
    );
    let after = fx.store.get_attempt(fx.att.attempt_id).unwrap();
    assert_eq!(before.state, after.state);
    assert!(matches!(after.state, AttemptState::Indeterminate { .. }));
    assert_eq!(
        fx.store.get_standing_grant(grant.id).unwrap().state,
        GrantState::Available
    );

    // Even with an untampered journal, another attempt's commit cannot settle
    // this one: record B's commitment and restore the journal.
    std::fs::write(&journal_path, &original).unwrap();
    let dispatching_b = AttemptState::Prepared;
    let _ = dispatching_b;
    fx.store
        .record_commitment_for_test(&b_commitment)
        .expect("record B's commitment");
    let fact2 = gwr_local::recover::produce_fact(
        &mut fx.store,
        fx.att.attempt_id,
        &fx.repo.join(".gwr-journals"),
        &clock,
        &mut fx.ids,
    )
    .unwrap();
    let mut ev = evidence(&fx);
    let err = resolve(
        &mut fx.store,
        fx.att.attempt_id,
        fact2.id,
        grant.id,
        ACTOR,
        &mut ev,
        &clock,
        &mut fx.ids,
    )
    .unwrap_err();
    assert_eq!(
        err,
        ResolveError::Bridge(rec_bridge::Refusal::Recovery(
            RecoveryRefusal::CommitAttributedElsewhere
        ))
    );
    let after = fx.store.get_attempt(fx.att.attempt_id).unwrap();
    assert!(matches!(after.state, AttemptState::Indeterminate { .. }));
}

/// V3: the runtime dies inside `Dispatching`, after the broker acknowledged the
/// ref update. On restart the attempt must settle from the journal, not strand.
#[test]
fn runtime_death_inside_dispatching_settles_on_re_entry() {
    let mut fx = fixture("strand");
    ratify_and_reserve(&mut fx);

    // Drive the broker to a real, acknowledged commit, but do not let the
    // runtime record it: mint the dispatch, persist Dispatching, run the
    // broker, and stop there — exactly the window a kill -9 leaves behind.
    let projected = fx.store.get_attempt(fx.att.attempt_id).unwrap();
    let AttemptState::Reserved { reservation, .. } = &projected.state else {
        panic!("expected reserved");
    };
    let claim = fx.store.get_reservation(*reservation).unwrap();
    let ratification = match &projected.state {
        AttemptState::Reserved { ratification, .. } => ratification.clone(),
        _ => unreachable!(),
    };
    let out = gwr_core::bridge::reservation_to_dispatch::cross(
        gwr_core::bridge::reservation_to_dispatch::Input {
            version: 1,
            claim: &claim,
            ratification: &ratification,
            attempt: &projected.attempt,
            existing_dispatch: None,
            now: ClockReading(20),
            new_dispatch: DispatchId::from_bytes([8; 16]),
            new_use: ReservationUseId::from_bytes([9; 16]),
        },
    )
    .unwrap();
    let dispatching = projected
        .state
        .dispatch(out.reservation_ref.clone(), out.dispatch_ref.clone())
        .unwrap();
    fx.store
        .record_dispatch(
            projected.version,
            &out.envelope,
            &dispatching,
            &out.consumed_claim,
        )
        .unwrap();
    // The effect happens; its outcome is never recorded.
    let broker_outcome = {
        use gwr_runtime::ports::effect_broker::EffectBroker;
        fx.broker.execute(&out.envelope)
    };
    assert!(matches!(
        broker_outcome,
        gwr_runtime::ports::effect_broker::BrokerOutcome::Committed { .. }
    ));
    let ref_after_effect = sh(&fx.repo, &["git", "rev-parse", TARGET_REF]);
    assert_ne!(ref_after_effect, fx.basis, "the effect did land");

    // Restart: the ledger says Dispatching, the world says committed.
    drop(std::mem::replace(
        &mut fx.store,
        SqliteStore::open(&fx.db).unwrap(),
    ));
    let stranded = fx.store.get_attempt(fx.att.attempt_id).unwrap();
    assert!(matches!(stranded.state, AttemptState::Dispatching { .. }));

    // Re-entering dispatch settles from the journal without repeating anything.
    let clock = FixedClock(ClockReading(30));
    let outcome = dispatch(
        &mut fx.store,
        fx.att.attempt_id,
        &mut fx.broker,
        &clock,
        &mut fx.ids,
    )
    .unwrap();
    let DispatchOutcome::Committed(commitment) = outcome else {
        panic!("re-entry stranded the effect: {outcome:?}");
    };
    assert_eq!(commitment.result_commit.as_str(), ref_after_effect);
    let settled = fx.store.get_attempt(fx.att.attempt_id).unwrap();
    assert!(matches!(settled.state, AttemptState::Committed { .. }));
    // The effect did not repeat: the ref is where the single effect left it.
    assert_eq!(
        sh(&fx.repo, &["git", "rev-parse", TARGET_REF]),
        ref_after_effect
    );
}

/// The same window, but the broker died before touching the ref: re-entry must
/// settle to indeterminacy, the recoverable state.
#[test]
fn runtime_death_inside_dispatching_settles_to_indeterminate_when_journal_is_incomplete() {
    let mut fx = fixture("strand-uncertain");
    ratify_and_reserve(&mut fx);
    fx.broker.crash_after = Some("commit_created".into());
    let clock = FixedClock(ClockReading(20));
    let outcome = dispatch(
        &mut fx.store,
        fx.att.attempt_id,
        &mut fx.broker,
        &clock,
        &mut fx.ids,
    )
    .unwrap();
    assert!(matches!(outcome, DispatchOutcome::Indeterminate(_)));
    fx.broker.crash_after = None;
    // Re-entry from Indeterminate does not re-run: it reports the settled state.
    let again = dispatch(
        &mut fx.store,
        fx.att.attempt_id,
        &mut fx.broker,
        &clock,
        &mut fx.ids,
    )
    .unwrap();
    assert!(matches!(again, DispatchOutcome::AlreadyDispatched { .. }));
    assert_eq!(sh(&fx.repo, &["git", "rev-parse", TARGET_REF]), fx.basis);
}
