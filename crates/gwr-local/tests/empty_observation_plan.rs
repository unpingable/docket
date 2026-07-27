//! Regression for finding N-3: an empty observation plan is operator input, not
//! an impossible internal state.
//!
//! `observe()` indexed `argv[0]` with no guard, so an attempt admitted with an
//! empty plan committed normally and then panicked at observation. Observation
//! happens *after* commitment, so the important property is not just "no panic"
//! — it is that a malformed invocation must not consume or strand a committed
//! attempt. Nothing may be run and no record written before the refusal.

use gwr_core::digest::Sha256Digest;
use gwr_core::effect_spec::GitRefEffect;
use gwr_core::ids::*;
use gwr_core::lifecycle::AttemptState;
use gwr_core::observation_plan::ObservationPlan;
use gwr_core::outcome::Commitment;
use gwr_core::prepared_attempt::PreparedAttempt;
use gwr_core::work_request::{ClockReading, CommitHash, RefName, RepositoryLocator};
use gwr_local::adapters::{FixedClock, HashChainIds};
use gwr_local::observe::{observe, ObserveError};
use gwr_local::store::SqliteStore;
use gwr_runtime::ports::store::Store;

fn attempt_with(argv: Vec<String>) -> PreparedAttempt {
    let d = Sha256Digest::of_bytes(b"patch");
    PreparedAttempt::admit(
        AttemptId::from_bytes([9; 16]),
        WorkRequestId::from_bytes([1; 16]),
        CandidateArtifactId::from_bytes([2; 16]),
        RepositoryLocator::new("/nonexistent-repo"),
        CommitHash::new("basis"),
        d,
        GitRefEffect {
            target_ref: RefName::new("refs/gwr/target"),
            expected_basis: CommitHash::new("basis"),
            patch_digest: d,
            allowed_paths: vec!["src/lib.rs".into()],
        },
        ObservationPlan {
            argv,
            environment_description: "fixture".into(),
        },
        ClockReading(1),
    )
}

#[test]
fn an_empty_observation_plan_refuses_cleanly_and_strands_nothing() {
    let root = std::env::temp_dir().join(format!("gwr-emptyplan-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let mut store = SqliteStore::open(&root.join("s.sqlite")).unwrap();

    let att = attempt_with(vec![]);
    store.admit_attempt(&att).unwrap();
    // Stage a commitment so observation is reachable: the defect appeared only
    // after the effect had already landed.
    let commitment = Commitment {
        attempt: att.attempt_id,
        dispatch: DispatchId::from_bytes([5; 16]),
        target_ref: RefName::new("refs/gwr/target"),
        previous_value: CommitHash::new("basis"),
        result_commit: CommitHash::new("result"),
        journal_digest: Sha256Digest::of_bytes(b"j"),
        committed_at: ClockReading(2),
    };
    store.record_commitment_for_test(&commitment).unwrap();

    let before = store.get_attempt(att.attempt_id).unwrap();
    let r = observe(
        &mut store,
        att.attempt_id,
        &FixedClock(ClockReading(3)),
        &mut HashChainIds::new(),
    );

    // A typed refusal, not a panic and not an I/O error from a half-built
    // worktree: the plan is checked before anything is run.
    assert!(
        matches!(r, Err(ObserveError::EmptyObservationPlan)),
        "expected EmptyObservationPlan, got {r:?}"
    );

    // Nothing was consumed. The commitment stands, the projection is unmoved,
    // and no observation was recorded.
    let after = store.get_attempt(att.attempt_id).unwrap();
    assert_eq!(after.state, before.state);
    assert_eq!(after.version, before.version);
    assert_eq!(
        store.get_commitment(att.attempt_id).unwrap(),
        commitment,
        "the commitment record must be untouched"
    );
    assert!(
        store.get_observations(att.attempt_id).unwrap().is_empty(),
        "a refused observation must write no record"
    );
    assert!(matches!(after.state, AttemptState::Prepared));

    let _ = std::fs::remove_dir_all(&root);
}

/// The refusal is a property of the plan, not of the attempt: a well-formed plan
/// on the same attempt shape reaches the execution path instead of refusing.
#[test]
fn a_non_empty_plan_is_not_refused_for_being_empty() {
    let root = std::env::temp_dir().join(format!("gwr-nonemptyplan-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let mut store = SqliteStore::open(&root.join("s.sqlite")).unwrap();

    let att = attempt_with(vec!["true".into()]);
    store.admit_attempt(&att).unwrap();
    store
        .record_commitment_for_test(&Commitment {
            attempt: att.attempt_id,
            dispatch: DispatchId::from_bytes([5; 16]),
            target_ref: RefName::new("refs/gwr/target"),
            previous_value: CommitHash::new("basis"),
            result_commit: CommitHash::new("result"),
            journal_digest: Sha256Digest::of_bytes(b"j"),
            committed_at: ClockReading(2),
        })
        .unwrap();

    // The repository does not exist, so this fails at worktree creation — an
    // I/O error, which is precisely *not* EmptyObservationPlan.
    let r = observe(
        &mut store,
        att.attempt_id,
        &FixedClock(ClockReading(3)),
        &mut HashChainIds::new(),
    );
    assert!(
        matches!(r, Err(ObserveError::Io(_))),
        "expected the plan to be accepted and execution attempted, got {r:?}"
    );

    let _ = std::fs::remove_dir_all(&root);
}
