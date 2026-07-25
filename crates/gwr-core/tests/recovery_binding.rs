//! Regression suite for the invariant-8 defect found by the Task 12 conformance
//! audit (2026-07-24): `validate_fact_binding` checked only attempt, dispatch,
//! and prepared-attempt digest, and `establishes()` compared the observed ref
//! against the fact's *own* copy of the basis. A recovery fact could therefore
//! supply both the proposition and the comparison baseline — self-certifying
//! evidence — and manufacture a false `ProvenNotCommitted` for an attempt it
//! never touched.

use gwr_core::digest::Sha256Digest;
use gwr_core::effect_spec::GitRefEffect;
use gwr_core::ids::*;
use gwr_core::lifecycle::RecoveryVerdict;
use gwr_core::observation_plan::ObservationPlan;
use gwr_core::prepared_attempt::PreparedAttempt;
use gwr_core::recovery::{validate_fact_binding, AuthoritativeBinding, FactSource, RecoveryFact};
use gwr_core::refusal::RecoveryRefusal;
use gwr_core::work_request::{ClockReading, CommitHash, RefName, RepositoryIdentity};

const REAL_REPO: &str = "/governed/repo";
const REAL_REF: &str = "refs/gwr/target";
const REAL_BASIS: &str = "basis-aaa";
const RESULT: &str = "result-ccc";

fn attempt() -> PreparedAttempt {
    PreparedAttempt::admit(
        AttemptId::from_bytes([9; 16]),
        WorkRequestId::from_bytes([1; 16]),
        CandidateArtifactId::from_bytes([2; 16]),
        RepositoryIdentity::new(REAL_REPO),
        CommitHash::new(REAL_BASIS),
        Sha256Digest::of_bytes(b"candidate"),
        GitRefEffect {
            target_ref: RefName::new(REAL_REF),
            expected_basis: CommitHash::new(REAL_BASIS),
            patch_digest: Sha256Digest::of_bytes(b"patch"),
            allowed_paths: vec!["src/lib.rs".into()],
        },
        ObservationPlan {
            argv: vec!["cargo".into(), "test".into()],
            environment_description: "fixture".into(),
        },
        ClockReading(1),
    )
}

fn authoritative(att: &PreparedAttempt) -> AuthoritativeBinding<'_> {
    AuthoritativeBinding {
        attempt: att.attempt_id,
        dispatch: DispatchId::from_bytes([8; 16]),
        prepared_attempt_digest: &att.prepared_attempt_digest,
        repository: &att.repository,
        target_ref: &att.effect.target_ref,
        basis: &att.effect.expected_basis,
    }
}

/// The witness from the audit, unchanged in construction: the three formerly
/// checked fields are correct, every contextual binding points somewhere else.
/// Previously ACCEPTED, and it drove `ProvenNotCommitted`.
#[test]
fn contradictory_context_is_refused() {
    let att = attempt();
    let auth = authoritative(&att);
    let contradictory = RecoveryFact {
        id: RecoveryFactId::from_bytes([1; 16]),
        attempt: att.attempt_id,
        dispatch: DispatchId::from_bytes([8; 16]),
        prepared_attempt_digest: att.prepared_attempt_digest,
        repository: RepositoryIdentity::new("/some/entirely/other/repo"),
        target_ref: RefName::new("refs/heads/unrelated"),
        basis: CommitHash::new("a-basis-the-attempt-never-had"),
        observed_ref: CommitHash::new("a-basis-the-attempt-never-had"),
        expected_result_commit: None,
        journal_digest: Sha256Digest::of_bytes(b"unrelated journal"),
        source: FactSource::OperatorSupplied("hand-written".into()),
        recorded_at: ClockReading(1),
    };
    assert_eq!(
        validate_fact_binding(&contradictory, &auth),
        Err(RecoveryRefusal::RepositoryMismatch)
    );
    // And even if binding were waived, the verdict no longer follows from the
    // fact's own basis: the observed ref is not the attempt's real basis.
    assert_eq!(contradictory.establishes(&auth), None);
}

/// Each contextual field is load-bearing on its own.
#[test]
fn each_contextual_binding_is_checked_independently() {
    let att = attempt();
    let auth = authoritative(&att);
    let good = RecoveryFact {
        id: RecoveryFactId::from_bytes([1; 16]),
        attempt: att.attempt_id,
        dispatch: DispatchId::from_bytes([8; 16]),
        prepared_attempt_digest: att.prepared_attempt_digest,
        repository: RepositoryIdentity::new(REAL_REPO),
        target_ref: RefName::new(REAL_REF),
        basis: CommitHash::new(REAL_BASIS),
        observed_ref: CommitHash::new(REAL_BASIS),
        expected_result_commit: Some(CommitHash::new(RESULT)),
        journal_digest: Sha256Digest::of_bytes(b"journal"),
        source: FactSource::RefInspection,
        recorded_at: ClockReading(90),
    };

    let mut wrong_repo = good.clone();
    wrong_repo.repository = RepositoryIdentity::new("/elsewhere");
    assert_eq!(
        validate_fact_binding(&wrong_repo, &auth),
        Err(RecoveryRefusal::RepositoryMismatch)
    );

    let mut wrong_ref = good.clone();
    wrong_ref.target_ref = RefName::new("refs/heads/main");
    assert_eq!(
        validate_fact_binding(&wrong_ref, &auth),
        Err(RecoveryRefusal::TargetRefMismatch)
    );

    let mut wrong_basis = good.clone();
    wrong_basis.basis = CommitHash::new("basis-zzz");
    assert_eq!(
        validate_fact_binding(&wrong_basis, &auth),
        Err(RecoveryRefusal::BasisMismatch)
    );

    let mut wrong_attempt = good.clone();
    wrong_attempt.attempt = AttemptId::from_bytes([77; 16]);
    assert!(matches!(
        validate_fact_binding(&wrong_attempt, &auth),
        Err(RecoveryRefusal::AttemptMismatch { .. })
    ));

    let mut wrong_dispatch = good.clone();
    wrong_dispatch.dispatch = DispatchId::from_bytes([77; 16]);
    assert!(matches!(
        validate_fact_binding(&wrong_dispatch, &auth),
        Err(RecoveryRefusal::DispatchMismatch { .. })
    ));

    let mut wrong_digest = good.clone();
    wrong_digest.prepared_attempt_digest = Sha256Digest::of_bytes(b"another attempt");
    assert_eq!(
        validate_fact_binding(&wrong_digest, &auth),
        Err(RecoveryRefusal::BindingIncomplete)
    );
}

/// A correctly bound fact still resolves — in both directions.
#[test]
fn correctly_bound_facts_still_establish_their_verdicts() {
    let att = attempt();
    let auth = authoritative(&att);
    let base = RecoveryFact {
        id: RecoveryFactId::from_bytes([1; 16]),
        attempt: att.attempt_id,
        dispatch: DispatchId::from_bytes([8; 16]),
        prepared_attempt_digest: att.prepared_attempt_digest,
        repository: RepositoryIdentity::new(REAL_REPO),
        target_ref: RefName::new(REAL_REF),
        basis: CommitHash::new(REAL_BASIS),
        observed_ref: CommitHash::new(REAL_BASIS),
        expected_result_commit: Some(CommitHash::new(RESULT)),
        journal_digest: Sha256Digest::of_bytes(b"journal"),
        source: FactSource::RefInspection,
        recorded_at: ClockReading(90),
    };

    // Ref still at the attempt's real basis: the effect did not land.
    assert_eq!(validate_fact_binding(&base, &auth), Ok(()));
    assert_eq!(
        base.establishes(&auth),
        Some(RecoveryVerdict::ProvenNotCommitted)
    );

    // Ref at exactly the commit the journal said this dispatch would produce.
    let mut committed = base.clone();
    committed.observed_ref = CommitHash::new(RESULT);
    assert_eq!(validate_fact_binding(&committed, &auth), Ok(()));
    assert_eq!(
        committed.establishes(&auth),
        Some(RecoveryVerdict::CommittedViaRecovery)
    );

    // Ref somewhere else entirely: conflicting evidence resolves nothing and
    // the attempt stays indeterminate.
    let mut third_party = base.clone();
    third_party.observed_ref = CommitHash::new("someone-elses-commit");
    assert_eq!(validate_fact_binding(&third_party, &auth), Ok(()));
    assert_eq!(third_party.establishes(&auth), None);
}

/// A "result" equal to the basis is not a commitment: the ref never moved.
#[test]
fn expected_result_equal_to_basis_is_not_a_commitment() {
    let att = attempt();
    let auth = authoritative(&att);
    let degenerate = RecoveryFact {
        id: RecoveryFactId::from_bytes([1; 16]),
        attempt: att.attempt_id,
        dispatch: DispatchId::from_bytes([8; 16]),
        prepared_attempt_digest: att.prepared_attempt_digest,
        repository: RepositoryIdentity::new(REAL_REPO),
        target_ref: RefName::new(REAL_REF),
        basis: CommitHash::new(REAL_BASIS),
        observed_ref: CommitHash::new(REAL_BASIS),
        expected_result_commit: Some(CommitHash::new(REAL_BASIS)),
        journal_digest: Sha256Digest::of_bytes(b"journal"),
        source: FactSource::OperatorSupplied("claims basis is the result".into()),
        recorded_at: ClockReading(90),
    };
    assert_eq!(
        degenerate.establishes(&auth),
        Some(RecoveryVerdict::ProvenNotCommitted)
    );
}
