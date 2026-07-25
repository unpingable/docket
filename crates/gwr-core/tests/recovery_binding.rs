//! Regression suite for the recovery-evidence defects.
//!
//! Round one (Task 12 audit): `validate_fact_binding` checked only attempt,
//! dispatch, and prepared-attempt digest, and the verdict was read off the
//! fact's own copy of the basis.
//!
//! Round two (V2, blind adversarial review): the verdict was still derived from
//! the fact's `observed_ref` and `expected_result_commit`. A fact with every
//! *checked* binding copied faithfully and invented result fields minted
//! `CommittedViaRecovery` for an effect that never landed — including by
//! claiming another attempt's commit.
//!
//! The verdict now comes from `AuthoritativeBinding` — the runtime's own
//! records — and the fact must merely agree with it.

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
const OUR_RESULT: &str = "result-ccc";
const OTHER_ATTEMPT_COMMIT: &str = "result-bbb-owned-by-attempt-b";

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

/// The runtime's record: its own ref reading, its own digest-verified journal.
struct World {
    journal_digest: Sha256Digest,
    observed_ref: CommitHash,
    expected_result: Option<CommitHash>,
    observed_ref_owner: Option<AttemptId>,
}

fn world(observed: &str, expected: Option<&str>, owner: Option<AttemptId>) -> World {
    World {
        journal_digest: Sha256Digest::of_bytes(b"the real journal"),
        observed_ref: CommitHash::new(observed),
        expected_result: expected.map(CommitHash::new),
        observed_ref_owner: owner,
    }
}

fn auth<'a>(att: &'a PreparedAttempt, w: &'a World) -> AuthoritativeBinding<'a> {
    AuthoritativeBinding {
        attempt: att.attempt_id,
        dispatch: DispatchId::from_bytes([8; 16]),
        prepared_attempt_digest: &att.prepared_attempt_digest,
        repository: &att.repository,
        target_ref: &att.effect.target_ref,
        basis: &att.effect.expected_basis,
        journal_digest: &w.journal_digest,
        observed_ref: &w.observed_ref,
        expected_result: w.expected_result.as_ref(),
        observed_ref_owner: w.observed_ref_owner,
    }
}

/// A fact that faithfully reports the runtime's record.
fn truthful_fact(att: &PreparedAttempt, w: &World) -> RecoveryFact {
    RecoveryFact {
        id: RecoveryFactId::from_bytes([1; 16]),
        attempt: att.attempt_id,
        dispatch: DispatchId::from_bytes([8; 16]),
        prepared_attempt_digest: att.prepared_attempt_digest,
        repository: RepositoryIdentity::new(REAL_REPO),
        target_ref: RefName::new(REAL_REF),
        basis: CommitHash::new(REAL_BASIS),
        observed_ref: w.observed_ref.clone(),
        expected_result_commit: w.expected_result.clone(),
        journal_digest: w.journal_digest,
        source: FactSource::RefInspection,
        recorded_at: ClockReading(90),
    }
}

// ---------------------------------------------------------------- round one

/// The Task 12 witness, unchanged in construction: correct attempt, dispatch,
/// and digest; foreign repository, ref, and basis.
#[test]
fn contradictory_context_is_refused() {
    let att = attempt();
    let w = world(REAL_BASIS, None, None);
    let a = auth(&att, &w);
    let mut contradictory = truthful_fact(&att, &w);
    contradictory.repository = RepositoryIdentity::new("/some/entirely/other/repo");
    contradictory.target_ref = RefName::new("refs/heads/unrelated");
    contradictory.basis = CommitHash::new("a-basis-the-attempt-never-had");
    assert_eq!(
        validate_fact_binding(&contradictory, &a),
        Err(RecoveryRefusal::RepositoryMismatch)
    );
}

#[test]
fn each_contextual_binding_is_checked_independently() {
    let att = attempt();
    let w = world(REAL_BASIS, Some(OUR_RESULT), None);
    let a = auth(&att, &w);
    let good = truthful_fact(&att, &w);
    assert_eq!(validate_fact_binding(&good, &a), Ok(()));

    /// One mutation of a binding field and the refusal it must produce.
    type Case = (
        &'static str,
        Box<dyn Fn(&mut RecoveryFact)>,
        RecoveryRefusal,
    );

    let cases: Vec<Case> = vec![
        (
            "repository",
            Box::new(|f: &mut RecoveryFact| f.repository = RepositoryIdentity::new("/elsewhere")),
            RecoveryRefusal::RepositoryMismatch,
        ),
        (
            "target_ref",
            Box::new(|f: &mut RecoveryFact| f.target_ref = RefName::new("refs/heads/main")),
            RecoveryRefusal::TargetRefMismatch,
        ),
        (
            "basis",
            Box::new(|f: &mut RecoveryFact| f.basis = CommitHash::new("basis-zzz")),
            RecoveryRefusal::BasisMismatch,
        ),
        (
            "prepared_attempt_digest",
            Box::new(|f: &mut RecoveryFact| {
                f.prepared_attempt_digest = Sha256Digest::of_bytes(b"another attempt")
            }),
            RecoveryRefusal::BindingIncomplete,
        ),
        (
            "journal_digest",
            Box::new(|f: &mut RecoveryFact| {
                f.journal_digest = Sha256Digest::of_bytes(b"a different journal")
            }),
            RecoveryRefusal::JournalDigestMismatch,
        ),
        (
            "observed_ref",
            Box::new(|f: &mut RecoveryFact| f.observed_ref = CommitHash::new("invented")),
            RecoveryRefusal::ObservedRefMismatch,
        ),
        (
            "expected_result_commit",
            Box::new(|f: &mut RecoveryFact| {
                f.expected_result_commit = Some(CommitHash::new("invented"))
            }),
            RecoveryRefusal::ExpectedResultMismatch,
        ),
    ];
    for (field, mutate, expected) in cases {
        let mut f = good.clone();
        mutate(&mut f);
        assert_eq!(
            validate_fact_binding(&f, &a),
            Err(expected),
            "mutating {field} must be refused"
        );
    }

    let mut wrong_attempt = good.clone();
    wrong_attempt.attempt = AttemptId::from_bytes([77; 16]);
    assert!(matches!(
        validate_fact_binding(&wrong_attempt, &a),
        Err(RecoveryRefusal::AttemptMismatch { .. })
    ));
    let mut wrong_dispatch = good.clone();
    wrong_dispatch.dispatch = DispatchId::from_bytes([77; 16]);
    assert!(matches!(
        validate_fact_binding(&wrong_dispatch, &a),
        Err(RecoveryRefusal::DispatchMismatch { .. })
    ));
}

// ---------------------------------------------------------------- round two

/// V2's port-level witness: every checked binding copied faithfully, result
/// fields invented. The fact can no longer contribute a verdict at all, and its
/// invented readings now disagree with the record and are refused.
#[test]
fn self_authored_result_fields_cannot_mint_a_commitment() {
    let att = attempt();
    // The runtime read the ref and found it still at the basis: nothing landed.
    let w = world(REAL_BASIS, None, None);
    let a = auth(&att, &w);

    let mut fabricated = truthful_fact(&att, &w);
    fabricated.observed_ref = CommitHash::new(OUR_RESULT);
    fabricated.expected_result_commit = Some(CommitHash::new(OUR_RESULT));
    fabricated.journal_digest = Sha256Digest::of_bytes(b"a journal I wrote myself");
    fabricated.source = FactSource::BrokerJournal;

    // Refused as evidence...
    assert_eq!(
        validate_fact_binding(&fabricated, &a),
        Err(RecoveryRefusal::JournalDigestMismatch)
    );
    // ...and even waiving that, the record — not the fact — decides, and the
    // record says the ref never moved.
    assert_eq!(a.establishes(), Some(RecoveryVerdict::ProvenNotCommitted));
}

/// A commit belonging to another attempt is structurally incapable of settling
/// this one, in either direction.
#[test]
fn another_attempts_commit_cannot_settle_this_attempt() {
    let att = attempt();
    let attempt_b = AttemptId::from_bytes([22; 16]);
    // The ref holds B's commit; the ledger attributes it to B.
    let w = world(
        OTHER_ATTEMPT_COMMIT,
        Some(OTHER_ATTEMPT_COMMIT),
        Some(attempt_b),
    );
    let a = auth(&att, &w);
    // Even with the journal claiming that commit as our expected result — the
    // tampered-journal scenario — the verdict is withheld.
    assert_eq!(a.establishes(), None);
}

/// Our own commit still settles our own attempt.
#[test]
fn our_own_commit_settles_our_own_attempt() {
    let att = attempt();
    let w = world(OUR_RESULT, Some(OUR_RESULT), Some(att.attempt_id));
    let a = auth(&att, &w);
    assert_eq!(a.establishes(), Some(RecoveryVerdict::CommittedViaRecovery));
    assert_eq!(validate_fact_binding(&truthful_fact(&att, &w), &a), Ok(()));
}

#[test]
fn correctly_bound_facts_still_establish_their_verdicts() {
    let att = attempt();

    // Ref at the attempt's real basis: the effect did not land.
    let not_committed = world(REAL_BASIS, Some(OUR_RESULT), None);
    let a = auth(&att, &not_committed);
    assert_eq!(
        validate_fact_binding(&truthful_fact(&att, &not_committed), &a),
        Ok(())
    );
    assert_eq!(a.establishes(), Some(RecoveryVerdict::ProvenNotCommitted));

    // Ref at exactly what this dispatch's journal recorded creating.
    let committed = world(OUR_RESULT, Some(OUR_RESULT), None);
    let a = auth(&att, &committed);
    assert_eq!(
        validate_fact_binding(&truthful_fact(&att, &committed), &a),
        Ok(())
    );
    assert_eq!(a.establishes(), Some(RecoveryVerdict::CommittedViaRecovery));

    // Ref somewhere else entirely, unattributed: conflicting, resolves nothing.
    let third_party = world("someone-elses-commit", Some(OUR_RESULT), None);
    let a = auth(&att, &third_party);
    assert_eq!(a.establishes(), None);
}

/// A journal with no `commit_created` line yields no expected result, so a
/// moved ref cannot be read as our commitment.
#[test]
fn absent_expected_result_cannot_establish_commitment() {
    let att = attempt();
    let w = world("some-other-commit", None, None);
    let a = auth(&att, &w);
    assert_eq!(a.establishes(), None);
}

/// A "result" equal to the basis is not a commitment: the ref never moved.
#[test]
fn expected_result_equal_to_basis_is_not_a_commitment() {
    let att = attempt();
    let w = world(REAL_BASIS, Some(REAL_BASIS), None);
    let a = auth(&att, &w);
    assert_eq!(a.establishes(), Some(RecoveryVerdict::ProvenNotCommitted));
}
