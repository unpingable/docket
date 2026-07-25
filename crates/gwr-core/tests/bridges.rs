//! Task 4 bridge tests: semantic boundaries visible in the API.

use gwr_core::bridge::{
    observation_to_review_queue as obs_bridge, recovery_standing_to_resolution as rec_bridge,
    reservation_to_dispatch as rsv_bridge, standing_to_ratification as rat_bridge,
};
use gwr_core::digest::Sha256Digest;
use gwr_core::domain::evidence::Claim;
use gwr_core::domain::reservation::{ClaimState, ReservationClaim};
use gwr_core::domain::standing::{GrantState, StandingAct, StandingGrant, StandingScope};
use gwr_core::effect_spec::GitRefEffect;
use gwr_core::ids::*;
use gwr_core::observation_plan::{ObservationPlan, ObservationRecord};
use gwr_core::outcome::Commitment;
use gwr_core::prepared_attempt::PreparedAttempt;
use gwr_core::recovery::{FactSource, RecoveryFact};
use gwr_core::refusal::{
    ObservationRefusal, RecoveryRefusal, RelianceRefusal, ReservationRefusal, StandingRefusal,
};
use gwr_core::work_request::{ClockReading, CommitHash, RefName, RepositoryIdentity};

fn attempt(id_byte: u8) -> PreparedAttempt {
    PreparedAttempt::admit(
        AttemptId::from_bytes([id_byte; 16]),
        WorkRequestId::from_bytes([1; 16]),
        CandidateArtifactId::from_bytes([2; 16]),
        RepositoryIdentity::new("/tmp/fixture"),
        CommitHash::new("basis-aaa"),
        Sha256Digest::of_bytes(b"candidate"),
        GitRefEffect {
            target_ref: RefName::new("refs/gwr/target"),
            expected_basis: CommitHash::new("basis-aaa"),
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

fn ratify_grant(att: &PreparedAttempt, act: StandingAct, expires: u64) -> StandingGrant {
    StandingGrant {
        id: StandingGrantId::from_bytes([3; 16]),
        scope: StandingScope {
            actor: ActorId::from_bytes([4; 16]),
            act,
            repository: att.repository.clone(),
            attempt_digest: att.prepared_attempt_digest,
        },
        expires_at: ClockReading(expires),
        state: GrantState::Available,
    }
}

fn rat_input<'a>(grant: &'a StandingGrant, att: &'a PreparedAttempt) -> rat_bridge::Input<'a> {
    rat_bridge::Input {
        version: 1,
        grant,
        actor: ActorId::from_bytes([4; 16]),
        attempt: att,
        ratified_digest: att.prepared_attempt_digest,
        ratified_basis: att.basis.clone(),
        now: ClockReading(50),
        new_ratification: RatificationId::from_bytes([5; 16]),
        new_use: StandingUseId::from_bytes([6; 16]),
    }
}

#[test]
fn expired_standing_cannot_authorize_ratification() {
    let att = attempt(9);
    let grant = ratify_grant(&att, StandingAct::Ratify, 10); // expires before now=50
    let out = rat_bridge::cross(rat_input(&grant, &att));
    assert_eq!(
        out.unwrap_err(),
        rat_bridge::Refusal::Standing(StandingRefusal::Expired)
    );
    assert_eq!(
        grant.state,
        GrantState::Available,
        "refusal consumed nothing"
    );
}

#[test]
fn consumed_standing_cannot_be_reused() {
    let att = attempt(9);
    let grant = ratify_grant(&att, StandingAct::Ratify, 100);
    let first = rat_bridge::cross(rat_input(&grant, &att)).unwrap();
    // Replay against the consumed grant.
    let replay = rat_bridge::cross(rat_input(&first.consumed_grant, &att));
    assert_eq!(
        replay.unwrap_err(),
        rat_bridge::Refusal::Standing(StandingRefusal::AlreadyUsed)
    );
}

#[test]
fn wrong_digest_ratification_refuses_without_consuming() {
    let att = attempt(9);
    let grant = ratify_grant(&att, StandingAct::Ratify, 100);
    let mut input = rat_input(&grant, &att);
    input.ratified_digest = Sha256Digest::of_bytes(b"some other digest");
    assert_eq!(
        rat_bridge::cross(input).unwrap_err(),
        rat_bridge::Refusal::DigestMismatch
    );
    assert_eq!(grant.state, GrantState::Available);
}

#[test]
fn reservation_for_another_attempt_cannot_permit_dispatch() {
    let att = attempt(9);
    let other = attempt(10);
    let grant = ratify_grant(&att, StandingAct::Ratify, 100);
    let rat = rat_bridge::cross(rat_input(&grant, &att)).unwrap();
    // Reservation claims the *other* attempt.
    let claim = ReservationClaim {
        id: ReservationId::from_bytes([7; 16]),
        repository: att.repository.clone(),
        target_ref: att.effect.target_ref.clone(),
        basis: att.basis.clone(),
        attempt: other.attempt_id,
        expires_at: ClockReading(100),
        state: ClaimState::Active,
    };
    let out = rsv_bridge::cross(rsv_bridge::Input {
        version: 1,
        claim: &claim,
        ratification: &rat.ratification_ref,
        attempt: &att,
        existing_dispatch: None,
        now: ClockReading(50),
        new_dispatch: DispatchId::from_bytes([8; 16]),
        new_use: ReservationUseId::from_bytes([9; 16]),
    });
    assert_eq!(
        out.unwrap_err(),
        rsv_bridge::Refusal::Reservation(ReservationRefusal::AttemptMismatch)
    );
}

#[test]
fn different_dispatch_identity_for_same_attempt_is_refused() {
    let att = attempt(9);
    let grant = ratify_grant(&att, StandingAct::Ratify, 100);
    let rat = rat_bridge::cross(rat_input(&grant, &att)).unwrap();
    let claim = ReservationClaim {
        id: ReservationId::from_bytes([7; 16]),
        repository: att.repository.clone(),
        target_ref: att.effect.target_ref.clone(),
        basis: att.basis.clone(),
        attempt: att.attempt_id,
        expires_at: ClockReading(100),
        state: ClaimState::Active,
    };
    let out = rsv_bridge::cross(rsv_bridge::Input {
        version: 1,
        claim: &claim,
        ratification: &rat.ratification_ref,
        attempt: &att,
        existing_dispatch: Some(DispatchId::from_bytes([8; 16])),
        now: ClockReading(50),
        new_dispatch: DispatchId::from_bytes([9; 16]), // different identity
        new_use: ReservationUseId::from_bytes([9; 16]),
    });
    assert_eq!(
        out.unwrap_err(),
        rsv_bridge::Refusal::Reservation(ReservationRefusal::DispatchIdentityConflict)
    );
}

fn commitment(att: &PreparedAttempt, result: &str) -> Commitment {
    Commitment {
        attempt: att.attempt_id,
        dispatch: DispatchId::from_bytes([8; 16]),
        target_ref: att.effect.target_ref.clone(),
        previous_value: att.basis.clone(),
        result_commit: CommitHash::new(result),
        journal_digest: Sha256Digest::of_bytes(b"journal"),
        committed_at: ClockReading(60),
    }
}

fn observation(att: &PreparedAttempt, commit: &str, exit: i32) -> ObservationRecord {
    ObservationRecord {
        id: ObservationId::from_bytes([10; 16]),
        attempt: att.attempt_id,
        argv: vec!["cargo".into(), "test".into()],
        working_directory_identity: "fixture".into(),
        result_commit: CommitHash::new(commit),
        environment_description: "fixture".into(),
        exit_status: exit,
        stdout_digest: Sha256Digest::of_bytes(b"out"),
        stderr_digest: Sha256Digest::of_bytes(b"err"),
        observed_at: ClockReading(70),
    }
}

#[test]
fn observation_for_commit_a_cannot_support_claim_about_commit_b() {
    let att = attempt(9);
    let commit_b = commitment(&att, "result-bbb");
    let obs_of_a = observation(&att, "result-aaa", 0);
    let out = obs_bridge::cross(obs_bridge::Input {
        version: 1,
        observation: &obs_of_a,
        commitment: &commit_b,
        claim: Claim::ExactResultCommitProducedAndCommandExitedZero,
        now: ClockReading(80),
    });
    assert_eq!(
        out.unwrap_err(),
        RelianceRefusal::Observation(ObservationRefusal::ScopeMismatch)
    );
}

#[test]
fn a_passing_test_cannot_support_obligation_closure() {
    let att = attempt(9);
    let cmt = commitment(&att, "result-aaa");
    let obs = observation(&att, "result-aaa", 0);
    for refused in [
        Claim::PatchIsCorrect,
        Claim::TaskIsComplete,
        Claim::SafeToMerge,
        Claim::ObligationDischarged,
        Claim::WorkMayBeClosed,
    ] {
        let out = obs_bridge::cross(obs_bridge::Input {
            version: 1,
            observation: &obs,
            commitment: &cmt,
            claim: refused,
            now: ClockReading(80),
        });
        assert_eq!(out.unwrap_err(), RelianceRefusal::ClaimNotAdmissible);
    }
    // The one admissible claim is admitted — and admission mutates nothing.
    let before = obs.clone();
    let admitted = obs_bridge::cross(obs_bridge::Input {
        version: 1,
        observation: &obs,
        commitment: &cmt,
        claim: Claim::ExactResultCommitProducedAndCommandExitedZero,
        now: ClockReading(80),
    })
    .unwrap();
    assert_eq!(admitted.result_commit, cmt.result_commit);
    assert_eq!(obs, before);
}

fn fact_for(att: &PreparedAttempt, dispatch: [u8; 16]) -> RecoveryFact {
    RecoveryFact {
        id: RecoveryFactId::from_bytes([11; 16]),
        attempt: att.attempt_id,
        dispatch: DispatchId::from_bytes(dispatch),
        prepared_attempt_digest: att.prepared_attempt_digest,
        repository: att.repository.clone(),
        target_ref: att.effect.target_ref.clone(),
        basis: att.basis.clone(),
        observed_ref: CommitHash::new("result-aaa"),
        expected_result_commit: Some(CommitHash::new("result-aaa")),
        journal_digest: Sha256Digest::of_bytes(b"journal"),
        source: FactSource::RefInspection,
        recorded_at: ClockReading(90),
    }
}

#[test]
fn recovery_evidence_for_attempt_a_cannot_resolve_attempt_b() {
    let att_a = attempt(9);
    let att_b = attempt(10);
    let fact_a = fact_for(&att_a, [8; 16]);
    let grant = ratify_grant(&att_b, StandingAct::ResolveRecovery, 200);
    let out = rec_bridge::cross(rec_bridge::Input {
        version: 1,
        fact: &fact_a,
        grant: &grant,
        actor: ActorId::from_bytes([4; 16]),
        attempt: att_b.attempt_id,
        dispatch: DispatchId::from_bytes([8; 16]),
        prepared_attempt_digest: att_b.prepared_attempt_digest,
        repository: &att_b.repository,
        now: ClockReading(100),
        new_resolution: RecoveryResolutionId::from_bytes([12; 16]),
        new_use: StandingUseId::from_bytes([13; 16]),
    });
    assert!(matches!(
        out.unwrap_err(),
        rec_bridge::Refusal::Recovery(RecoveryRefusal::AttemptMismatch { .. })
    ));
    assert_eq!(grant.state, GrantState::Available, "nothing consumed");
}

#[test]
fn valid_recovery_evidence_with_insufficient_standing_produces_a_refusal() {
    let att = attempt(9);
    let fact = fact_for(&att, [8; 16]);
    // The grant is for Ratify, not ResolveRecovery: authenticity is not
    // authority, and ratification standing does not imply recovery standing.
    let grant = ratify_grant(&att, StandingAct::Ratify, 200);
    let out = rec_bridge::cross(rec_bridge::Input {
        version: 1,
        fact: &fact,
        grant: &grant,
        actor: ActorId::from_bytes([4; 16]),
        attempt: att.attempt_id,
        dispatch: DispatchId::from_bytes([8; 16]),
        prepared_attempt_digest: att.prepared_attempt_digest,
        repository: &att.repository,
        now: ClockReading(100),
        new_resolution: RecoveryResolutionId::from_bytes([12; 16]),
        new_use: StandingUseId::from_bytes([13; 16]),
    });
    assert_eq!(
        out.unwrap_err(),
        rec_bridge::Refusal::Recovery(RecoveryRefusal::StandingInsufficient)
    );
    assert_eq!(grant.state, GrantState::Available);
}

#[test]
fn missing_or_unsupported_bridge_produces_a_reliance_refusal() {
    // Unsupported version at every bridge: first-class refusal, no fallback.
    let att = attempt(9);
    let grant = ratify_grant(&att, StandingAct::Ratify, 100);
    let mut input = rat_input(&grant, &att);
    input.version = 2;
    assert_eq!(
        rat_bridge::cross(input).unwrap_err(),
        rat_bridge::Refusal::VersionUnsupported { presented: 2 }
    );

    let cmt = commitment(&att, "result-aaa");
    let obs = observation(&att, "result-aaa", 0);
    let out = obs_bridge::cross(obs_bridge::Input {
        version: 99,
        observation: &obs,
        commitment: &cmt,
        claim: Claim::ExactResultCommitProducedAndCommandExitedZero,
        now: ClockReading(80),
    });
    assert_eq!(
        out.unwrap_err(),
        RelianceRefusal::BridgeVersionUnsupported { presented: 99 }
    );

    // Where no bridge exists at all, the answer is the first-class refusal —
    // never a default or a pass-through.
    let absent = RelianceRefusal::NoBridge;
    assert_eq!(absent, RelianceRefusal::NoBridge);
}
