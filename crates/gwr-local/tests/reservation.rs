//! Task 7 reservation tests: exclusive, one-use, expiring, attempt-bound.

use gwr_core::bridge::reservation_to_dispatch as rsv_bridge;
use gwr_core::digest::Sha256Digest;
use gwr_core::domain::standing::{GrantState, StandingAct, StandingGrant, StandingScope};
use gwr_core::effect_spec::GitRefEffect;
use gwr_core::ids::*;
use gwr_core::lifecycle::AttemptState;
use gwr_core::observation_plan::ObservationPlan;
use gwr_core::prepared_attempt::PreparedAttempt;
use gwr_core::refusal::ReservationRefusal;
use gwr_core::work_request::{ClockReading, CommitHash, RefName, RepositoryIdentity};
use gwr_local::adapters::{FixedClock, HashChainIds};
use gwr_local::store::SqliteStore;
use gwr_runtime::ports::store::Store;
use gwr_runtime::services::ratification::ratify;
use gwr_runtime::services::reservation::{reserve, ReserveError};

fn attempt(byte: u8) -> PreparedAttempt {
    PreparedAttempt::admit(
        AttemptId::from_bytes([byte; 16]),
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

/// Admit and ratify an attempt so it is reservable; returns its ratification.
fn admit_and_ratify(
    store: &mut SqliteStore,
    ids: &mut HashChainIds,
    att: &PreparedAttempt,
    grant_byte: u8,
) -> gwr_core::lifecycle::RatificationRef {
    store.admit_attempt(att).unwrap();
    let grant = StandingGrant {
        id: StandingGrantId::from_bytes([grant_byte; 16]),
        scope: StandingScope {
            actor: ActorId::from_bytes([4; 16]),
            act: StandingAct::Ratify,
            repository: att.repository.clone(),
            attempt_digest: att.prepared_attempt_digest,
        },
        expires_at: ClockReading(10_000),
        state: GrantState::Available,
    };
    store.create_standing_grant(&grant).unwrap();
    let clock = FixedClock(ClockReading(10));
    ratify(
        store,
        att.attempt_id,
        grant.id,
        ActorId::from_bytes([4; 16]),
        att.prepared_attempt_digest,
        att.basis.clone(),
        &clock,
        ids,
    )
    .unwrap();
    let projected = store.get_attempt(att.attempt_id).unwrap();
    match projected.state {
        AttemptState::Ratified { ratification } => ratification,
        other => panic!("expected ratified, got {other:?}"),
    }
}

#[test]
fn reserve_then_conflict_then_free_after_consumption() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let mut ids = HashChainIds::new();
    let att = attempt(9);
    let rat = admit_and_ratify(&mut store, &mut ids, &att, 3);
    let clock = FixedClock(ClockReading(20));
    let claim = reserve(&mut store, att.attempt_id, 500, &clock, &mut ids).unwrap();
    let projected = store.get_attempt(att.attempt_id).unwrap();
    assert!(matches!(projected.state, AttemptState::Reserved { .. }));

    // A second attempt on the same repo+ref conflicts while the claim is alive.
    let other = attempt(10);
    admit_and_ratify(&mut store, &mut ids, &other, 5);
    assert_eq!(
        reserve(&mut store, other.attempt_id, 500, &clock, &mut ids).unwrap_err(),
        ReserveError::Conflict
    );

    // Consume the first claim through the dispatch bridge; the ref frees.
    let out = rsv_bridge::cross(rsv_bridge::Input {
        version: 1,
        claim: &claim,
        ratification: &rat,
        attempt: &att,
        existing_dispatch: None,
        now: ClockReading(30),
        new_dispatch: DispatchId::from_bytes([8; 16]),
        new_use: ReservationUseId::from_bytes([9; 16]),
    })
    .unwrap();
    let dispatching = projected
        .state
        .dispatch(out.reservation_ref.clone(), out.dispatch_ref.clone())
        .unwrap();
    store
        .record_dispatch(
            projected.version,
            &out.envelope,
            &dispatching,
            &out.consumed_claim,
        )
        .unwrap();
    // Now the other attempt can reserve.
    reserve(&mut store, other.attempt_id, 500, &clock, &mut ids).unwrap();
}

#[test]
fn expired_reservation_cannot_be_consumed() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let mut ids = HashChainIds::new();
    let att = attempt(9);
    let rat = admit_and_ratify(&mut store, &mut ids, &att, 3);
    let clock = FixedClock(ClockReading(20));
    let claim = reserve(&mut store, att.attempt_id, 100, &clock, &mut ids).unwrap();
    // Consumption attempted after expiry (20 + 100 < 500).
    let out = rsv_bridge::cross(rsv_bridge::Input {
        version: 1,
        claim: &claim,
        ratification: &rat,
        attempt: &att,
        existing_dispatch: None,
        now: ClockReading(500),
        new_dispatch: DispatchId::from_bytes([8; 16]),
        new_use: ReservationUseId::from_bytes([9; 16]),
    });
    assert_eq!(
        out.unwrap_err(),
        rsv_bridge::Refusal::Reservation(ReservationRefusal::Expired)
    );
}

#[test]
fn wrong_attempt_reservation_cannot_dispatch_and_replay_is_refused() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let mut ids = HashChainIds::new();
    let att = attempt(9);
    let rat = admit_and_ratify(&mut store, &mut ids, &att, 3);
    let clock = FixedClock(ClockReading(20));
    let claim = reserve(&mut store, att.attempt_id, 500, &clock, &mut ids).unwrap();

    // A claim doctored to name another attempt cannot permit dispatch for it.
    let other = attempt(10);
    let mut foreign_claim = claim.clone();
    foreign_claim.attempt = other.attempt_id;
    // (The store's claim is authoritative; but even at the pure layer the
    // bridge refuses the mismatch between claim and attempt.)
    let out = rsv_bridge::cross(rsv_bridge::Input {
        version: 1,
        claim: &foreign_claim,
        ratification: &rat,
        attempt: &att,
        existing_dispatch: None,
        now: ClockReading(30),
        new_dispatch: DispatchId::from_bytes([8; 16]),
        new_use: ReservationUseId::from_bytes([9; 16]),
    });
    assert_eq!(
        out.unwrap_err(),
        rsv_bridge::Refusal::Reservation(ReservationRefusal::AttemptMismatch)
    );

    // Legitimate consumption once; store-level replay refuses.
    let out = rsv_bridge::cross(rsv_bridge::Input {
        version: 1,
        claim: &claim,
        ratification: &rat,
        attempt: &att,
        existing_dispatch: None,
        now: ClockReading(30),
        new_dispatch: DispatchId::from_bytes([8; 16]),
        new_use: ReservationUseId::from_bytes([9; 16]),
    })
    .unwrap();
    let projected = store.get_attempt(att.attempt_id).unwrap();
    let dispatching = projected
        .state
        .dispatch(out.reservation_ref.clone(), out.dispatch_ref.clone())
        .unwrap();
    store
        .record_dispatch(
            projected.version,
            &out.envelope,
            &dispatching,
            &out.consumed_claim,
        )
        .unwrap();
    // Replay the same consumed claim at the store: refused.
    let replay = store.record_dispatch(
        projected.version + 1,
        &out.envelope,
        &dispatching,
        &out.consumed_claim,
    );
    assert!(replay.is_err());
    // And at the bridge, the consumed claim refuses too.
    let bridge_replay = rsv_bridge::cross(rsv_bridge::Input {
        version: 1,
        claim: &out.consumed_claim,
        ratification: &rat,
        attempt: &att,
        existing_dispatch: None,
        now: ClockReading(40),
        new_dispatch: DispatchId::from_bytes([88; 16]),
        new_use: ReservationUseId::from_bytes([99; 16]),
    });
    assert_eq!(
        bridge_replay.unwrap_err(),
        rsv_bridge::Refusal::Reservation(ReservationRefusal::AlreadyUsed)
    );
}

#[test]
fn malformed_reserve_requests_do_not_consume_unrelated_resources() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let mut ids = HashChainIds::new();
    let att = attempt(9);
    store.admit_attempt(&att).unwrap();
    // Attempt not ratified: reserve refuses at the transition and creates no
    // claim, so the target ref is not held.
    let clock = FixedClock(ClockReading(20));
    let err = reserve(&mut store, att.attempt_id, 500, &clock, &mut ids).unwrap_err();
    assert!(matches!(err, ReserveError::Transition(_)));
    // The ref is free: after ratifying, reservation succeeds immediately.
    admit_and_ratify(&mut store, &mut ids, &att, 3);
    reserve(&mut store, att.attempt_id, 500, &clock, &mut ids).unwrap();
}
