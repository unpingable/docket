//! Task 5 persistence tests: durable exact state without event sourcing.

use gwr_core::bridge::{
    reservation_to_dispatch as rsv_bridge, standing_to_ratification as rat_bridge,
};
use gwr_core::digest::Sha256Digest;
use gwr_core::domain::reservation::{ClaimState, ReservationClaim};
use gwr_core::domain::standing::{
    GrantState, StandingAct, StandingGrant, StandingScope, StandingUse,
};
use gwr_core::effect_spec::GitRefEffect;
use gwr_core::ids::*;
use gwr_core::lifecycle::AttemptState;
use gwr_core::observation_plan::ObservationPlan;
use gwr_core::outcome::{Commitment, IndeterminateRecord};
use gwr_core::preparation::{CandidateArtifact, PreparationEnd, PreparationRun, PreparationStatus};
use gwr_core::prepared_attempt::PreparedAttempt;
use gwr_core::repository::{RepositoryAlias, RepositoryAliasKind, RepositoryRegistration};
use gwr_core::work_request::{ClockReading, CommitHash, RefName, RepositoryLocator, WorkRequest};
use gwr_local::store::SqliteStore;
use gwr_runtime::ports::store::{Store, StoreError};

fn attempt(byte: u8) -> PreparedAttempt {
    PreparedAttempt::admit(
        AttemptId::from_bytes([byte; 16]),
        WorkRequestId::from_bytes([1; 16]),
        CandidateArtifactId::from_bytes([2; 16]),
        RepositoryLocator::new("/tmp/fixture"),
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

fn grant_for(att: &PreparedAttempt, byte: u8) -> StandingGrant {
    StandingGrant::issue(
        StandingGrantId::from_bytes([byte; 16]),
        StandingScope {
            actor: ActorId::from_bytes([4; 16]),
            act: StandingAct::Ratify,
            repository: att.repository.clone(),
            attempt_digest: att.prepared_attempt_digest,
        },
        ClockReading(1000),
    )
}

fn claim_for(att: &PreparedAttempt, byte: u8) -> ReservationClaim {
    ReservationClaim::claim(
        ReservationId::from_bytes([byte; 16]),
        att.repository.clone(),
        att.effect.target_ref.clone(),
        att.basis.clone(),
        att.attempt_id,
        ClockReading(1000),
    )
}

/// Drive an attempt admission → ratified → reserved → dispatching. Returns the
/// dispatching state; the projection version afterwards is 3.
fn drive_to_dispatching(store: &mut SqliteStore, att: &PreparedAttempt) -> AttemptState {
    store.admit_attempt(att).unwrap();

    let grant = grant_for(att, 3);
    store.create_standing_grant(&grant).unwrap();
    let rat = rat_bridge::cross(rat_bridge::Input {
        version: 1,
        grant: &grant,
        actor: ActorId::from_bytes([4; 16]),
        attempt: att,
        ratified_digest: att.prepared_attempt_digest,
        ratified_basis: att.basis.clone(),
        now: ClockReading(10),
        new_ratification: RatificationId::from_bytes([5; 16]),
        new_use: StandingUseId::from_bytes([6; 16]),
    })
    .unwrap();
    let ratified = AttemptState::Prepared
        .ratify(rat.ratification_ref.clone())
        .unwrap();
    let standing_use = StandingUse {
        id: StandingUseId::from_bytes([6; 16]),
        grant: grant.id(),
        used_at: ClockReading(10),
    };
    store
        .record_ratification(0, &rat.receipt, &ratified, &grant, &standing_use)
        .unwrap();

    let claim = claim_for(att, 7);
    store.create_reservation(&claim, ClockReading(11)).unwrap();
    let reserved = ratified.reserve(claim.id()).unwrap();
    store
        .record_reserved(1, att.attempt_id, &reserved, ClockReading(11))
        .unwrap();

    let out = rsv_bridge::cross(rsv_bridge::Input {
        version: 1,
        claim: &claim,
        ratification: &rat.ratification_ref,
        attempt: att,
        existing_dispatch: None,
        now: ClockReading(12),
        new_dispatch: DispatchId::from_bytes([8; 16]),
        new_use: ReservationUseId::from_bytes([9; 16]),
    })
    .unwrap();
    let dispatching = reserved
        .dispatch(out.reservation_ref.clone(), out.dispatch_ref.clone())
        .unwrap();
    store
        .record_dispatch(2, &out.envelope, &dispatching, &out.consumed_claim)
        .unwrap();
    dispatching
}

fn temp_db(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("gwr-persist-{}-{}", name, std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("state.sqlite");
    let _ = std::fs::remove_file(&db);
    db
}

#[test]
fn pre_registry_database_migrates_with_repository_identity_unbound() {
    let db = temp_db("repository-migration");
    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE TABLE work_request (
                id TEXT PRIMARY KEY,
                repository TEXT NOT NULL,
                target_ref TEXT NOT NULL,
                goal TEXT NOT NULL,
                created_at INTEGER NOT NULL
             ) STRICT;
             INSERT INTO work_request
                (id, repository, target_ref, goal, created_at)
             VALUES
                ('01010101010101010101010101010101',
                 '/old/checkout',
                 'refs/gwr/target',
                 'legacy request',
                 1);",
        )
        .unwrap();
    }

    let mut store = SqliteStore::open(&db).unwrap();
    let legacy = store
        .get_work_request(WorkRequestId::from_bytes([1; 16]))
        .unwrap();
    assert_eq!(legacy.repository_id, None);
    assert_eq!(legacy.repository.as_str(), "/old/checkout");
    assert!(store
        .all_column_names()
        .unwrap()
        .contains(&"work_request.repository_id".to_string()));
    std::fs::remove_file(&db).unwrap();
}

#[test]
fn every_state_survives_close_and_reopen() {
    let db = temp_db("states");
    let att = attempt(9);
    let dispatching;
    {
        let mut store = SqliteStore::open(&db).unwrap();
        dispatching = drive_to_dispatching(&mut store, &att);
    }
    {
        let mut store = SqliteStore::open(&db).unwrap();
        let projected = store.get_attempt(att.attempt_id).unwrap();
        assert_eq!(projected.attempt, att);
        assert_eq!(projected.state, dispatching);
        assert!(matches!(projected.state, AttemptState::Dispatching { .. }));
        assert_eq!(projected.version, 3);
        // Advance to Committed and reopen once more.
        let committed_state = projected.state.commit().unwrap();
        let commitment = Commitment {
            attempt: att.attempt_id,
            dispatch: DispatchId::from_bytes([8; 16]),
            target_ref: att.effect.target_ref.clone(),
            previous_value: att.basis.clone(),
            result_commit: CommitHash::new("result-ccc"),
            journal_digest: Sha256Digest::of_bytes(b"journal"),
            committed_at: ClockReading(20),
        };
        store
            .record_commitment(3, &commitment, &committed_state)
            .unwrap();
    }
    let mut store = SqliteStore::open(&db).unwrap();
    let projected = store.get_attempt(att.attempt_id).unwrap();
    assert!(matches!(projected.state, AttemptState::Committed { .. }));
    assert_eq!(projected.version, 4);
    let stored = store.get_commitment(att.attempt_id).unwrap();
    assert_eq!(stored.result_commit, CommitHash::new("result-ccc"));
    std::fs::remove_file(&db).unwrap();
}

#[test]
fn indeterminate_survives_restart() {
    let db = temp_db("indeterminate");
    let att = attempt(9);
    {
        let mut store = SqliteStore::open(&db).unwrap();
        let dispatching = drive_to_dispatching(&mut store, &att);
        let indeterminate = dispatching.mark_indeterminate().unwrap();
        let record = IndeterminateRecord {
            attempt: att.attempt_id,
            dispatch: DispatchId::from_bytes([8; 16]),
            last_journal_digest: Some(Sha256Digest::of_bytes(b"journal")),
            recorded_at: ClockReading(20),
        };
        store
            .record_indeterminate(3, &record, &indeterminate)
            .unwrap();
    }
    let mut store = SqliteStore::open(&db).unwrap();
    let projected = store.get_attempt(att.attempt_id).unwrap();
    assert!(matches!(
        projected.state,
        AttemptState::Indeterminate { .. }
    ));
    assert_eq!(projected.version, 4);
    std::fs::remove_file(&db).unwrap();
}

#[test]
fn stale_optimistic_writes_fail() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let att = attempt(9);
    store.admit_attempt(&att).unwrap();
    let grant = grant_for(&att, 3);
    store.create_standing_grant(&grant).unwrap();
    let rat = rat_bridge::cross(rat_bridge::Input {
        version: 1,
        grant: &grant,
        actor: ActorId::from_bytes([4; 16]),
        attempt: &att,
        ratified_digest: att.prepared_attempt_digest,
        ratified_basis: att.basis.clone(),
        now: ClockReading(10),
        new_ratification: RatificationId::from_bytes([5; 16]),
        new_use: StandingUseId::from_bytes([6; 16]),
    })
    .unwrap();
    let ratified = AttemptState::Prepared
        .ratify(rat.ratification_ref.clone())
        .unwrap();
    let standing_use = StandingUse {
        id: StandingUseId::from_bytes([6; 16]),
        grant: grant.id(),
        used_at: ClockReading(10),
    };
    let err = store
        .record_ratification(5, &rat.receipt, &ratified, &grant, &standing_use)
        .unwrap_err();
    assert_eq!(
        err,
        StoreError::StaleVersion {
            expected: 5,
            actual: 0
        }
    );
    // The refused write consumed nothing: the grant is still available.
    let g = store.get_standing_grant(grant.id()).unwrap();
    assert_eq!(*g.state(), GrantState::Available);
}

#[test]
fn immutable_ids_cannot_be_rebound_to_different_content() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let att = attempt(9);
    store.admit_attempt(&att).unwrap();
    let altered = PreparedAttempt::admit(
        att.attempt_id,
        att.work_request,
        att.candidate,
        att.repository.clone(),
        CommitHash::new("basis-bbb"),
        att.artifact_digest,
        att.effect.clone(),
        att.observation_plan.clone(),
        att.admitted_at,
    );
    assert_eq!(
        store.admit_attempt(&altered).unwrap_err(),
        StoreError::ImmutableRebind
    );
    let wr = WorkRequest {
        id: WorkRequestId::from_bytes([1; 16]),
        repository_id: None,
        repository: RepositoryLocator::new("/tmp/fixture"),
        target_ref: RefName::new("refs/gwr/target"),
        goal: "make the test pass".into(),
        created_at: ClockReading(1),
    };
    store.create_work_request(&wr).unwrap();
    let mut wr2 = wr.clone();
    wr2.goal = "different goal".into();
    assert_eq!(
        store.create_work_request(&wr2).unwrap_err(),
        StoreError::ImmutableRebind
    );
}

#[test]
fn repository_identity_survives_path_relocation_and_aliases_cannot_be_rebound() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let repository_id = RepositoryId::from_bytes([0xa5; 16]);
    let old_path = RepositoryLocator::new("/srv/checkouts/project-a");
    let new_path = RepositoryLocator::new("/work/recloned/project-a");
    store
        .register_repository(&RepositoryRegistration {
            id: repository_id,
            registered_at: ClockReading(10),
            aliases: vec![RepositoryAlias {
                kind: RepositoryAliasKind::Path,
                locator: old_path.clone(),
                registered_at: ClockReading(10),
                current: true,
            }],
        })
        .unwrap();

    store
        .add_repository_alias(
            repository_id,
            &RepositoryAlias {
                kind: RepositoryAliasKind::Path,
                locator: new_path.clone(),
                registered_at: ClockReading(20),
                current: true,
            },
        )
        .unwrap();

    let registration = store.get_repository(repository_id).unwrap();
    assert_eq!(registration.id, repository_id);
    assert_eq!(registration.current_path(), Some(&new_path));
    assert!(registration.has_path(&old_path));
    assert!(registration.has_path(&new_path));
    assert_eq!(
        store
            .find_repository_by_path(&old_path)
            .unwrap()
            .unwrap()
            .id,
        repository_id,
        "the historical locator still resolves through the explicit registry"
    );
    assert_eq!(
        store
            .find_repository_by_path(&new_path)
            .unwrap()
            .unwrap()
            .id,
        repository_id
    );

    let other_id = RepositoryId::from_bytes([0xb6; 16]);
    store
        .register_repository(&RepositoryRegistration {
            id: other_id,
            registered_at: ClockReading(30),
            aliases: vec![RepositoryAlias {
                kind: RepositoryAliasKind::Path,
                locator: RepositoryLocator::new("/work/other"),
                registered_at: ClockReading(30),
                current: true,
            }],
        })
        .unwrap();

    let legacy_request = WorkRequest {
        id: WorkRequestId::from_bytes([0xc7; 16]),
        repository_id: None,
        repository: new_path.clone(),
        target_ref: RefName::new("refs/gwr/target"),
        goal: "legacy request".into(),
        created_at: ClockReading(32),
    };
    store.create_work_request(&legacy_request).unwrap();
    assert_eq!(
        store
            .get_work_request(legacy_request.id)
            .unwrap()
            .repository_id,
        None,
        "alias registration alone never promotes an existing work request"
    );
    store
        .bind_work_request_repository(legacy_request.id, repository_id)
        .unwrap();
    assert_eq!(
        store
            .get_work_request(legacy_request.id)
            .unwrap()
            .repository_id,
        Some(repository_id)
    );
    assert_eq!(
        store
            .add_repository_alias(
                other_id,
                &RepositoryAlias {
                    kind: RepositoryAliasKind::Path,
                    locator: old_path,
                    registered_at: ClockReading(31),
                    current: false,
                },
            )
            .unwrap_err(),
        StoreError::ImmutableRebind,
        "a locator already registered to one opaque identity cannot be laundered into another"
    );
    assert_eq!(
        store
            .bind_work_request_repository(legacy_request.id, other_id)
            .unwrap_err(),
        StoreError::ImmutableRebind,
        "an explicit legacy binding is immutable"
    );
}

#[test]
fn identical_duplicate_commands_are_idempotent() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let att = attempt(9);
    store.admit_attempt(&att).unwrap();
    store.admit_attempt(&att).unwrap();
    let wr = WorkRequest {
        id: WorkRequestId::from_bytes([1; 16]),
        repository_id: None,
        repository: RepositoryLocator::new("/tmp/fixture"),
        target_ref: RefName::new("refs/gwr/target"),
        goal: "make the test pass".into(),
        created_at: ClockReading(1),
    };
    store.create_work_request(&wr).unwrap();
    store.create_work_request(&wr).unwrap();
    let run = PreparationRun {
        id: PreparationRunId::from_bytes([2; 16]),
        work_request: wr.id,
        started_at: ClockReading(2),
        deadline: ClockReading(100),
        status: PreparationStatus::Running,
    };
    store.create_preparation_run(&run).unwrap();
    store.create_preparation_run(&run).unwrap();
    store
        .end_preparation_run(run.id, PreparationEnd::CandidateProduced, ClockReading(50))
        .unwrap();
    store
        .end_preparation_run(run.id, PreparationEnd::CandidateProduced, ClockReading(50))
        .unwrap();
    // A *different* end for the same run is a rebind.
    assert_eq!(
        store
            .end_preparation_run(run.id, PreparationEnd::ProviderFailed, ClockReading(51))
            .unwrap_err(),
        StoreError::ImmutableRebind
    );
    let cand = CandidateArtifact {
        id: CandidateArtifactId::from_bytes([2; 16]),
        preparation_run: run.id,
        content_digest: Sha256Digest::of_bytes(b"candidate"),
        content_len: 9,
        ingested_at: ClockReading(50),
    };
    store.ingest_candidate(&cand).unwrap();
    store.ingest_candidate(&cand).unwrap();
}

#[test]
fn standing_and_reservation_uses_are_single_use() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let att = attempt(9);
    drive_to_dispatching(&mut store, &att);
    let grant = store
        .get_standing_grant(StandingGrantId::from_bytes([3; 16]))
        .unwrap();
    assert!(matches!(grant.state(), GrantState::Consumed { .. }));
    let reservation = store
        .get_reservation(ReservationId::from_bytes([7; 16]))
        .unwrap();
    assert!(matches!(reservation.state(), ClaimState::Consumed { .. }));
    // Direct replay at the store layer refuses and consumes nothing further.
    let fresh_use = StandingUse {
        id: StandingUseId::from_bytes([99; 16]),
        grant: grant.id(),
        used_at: ClockReading(60),
    };
    let rat_receipt = gwr_core::receipt::RatificationReceipt {
        ratification: RatificationId::from_bytes([98; 16]),
        attempt: att.attempt_id,
        prepared_attempt_digest: att.prepared_attempt_digest,
        actor: ActorId::from_bytes([4; 16]),
        standing_use: fresh_use.id,
        clock_reading: ClockReading(60),
    };
    let err = store
        .record_ratification(3, &rat_receipt, &AttemptState::Prepared, &grant, &fresh_use)
        .unwrap_err();
    assert_eq!(err, StoreError::AlreadyConsumed);
}

#[test]
fn reservation_conflict_is_refused() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let att = attempt(9);
    let other = attempt(10);
    store.admit_attempt(&att).unwrap();
    store.admit_attempt(&other).unwrap();
    let claim = claim_for(&att, 7);
    store.create_reservation(&claim, ClockReading(11)).unwrap();
    let clash = claim_for(&other, 8);
    assert_eq!(
        store
            .create_reservation(&clash, ClockReading(12))
            .unwrap_err(),
        StoreError::ReservationConflict
    );
}

#[test]
fn provider_specific_fields_do_not_appear_in_core_tables() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let names = store.all_column_names().unwrap();
    assert!(!names.is_empty());
    for banned in ["provider", "codex", "claude", "session", "model"] {
        for col in &names {
            assert!(
                !col.to_lowercase().contains(banned),
                "provider-specific column {col} found"
            );
        }
    }
}

#[test]
fn historical_records_cannot_be_rewritten() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let att = attempt(9);
    drive_to_dispatching(&mut store, &att);
    let altered = PreparedAttempt::admit(
        att.attempt_id,
        att.work_request,
        att.candidate,
        att.repository.clone(),
        CommitHash::new("history-rewrite"),
        att.artifact_digest,
        att.effect.clone(),
        att.observation_plan.clone(),
        att.admitted_at,
    );
    assert_eq!(
        store.admit_attempt(&altered).unwrap_err(),
        StoreError::ImmutableRebind
    );
    let stored = store.get_attempt(att.attempt_id).unwrap();
    assert_eq!(stored.attempt.basis, CommitHash::new("basis-aaa"));
    // The timeline is append-only and reflects the true sequence.
    let timeline = store.timeline(att.attempt_id).unwrap();
    let kinds: Vec<&str> = timeline.iter().map(|t| t.kind.as_str()).collect();
    assert_eq!(
        kinds,
        vec!["admitted", "ratified", "reserved", "dispatching"]
    );
}

/// V6: the store validates the transition it is asked to persist. The blind
/// review reached `Committed` with no ratification, reservation, or dispatch
/// row, then regressed to `Prepared` — through the port, bypassing the
/// lifecycle entirely.
#[test]
fn the_store_refuses_illegal_transitions() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let att = attempt(9);
    store.admit_attempt(&att).unwrap();

    // Prepared -> Committed, skipping everything.
    let forged_committed = AttemptState::Committed {
        ratification: gwr_core::lifecycle::RatificationRef {
            ratification: RatificationId::from_bytes([1; 16]),
            prepared_attempt_digest: att.prepared_attempt_digest,
            standing_use: StandingUseId::from_bytes([2; 16]),
        },
        reservation: gwr_core::lifecycle::ReservationRef {
            reservation: ReservationId::from_bytes([3; 16]),
            reservation_use: ReservationUseId::from_bytes([4; 16]),
        },
        dispatch: gwr_core::lifecycle::DispatchRef {
            dispatch: DispatchId::from_bytes([5; 16]),
        },
    };
    let commitment = Commitment {
        attempt: att.attempt_id,
        dispatch: DispatchId::from_bytes([5; 16]),
        target_ref: att.effect.target_ref.clone(),
        previous_value: att.basis.clone(),
        result_commit: CommitHash::new("deadbeef"),
        journal_digest: Sha256Digest::of_bytes(b"forged"),
        committed_at: ClockReading(10),
    };
    let err = store
        .record_commitment(0, &commitment, &forged_committed)
        .unwrap_err();
    assert_eq!(
        err,
        StoreError::IllegalTransition {
            from: "prepared".into(),
            to: "committed".into()
        }
    );
    // Nothing moved, and no commitment was written.
    let projected = store.get_attempt(att.attempt_id).unwrap();
    assert_eq!(projected.state, AttemptState::Prepared);
    assert_eq!(projected.version, 0);
    assert_eq!(
        store.get_commitment(att.attempt_id).unwrap_err(),
        StoreError::NotFound
    );

    // And a legal forward step still works, so the gate is a successor check
    // rather than a blanket refusal.
    let grant = grant_for(&att, 3);
    store.create_standing_grant(&grant).unwrap();
    let rat = rat_bridge::cross(rat_bridge::Input {
        version: 1,
        grant: &grant,
        actor: ActorId::from_bytes([4; 16]),
        attempt: &att,
        ratified_digest: att.prepared_attempt_digest,
        ratified_basis: att.basis.clone(),
        now: ClockReading(10),
        new_ratification: RatificationId::from_bytes([5; 16]),
        new_use: StandingUseId::from_bytes([6; 16]),
    })
    .unwrap();
    let ratified = AttemptState::Prepared
        .ratify(rat.ratification_ref.clone())
        .unwrap();
    let standing_use = StandingUse {
        id: StandingUseId::from_bytes([6; 16]),
        grant: grant.id(),
        used_at: ClockReading(10),
    };
    store
        .record_ratification(0, &rat.receipt, &ratified, &grant, &standing_use)
        .unwrap();

    // Ratified -> Prepared: a regression, refused.
    let err = store
        .record_reserved(1, att.attempt_id, &AttemptState::Prepared, ClockReading(11))
        .unwrap_err();
    assert_eq!(
        err,
        StoreError::IllegalTransition {
            from: "ratified".into(),
            to: "prepared".into()
        }
    );
    let timeline = store.timeline(att.attempt_id).unwrap();
    let kinds: Vec<&str> = timeline.iter().map(|t| t.kind.as_str()).collect();
    assert_eq!(kinds, vec!["admitted", "ratified"]);
}
