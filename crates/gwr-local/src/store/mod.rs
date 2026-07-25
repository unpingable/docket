//! SQLite implementation of the store port: transactional current-state
//! projections plus immutable typed ledger records.

mod codec;

use codec::*;
use gwr_core::domain::reservation::{ClaimState, ReservationClaim};
use gwr_core::domain::standing::{GrantState, StandingGrant, StandingScope, StandingUse};
use gwr_core::ids::*;
use gwr_core::lifecycle::AttemptState;
use gwr_core::observation_plan::{ObservationPlan, ObservationRecord};
use gwr_core::outcome::{Commitment, DispatchRefusalRecord, IndeterminateRecord};
use gwr_core::preparation::{CandidateArtifact, PreparationEnd, PreparationRun, PreparationStatus};
use gwr_core::prepared_attempt::PreparedAttempt;
use gwr_core::receipt::{DispatchEnvelope, RatificationReceipt, ReviewQueueAdmission};
use gwr_core::reconciliation::{Reconciliation, ResidualObligation};
use gwr_core::recovery::{RecoveryFact, RecoveryResolution};
use gwr_core::refusal::RelianceRefusal;
use gwr_core::work_request::{ClockReading, WorkRequest};
use gwr_runtime::ports::store::{ProjectedAttempt, Store, StoreError, TimelineEntry};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use std::path::Path;

const MIGRATION: &str = include_str!("../../migrations/0001_init.sql");

pub struct SqliteStore {
    conn: Connection,
}

fn backend(e: rusqlite::Error) -> StoreError {
    StoreError::Backend(e.to_string())
}

impl SqliteStore {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let conn = Connection::open(path).map_err(backend)?;
        conn.pragma_update(None, "journal_mode", "WAL").ok();
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(backend)?;
        conn.execute_batch(MIGRATION).map_err(backend)?;
        Ok(Self { conn })
    }

    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory().map_err(backend)?;
        conn.execute_batch(MIGRATION).map_err(backend)?;
        Ok(Self { conn })
    }

    fn tx(&mut self) -> Result<Transaction<'_>, StoreError> {
        self.conn.transaction().map_err(backend)
    }

    /// Insert a commitment row directly. Test support only: it exists so a
    /// suite can stage another attempt's committed effect without driving that
    /// attempt's whole lifecycle. It writes no projection.
    pub fn record_commitment_for_test(
        &mut self,
        c: &gwr_core::outcome::Commitment,
    ) -> Result<(), StoreError> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO commitment
                 (attempt, dispatch, target_ref, previous_value, result_commit, journal_digest, at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![
                    id16(c.attempt.as_bytes()),
                    id16(c.dispatch.as_bytes()),
                    c.target_ref.as_str(),
                    c.previous_value.as_str(),
                    c.result_commit.as_str(),
                    c.journal_digest.to_hex(),
                    c.committed_at.0 as i64
                ],
            )
            .map_err(backend)?;
        Ok(())
    }

    /// Column names across every table, for boundary tests.
    pub fn all_column_names(&mut self) -> Result<Vec<String>, StoreError> {
        let mut names = Vec::new();
        let tables: Vec<String> = self
            .conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table'")
            .map_err(backend)?
            .query_map([], |r| r.get(0))
            .map_err(backend)?
            .collect::<Result<_, _>>()
            .map_err(backend)?;
        for t in tables {
            let mut stmt = self
                .conn
                .prepare(&format!("PRAGMA table_info({t})"))
                .map_err(backend)?;
            let cols: Vec<String> = stmt
                .query_map([], |r| r.get::<_, String>(1))
                .map_err(backend)?
                .collect::<Result<_, _>>()
                .map_err(backend)?;
            for c in cols {
                names.push(format!("{t}.{c}"));
            }
        }
        Ok(names)
    }
}

/// Serialize the projection columns for an attempt state.
#[allow(clippy::type_complexity)]
fn projection_columns(
    state: &AttemptState,
) -> (
    &'static str,
    Option<String>, // rat_id
    Option<String>, // rat_standing_use
    Option<String>, // rsv_id
    Option<String>, // rsv_use
    Option<String>, // dispatch_id
    Option<String>, // refusal_ground
    Option<String>, // resolution_id
) {
    use AttemptState as S;
    let rat = |r: &gwr_core::lifecycle::RatificationRef| {
        (
            Some(id16(r.ratification.as_bytes())),
            Some(id16(r.standing_use.as_bytes())),
        )
    };
    let rsv = |r: &gwr_core::lifecycle::ReservationRef| {
        (
            Some(id16(r.reservation.as_bytes())),
            Some(id16(r.reservation_use.as_bytes())),
        )
    };
    match state {
        S::Prepared => ("prepared", None, None, None, None, None, None, None),
        S::Ratified { ratification } => {
            let (a, b) = rat(ratification);
            ("ratified", a, b, None, None, None, None, None)
        }
        S::Reserved {
            ratification,
            reservation,
        } => {
            let (a, b) = rat(ratification);
            (
                "reserved",
                a,
                b,
                Some(id16(reservation.as_bytes())),
                None,
                None,
                None,
                None,
            )
        }
        S::Dispatching {
            ratification,
            reservation,
            dispatch,
        } => {
            let (a, b) = rat(ratification);
            let (c, d) = rsv(reservation);
            (
                "dispatching",
                a,
                b,
                c,
                d,
                Some(id16(dispatch.dispatch.as_bytes())),
                None,
                None,
            )
        }
        S::Committed {
            ratification,
            reservation,
            dispatch,
        } => {
            let (a, b) = rat(ratification);
            let (c, d) = rsv(reservation);
            (
                "committed",
                a,
                b,
                c,
                d,
                Some(id16(dispatch.dispatch.as_bytes())),
                None,
                None,
            )
        }
        S::DispatchRefused {
            ratification,
            reservation,
            dispatch,
            ground,
        } => {
            let (a, b) = rat(ratification);
            let (c, d) = rsv(reservation);
            (
                "dispatch_refused",
                a,
                b,
                c,
                d,
                Some(id16(dispatch.dispatch.as_bytes())),
                Some(ground_tag(*ground).to_string()),
                None,
            )
        }
        S::Indeterminate {
            ratification,
            reservation,
            dispatch,
        } => {
            let (a, b) = rat(ratification);
            let (c, d) = rsv(reservation);
            (
                "indeterminate",
                a,
                b,
                c,
                d,
                Some(id16(dispatch.dispatch.as_bytes())),
                None,
                None,
            )
        }
        S::CommittedViaRecovery {
            ratification,
            reservation,
            dispatch,
            resolution,
        } => {
            let (a, b) = rat(ratification);
            let (c, d) = rsv(reservation);
            (
                "committed_via_recovery",
                a,
                b,
                c,
                d,
                Some(id16(dispatch.dispatch.as_bytes())),
                None,
                Some(id16(resolution.resolution.as_bytes())),
            )
        }
        S::ProvenNotCommitted {
            ratification,
            reservation,
            dispatch,
            resolution,
        } => {
            let (a, b) = rat(ratification);
            let (c, d) = rsv(reservation);
            (
                "proven_not_committed",
                a,
                b,
                c,
                d,
                Some(id16(dispatch.dispatch.as_bytes())),
                None,
                Some(id16(resolution.resolution.as_bytes())),
            )
        }
    }
}

/// Atomically advance the attempt projection from `expected_version` and append
/// the timeline row. The single writer for the projection.
fn advance_projection(
    tx: &Transaction<'_>,
    attempt: AttemptId,
    expected_version: u64,
    state: &AttemptState,
    at: ClockReading,
) -> Result<(), StoreError> {
    let (tag, rat_id, rat_use, rsv_id, rsv_use, dsp, ground, res) = projection_columns(state);
    let changed = tx
        .execute(
            "UPDATE attempt_projection SET state=?1, version=?2, rat_id=?3, rat_standing_use=?4,
             rsv_id=?5, rsv_use=?6, dispatch_id=?7, refusal_ground=?8, resolution_id=?9
             WHERE attempt=?10 AND version=?11",
            params![
                tag,
                (expected_version + 1) as i64,
                rat_id,
                rat_use,
                rsv_id,
                rsv_use,
                dsp,
                ground,
                res,
                id16(attempt.as_bytes()),
                expected_version as i64,
            ],
        )
        .map_err(backend)?;
    if changed == 0 {
        let actual: Option<i64> = tx
            .query_row(
                "SELECT version FROM attempt_projection WHERE attempt=?1",
                params![id16(attempt.as_bytes())],
                |r| r.get(0),
            )
            .optional()
            .map_err(backend)?;
        return match actual {
            Some(v) => Err(StoreError::StaleVersion {
                expected: expected_version,
                actual: v as u64,
            }),
            None => Err(StoreError::NotFound),
        };
    }
    tx.execute(
        "INSERT INTO timeline (attempt, seq, kind, at) VALUES (?1, ?2, ?3, ?4)",
        params![
            id16(attempt.as_bytes()),
            (expected_version + 1) as i64,
            tag,
            at.0 as i64
        ],
    )
    .map_err(backend)?;
    Ok(())
}

/// Consume a standing grant inside a transaction, inserting the use record.
fn consume_standing(
    tx: &Transaction<'_>,
    grant: &StandingGrant,
    use_record: &StandingUse,
) -> Result<(), StoreError> {
    let changed = tx
        .execute(
            "UPDATE standing_projection SET consumed_by=?1, version=version+1
             WHERE grant_id=?2 AND consumed_by IS NULL",
            params![id16(use_record.id.as_bytes()), id16(grant.id.as_bytes())],
        )
        .map_err(backend)?;
    if changed == 0 {
        return Err(StoreError::AlreadyConsumed);
    }
    tx.execute(
        "INSERT INTO standing_use (id, grant_id, used_at) VALUES (?1, ?2, ?3)",
        params![
            id16(use_record.id.as_bytes()),
            id16(grant.id.as_bytes()),
            use_record.used_at.0 as i64
        ],
    )
    .map_err(backend)?;
    Ok(())
}

impl Store for SqliteStore {
    fn create_work_request(&mut self, wr: &WorkRequest) -> Result<(), StoreError> {
        let changed = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO work_request (id, repository, target_ref, goal, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    id16(wr.id.as_bytes()),
                    wr.repository.as_str(),
                    wr.target_ref.as_str(),
                    wr.goal,
                    wr.created_at.0 as i64
                ],
            )
            .map_err(backend)?;
        if changed == 0 {
            let existing = self.get_work_request(wr.id)?;
            if &existing != wr {
                return Err(StoreError::ImmutableRebind);
            }
        }
        Ok(())
    }

    fn get_work_request(&mut self, id: WorkRequestId) -> Result<WorkRequest, StoreError> {
        self.conn
            .query_row(
                "SELECT id, repository, target_ref, goal, created_at FROM work_request WHERE id=?1",
                params![id16(id.as_bytes())],
                |r| {
                    Ok(WorkRequest {
                        id: parse_id16(&r.get::<_, String>(0)?),
                        repository: repo(&r.get::<_, String>(1)?),
                        target_ref: refname(&r.get::<_, String>(2)?),
                        goal: r.get(3)?,
                        created_at: ClockReading(r.get::<_, i64>(4)? as u64),
                    })
                },
            )
            .optional()
            .map_err(backend)?
            .ok_or(StoreError::NotFound)
    }

    fn create_preparation_run(&mut self, run: &PreparationRun) -> Result<(), StoreError> {
        let changed = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO preparation_run (id, work_request, started_at, deadline)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    id16(run.id.as_bytes()),
                    id16(run.work_request.as_bytes()),
                    run.started_at.0 as i64,
                    run.deadline.0 as i64
                ],
            )
            .map_err(backend)?;
        if changed == 0 {
            let existing = self.get_preparation_run(run.id)?;
            let same = existing.id == run.id
                && existing.work_request == run.work_request
                && existing.started_at == run.started_at
                && existing.deadline == run.deadline;
            if !same {
                return Err(StoreError::ImmutableRebind);
            }
        }
        Ok(())
    }

    fn get_preparation_run(&mut self, id: PreparationRunId) -> Result<PreparationRun, StoreError> {
        let base = self
            .conn
            .query_row(
                "SELECT id, work_request, started_at, deadline FROM preparation_run WHERE id=?1",
                params![id16(id.as_bytes())],
                |r| {
                    Ok((
                        parse_id16::<PreparationRunId>(&r.get::<_, String>(0)?),
                        parse_id16::<WorkRequestId>(&r.get::<_, String>(1)?),
                        r.get::<_, i64>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(backend)?
            .ok_or(StoreError::NotFound)?;
        let end: Option<String> = self
            .conn
            .query_row(
                "SELECT end_kind FROM preparation_run_end WHERE run_id=?1",
                params![id16(id.as_bytes())],
                |r| r.get(0),
            )
            .optional()
            .map_err(backend)?;
        Ok(PreparationRun {
            id: base.0,
            work_request: base.1,
            started_at: ClockReading(base.2 as u64),
            deadline: ClockReading(base.3 as u64),
            status: match end {
                None => PreparationStatus::Running,
                Some(tag) => PreparationStatus::Ended(parse_end_tag(&tag)?),
            },
        })
    }

    fn end_preparation_run(
        &mut self,
        id: PreparationRunId,
        end: PreparationEnd,
        at: ClockReading,
    ) -> Result<(), StoreError> {
        let changed = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO preparation_run_end (run_id, end_kind, at) VALUES (?1, ?2, ?3)",
                params![id16(id.as_bytes()), end_tag(end), at.0 as i64],
            )
            .map_err(backend)?;
        if changed == 0 {
            let existing: String = self
                .conn
                .query_row(
                    "SELECT end_kind FROM preparation_run_end WHERE run_id=?1",
                    params![id16(id.as_bytes())],
                    |r| r.get(0),
                )
                .map_err(backend)?;
            if existing != end_tag(end) {
                return Err(StoreError::ImmutableRebind);
            }
        }
        Ok(())
    }

    fn ingest_candidate(&mut self, artifact: &CandidateArtifact) -> Result<(), StoreError> {
        let changed = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO candidate_artifact
                 (id, preparation_run, content_digest, content_len, ingested_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    id16(artifact.id.as_bytes()),
                    id16(artifact.preparation_run.as_bytes()),
                    artifact.content_digest.to_hex(),
                    artifact.content_len as i64,
                    artifact.ingested_at.0 as i64
                ],
            )
            .map_err(backend)?;
        if changed == 0 {
            let existing = self.get_candidate(artifact.id)?;
            if &existing != artifact {
                return Err(StoreError::ImmutableRebind);
            }
        }
        Ok(())
    }

    fn get_candidate(&mut self, id: CandidateArtifactId) -> Result<CandidateArtifact, StoreError> {
        self.conn
            .query_row(
                "SELECT id, preparation_run, content_digest, content_len, ingested_at
                 FROM candidate_artifact WHERE id=?1",
                params![id16(id.as_bytes())],
                |r| {
                    Ok(CandidateArtifact {
                        id: parse_id16(&r.get::<_, String>(0)?),
                        preparation_run: parse_id16(&r.get::<_, String>(1)?),
                        content_digest: parse_digest(&r.get::<_, String>(2)?),
                        content_len: r.get::<_, i64>(3)? as u64,
                        ingested_at: ClockReading(r.get::<_, i64>(4)? as u64),
                    })
                },
            )
            .optional()
            .map_err(backend)?
            .ok_or(StoreError::NotFound)
    }

    fn admit_attempt(&mut self, attempt: &PreparedAttempt) -> Result<(), StoreError> {
        let tx = self.tx()?;
        let changed = tx
            .execute(
                "INSERT OR IGNORE INTO attempt
                 (id, work_request, candidate, repository, basis, artifact_digest, target_ref,
                  expected_basis, patch_digest, allowed_paths, argv, environment, admitted_at,
                  prepared_digest)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
                params![
                    id16(attempt.attempt_id.as_bytes()),
                    id16(attempt.work_request.as_bytes()),
                    id16(attempt.candidate.as_bytes()),
                    attempt.repository.as_str(),
                    attempt.basis.as_str(),
                    attempt.artifact_digest.to_hex(),
                    attempt.effect.target_ref.as_str(),
                    attempt.effect.expected_basis.as_str(),
                    attempt.effect.patch_digest.to_hex(),
                    join_list(&attempt.effect.allowed_paths),
                    join_list(&attempt.observation_plan.argv),
                    attempt.observation_plan.environment_description,
                    attempt.admitted_at.0 as i64,
                    attempt.prepared_attempt_digest.to_hex()
                ],
            )
            .map_err(backend)?;
        if changed == 0 {
            drop(tx);
            let existing = self.get_attempt(attempt.attempt_id)?;
            if &existing.attempt != attempt {
                return Err(StoreError::ImmutableRebind);
            }
            return Ok(()); // idempotent duplicate
        }
        tx.execute(
            "INSERT INTO attempt_projection (attempt, state, version) VALUES (?1, 'prepared', 0)",
            params![id16(attempt.attempt_id.as_bytes())],
        )
        .map_err(backend)?;
        tx.execute(
            "INSERT INTO timeline (attempt, seq, kind, at) VALUES (?1, 0, 'admitted', ?2)",
            params![
                id16(attempt.attempt_id.as_bytes()),
                attempt.admitted_at.0 as i64
            ],
        )
        .map_err(backend)?;
        tx.commit().map_err(backend)
    }

    fn get_attempt(&mut self, id: AttemptId) -> Result<ProjectedAttempt, StoreError> {
        let attempt = self
            .conn
            .query_row(
                "SELECT work_request, candidate, repository, basis, artifact_digest, target_ref,
                        expected_basis, patch_digest, allowed_paths, argv, environment,
                        admitted_at
                 FROM attempt WHERE id=?1",
                params![id16(id.as_bytes())],
                |r| {
                    Ok(PreparedAttempt::admit(
                        id,
                        parse_id16(&r.get::<_, String>(0)?),
                        parse_id16(&r.get::<_, String>(1)?),
                        repo(&r.get::<_, String>(2)?),
                        commit(&r.get::<_, String>(3)?),
                        parse_digest(&r.get::<_, String>(4)?),
                        gwr_core::effect_spec::GitRefEffect {
                            target_ref: refname(&r.get::<_, String>(5)?),
                            expected_basis: commit(&r.get::<_, String>(6)?),
                            patch_digest: parse_digest(&r.get::<_, String>(7)?),
                            allowed_paths: split_list(&r.get::<_, String>(8)?),
                        },
                        ObservationPlan {
                            argv: split_list(&r.get::<_, String>(9)?),
                            environment_description: r.get(10)?,
                        },
                        ClockReading(r.get::<_, i64>(11)? as u64),
                    ))
                },
            )
            .optional()
            .map_err(backend)?
            .ok_or(StoreError::NotFound)?;
        let (state, version) = self
            .conn
            .query_row(
                "SELECT state, version, rat_id, rat_standing_use, rsv_id, rsv_use, dispatch_id,
                        refusal_ground, resolution_id
                 FROM attempt_projection WHERE attempt=?1",
                params![id16(id.as_bytes())],
                |r| {
                    let tag: String = r.get(0)?;
                    let version = r.get::<_, i64>(1)? as u64;
                    let cols = ProjCols {
                        rat_id: r.get(2)?,
                        rat_use: r.get(3)?,
                        rsv_id: r.get(4)?,
                        rsv_use: r.get(5)?,
                        dispatch: r.get(6)?,
                        ground: r.get(7)?,
                        resolution: r.get(8)?,
                    };
                    Ok((tag, version, cols))
                },
            )
            .optional()
            .map_err(backend)?
            .map(|(tag, version, cols)| {
                reconstruct_state(&tag, &cols, &attempt.prepared_attempt_digest)
                    .map(|s| (s, version))
            })
            .ok_or(StoreError::NotFound)??;
        Ok(ProjectedAttempt {
            attempt,
            state,
            version,
        })
    }

    fn find_attempt_dispatch(&mut self, id: AttemptId) -> Result<Option<DispatchId>, StoreError> {
        self.conn
            .query_row(
                "SELECT id FROM dispatch WHERE attempt=?1",
                params![id16(id.as_bytes())],
                |r| Ok(parse_id16::<DispatchId>(&r.get::<_, String>(0)?)),
            )
            .optional()
            .map_err(backend)
    }

    fn create_standing_grant(&mut self, grant: &StandingGrant) -> Result<(), StoreError> {
        let tx = self.tx()?;
        let changed = tx
            .execute(
                "INSERT OR IGNORE INTO standing_grant
                 (id, actor, act, repository, attempt_digest, expires_at)
                 VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    id16(grant.id.as_bytes()),
                    id16(grant.scope.actor.as_bytes()),
                    act_tag(grant.scope.act),
                    grant.scope.repository.as_str(),
                    grant.scope.attempt_digest.to_hex(),
                    grant.expires_at.0 as i64
                ],
            )
            .map_err(backend)?;
        if changed == 0 {
            drop(tx);
            let existing = self.get_standing_grant(grant.id)?;
            let mut fresh = existing.clone();
            fresh.state = GrantState::Available;
            let mut given = grant.clone();
            given.state = GrantState::Available;
            if fresh != given {
                return Err(StoreError::ImmutableRebind);
            }
            return Ok(());
        }
        tx.execute(
            "INSERT INTO standing_projection (grant_id, consumed_by, version) VALUES (?1, NULL, 0)",
            params![id16(grant.id.as_bytes())],
        )
        .map_err(backend)?;
        tx.commit().map_err(backend)
    }

    fn get_standing_grant(&mut self, id: StandingGrantId) -> Result<StandingGrant, StoreError> {
        self.conn
            .query_row(
                "SELECT g.actor, g.act, g.repository, g.attempt_digest, g.expires_at,
                        p.consumed_by
                 FROM standing_grant g JOIN standing_projection p ON p.grant_id = g.id
                 WHERE g.id=?1",
                params![id16(id.as_bytes())],
                |r| {
                    let consumed: Option<String> = r.get(5)?;
                    Ok(StandingGrant {
                        id,
                        scope: StandingScope {
                            actor: parse_id16(&r.get::<_, String>(0)?),
                            act: parse_act_tag(&r.get::<_, String>(1)?),
                            repository: repo(&r.get::<_, String>(2)?),
                            attempt_digest: parse_digest(&r.get::<_, String>(3)?),
                        },
                        expires_at: ClockReading(r.get::<_, i64>(4)? as u64),
                        state: match consumed {
                            None => GrantState::Available,
                            Some(u) => GrantState::Consumed {
                                used_as: parse_id16(&u),
                            },
                        },
                    })
                },
            )
            .optional()
            .map_err(backend)?
            .ok_or(StoreError::NotFound)
    }

    fn create_reservation(
        &mut self,
        claim: &ReservationClaim,
        now: ClockReading,
    ) -> Result<(), StoreError> {
        let tx = self.tx()?;
        // Exclusivity: any active, unexpired reservation on the same repository
        // and target ref conflicts. Conflict produces refusal, not waiting.
        let conflicts: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM reservation r
                 JOIN reservation_projection p ON p.reservation_id = r.id
                 WHERE r.repository=?1 AND r.target_ref=?2 AND p.consumed_by IS NULL
                   AND r.expires_at > ?3 AND r.id <> ?4",
                params![
                    claim.repository.as_str(),
                    claim.target_ref.as_str(),
                    now.0 as i64,
                    id16(claim.id.as_bytes())
                ],
                |r| r.get(0),
            )
            .map_err(backend)?;
        if conflicts > 0 {
            return Err(StoreError::ReservationConflict);
        }
        let changed = tx
            .execute(
                "INSERT OR IGNORE INTO reservation
                 (id, repository, target_ref, basis, attempt, expires_at)
                 VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    id16(claim.id.as_bytes()),
                    claim.repository.as_str(),
                    claim.target_ref.as_str(),
                    claim.basis.as_str(),
                    id16(claim.attempt.as_bytes()),
                    claim.expires_at.0 as i64
                ],
            )
            .map_err(backend)?;
        if changed == 0 {
            drop(tx);
            let existing = self.get_reservation(claim.id)?;
            let mut fresh = existing.clone();
            fresh.state = ClaimState::Active;
            let mut given = claim.clone();
            given.state = ClaimState::Active;
            if fresh != given {
                return Err(StoreError::ImmutableRebind);
            }
            return Ok(());
        }
        tx.execute(
            "INSERT INTO reservation_projection (reservation_id, consumed_by, version)
             VALUES (?1, NULL, 0)",
            params![id16(claim.id.as_bytes())],
        )
        .map_err(backend)?;
        tx.commit().map_err(backend)
    }

    fn get_reservation(&mut self, id: ReservationId) -> Result<ReservationClaim, StoreError> {
        self.conn
            .query_row(
                "SELECT r.repository, r.target_ref, r.basis, r.attempt, r.expires_at,
                        p.consumed_by
                 FROM reservation r JOIN reservation_projection p ON p.reservation_id = r.id
                 WHERE r.id=?1",
                params![id16(id.as_bytes())],
                |r| {
                    let consumed: Option<String> = r.get(5)?;
                    Ok(ReservationClaim {
                        id,
                        repository: repo(&r.get::<_, String>(0)?),
                        target_ref: refname(&r.get::<_, String>(1)?),
                        basis: commit(&r.get::<_, String>(2)?),
                        attempt: parse_id16(&r.get::<_, String>(3)?),
                        expires_at: ClockReading(r.get::<_, i64>(4)? as u64),
                        state: match consumed {
                            None => ClaimState::Active,
                            Some(u) => ClaimState::Consumed {
                                used_as: parse_id16(&u),
                            },
                        },
                    })
                },
            )
            .optional()
            .map_err(backend)?
            .ok_or(StoreError::NotFound)
    }

    fn record_ratification(
        &mut self,
        expected_version: u64,
        receipt: &RatificationReceipt,
        new_state: &AttemptState,
        consumed_grant: &StandingGrant,
        standing_use: &StandingUse,
    ) -> Result<(), StoreError> {
        let tx = self.tx()?;
        consume_standing(&tx, consumed_grant, standing_use)?;
        tx.execute(
            "INSERT INTO ratification (id, attempt, prepared_digest, actor, standing_use, at)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                id16(receipt.ratification.as_bytes()),
                id16(receipt.attempt.as_bytes()),
                receipt.prepared_attempt_digest.to_hex(),
                id16(receipt.actor.as_bytes()),
                id16(receipt.standing_use.as_bytes()),
                receipt.clock_reading.0 as i64
            ],
        )
        .map_err(backend)?;
        advance_projection(
            &tx,
            receipt.attempt,
            expected_version,
            new_state,
            receipt.clock_reading,
        )?;
        tx.commit().map_err(backend)
    }

    fn record_reserved(
        &mut self,
        expected_version: u64,
        attempt: AttemptId,
        new_state: &AttemptState,
        at: ClockReading,
    ) -> Result<(), StoreError> {
        let tx = self.tx()?;
        advance_projection(&tx, attempt, expected_version, new_state, at)?;
        tx.commit().map_err(backend)
    }

    fn record_dispatch(
        &mut self,
        expected_version: u64,
        envelope: &DispatchEnvelope,
        new_state: &AttemptState,
        consumed_claim: &ReservationClaim,
    ) -> Result<(), StoreError> {
        let ClaimState::Consumed { used_as } = &consumed_claim.state else {
            return Err(StoreError::Backend(
                "record_dispatch requires a consumed claim".into(),
            ));
        };
        let tx = self.tx()?;
        let changed = tx
            .execute(
                "UPDATE reservation_projection SET consumed_by=?1, version=version+1
                 WHERE reservation_id=?2 AND consumed_by IS NULL",
                params![id16(used_as.as_bytes()), id16(consumed_claim.id.as_bytes())],
            )
            .map_err(backend)?;
        if changed == 0 {
            return Err(StoreError::AlreadyConsumed);
        }
        tx.execute(
            "INSERT INTO reservation_use (id, reservation_id, used_at) VALUES (?1, ?2, ?3)",
            params![
                id16(used_as.as_bytes()),
                id16(consumed_claim.id.as_bytes()),
                envelope.created_at.0 as i64
            ],
        )
        .map_err(backend)?;
        tx.execute(
            "INSERT INTO dispatch
             (id, attempt, prepared_digest, reservation_use, repository, target_ref,
              expected_basis, patch_digest, allowed_paths, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                id16(envelope.dispatch.as_bytes()),
                id16(envelope.attempt.as_bytes()),
                envelope.prepared_attempt_digest.to_hex(),
                id16(envelope.reservation_use.as_bytes()),
                envelope.repository.as_str(),
                envelope.target_ref.as_str(),
                envelope.expected_basis.as_str(),
                envelope.patch_digest.to_hex(),
                join_list(&envelope.allowed_paths),
                envelope.created_at.0 as i64
            ],
        )
        .map_err(backend)?;
        advance_projection(
            &tx,
            envelope.attempt,
            expected_version,
            new_state,
            envelope.created_at,
        )?;
        tx.commit().map_err(backend)
    }

    fn record_commitment(
        &mut self,
        expected_version: u64,
        commitment_record: &Commitment,
        new_state: &AttemptState,
    ) -> Result<(), StoreError> {
        let tx = self.tx()?;
        tx.execute(
            "INSERT INTO commitment
             (attempt, dispatch, target_ref, previous_value, result_commit, journal_digest, at)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                id16(commitment_record.attempt.as_bytes()),
                id16(commitment_record.dispatch.as_bytes()),
                commitment_record.target_ref.as_str(),
                commitment_record.previous_value.as_str(),
                commitment_record.result_commit.as_str(),
                commitment_record.journal_digest.to_hex(),
                commitment_record.committed_at.0 as i64
            ],
        )
        .map_err(backend)?;
        advance_projection(
            &tx,
            commitment_record.attempt,
            expected_version,
            new_state,
            commitment_record.committed_at,
        )?;
        tx.commit().map_err(backend)
    }

    fn record_dispatch_refusal(
        &mut self,
        expected_version: u64,
        refusal: &DispatchRefusalRecord,
        new_state: &AttemptState,
    ) -> Result<(), StoreError> {
        let tx = self.tx()?;
        tx.execute(
            "INSERT INTO dispatch_refusal (attempt, dispatch, ground, journal_digest, at)
             VALUES (?1,?2,?3,?4,?5)",
            params![
                id16(refusal.attempt.as_bytes()),
                id16(refusal.dispatch.as_bytes()),
                ground_tag(refusal.ground),
                refusal.journal_digest.to_hex(),
                refusal.refused_at.0 as i64
            ],
        )
        .map_err(backend)?;
        advance_projection(
            &tx,
            refusal.attempt,
            expected_version,
            new_state,
            refusal.refused_at,
        )?;
        tx.commit().map_err(backend)
    }

    fn record_indeterminate(
        &mut self,
        expected_version: u64,
        record: &IndeterminateRecord,
        new_state: &AttemptState,
    ) -> Result<(), StoreError> {
        let tx = self.tx()?;
        tx.execute(
            "INSERT INTO indeterminate_outcome (attempt, dispatch, last_journal_digest, at)
             VALUES (?1,?2,?3,?4)",
            params![
                id16(record.attempt.as_bytes()),
                id16(record.dispatch.as_bytes()),
                record.last_journal_digest.as_ref().map(|d| d.to_hex()),
                record.recorded_at.0 as i64
            ],
        )
        .map_err(backend)?;
        advance_projection(
            &tx,
            record.attempt,
            expected_version,
            new_state,
            record.recorded_at,
        )?;
        tx.commit().map_err(backend)
    }

    fn record_recovery_resolution(
        &mut self,
        expected_version: u64,
        resolution: &RecoveryResolution,
        new_state: &AttemptState,
        consumed_grant: &StandingGrant,
        standing_use: &StandingUse,
    ) -> Result<(), StoreError> {
        let tx = self.tx()?;
        consume_standing(&tx, consumed_grant, standing_use)?;
        tx.execute(
            "INSERT INTO recovery_resolution
             (id, attempt, dispatch, fact, verdict, standing_use, at)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                id16(resolution.id.as_bytes()),
                id16(resolution.attempt.as_bytes()),
                id16(resolution.dispatch.as_bytes()),
                id16(resolution.fact.as_bytes()),
                verdict_tag(resolution.verdict),
                id16(resolution.recovery_standing_use.as_bytes()),
                resolution.resolved_at.0 as i64
            ],
        )
        .map_err(backend)?;
        advance_projection(
            &tx,
            resolution.attempt,
            expected_version,
            new_state,
            resolution.resolved_at,
        )?;
        tx.commit().map_err(backend)
    }

    fn record_recovery_fact(&mut self, fact: &RecoveryFact) -> Result<(), StoreError> {
        let (source_kind, source_detail) = source_tags(&fact.source);
        let changed = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO recovery_fact
                 (id, attempt, dispatch, prepared_digest, repository, target_ref, basis,
                  observed_ref, expected_result, journal_digest, source_kind, source_detail,
                  recorded_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                params![
                    id16(fact.id.as_bytes()),
                    id16(fact.attempt.as_bytes()),
                    id16(fact.dispatch.as_bytes()),
                    fact.prepared_attempt_digest.to_hex(),
                    fact.repository.as_str(),
                    fact.target_ref.as_str(),
                    fact.basis.as_str(),
                    fact.observed_ref.as_str(),
                    fact.expected_result_commit
                        .as_ref()
                        .map(|c| c.as_str().to_string()),
                    fact.journal_digest.to_hex(),
                    source_kind,
                    source_detail,
                    fact.recorded_at.0 as i64
                ],
            )
            .map_err(backend)?;
        if changed == 0 {
            let existing = self.get_recovery_fact(fact.id)?;
            if &existing != fact {
                return Err(StoreError::ImmutableRebind);
            }
        }
        Ok(())
    }

    fn get_recovery_fact(&mut self, id: RecoveryFactId) -> Result<RecoveryFact, StoreError> {
        self.conn
            .query_row(
                "SELECT attempt, dispatch, prepared_digest, repository, target_ref, basis,
                        observed_ref, expected_result, journal_digest, source_kind,
                        source_detail, recorded_at
                 FROM recovery_fact WHERE id=?1",
                params![id16(id.as_bytes())],
                |r| {
                    Ok(RecoveryFact {
                        id,
                        attempt: parse_id16(&r.get::<_, String>(0)?),
                        dispatch: parse_id16(&r.get::<_, String>(1)?),
                        prepared_attempt_digest: parse_digest(&r.get::<_, String>(2)?),
                        repository: repo(&r.get::<_, String>(3)?),
                        target_ref: refname(&r.get::<_, String>(4)?),
                        basis: commit(&r.get::<_, String>(5)?),
                        observed_ref: commit(&r.get::<_, String>(6)?),
                        expected_result_commit: r.get::<_, Option<String>>(7)?.map(|s| commit(&s)),
                        journal_digest: parse_digest(&r.get::<_, String>(8)?),
                        source: parse_source(
                            &r.get::<_, String>(9)?,
                            r.get::<_, Option<String>>(10)?,
                        ),
                        recorded_at: ClockReading(r.get::<_, i64>(11)? as u64),
                    })
                },
            )
            .optional()
            .map_err(backend)?
            .ok_or(StoreError::NotFound)
    }

    fn record_observation(&mut self, obs: &ObservationRecord) -> Result<(), StoreError> {
        let changed = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO observation
                 (id, attempt, argv, workdir, result_commit, environment, exit_status,
                  stdout_digest, stderr_digest, at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![
                    id16(obs.id.as_bytes()),
                    id16(obs.attempt.as_bytes()),
                    join_list(&obs.argv),
                    obs.working_directory_identity,
                    obs.result_commit.as_str(),
                    obs.environment_description,
                    obs.exit_status,
                    obs.stdout_digest.to_hex(),
                    obs.stderr_digest.to_hex(),
                    obs.observed_at.0 as i64
                ],
            )
            .map_err(backend)?;
        if changed == 0 {
            let existing = self
                .get_observations(obs.attempt)?
                .into_iter()
                .find(|o| o.id == obs.id)
                .ok_or(StoreError::ImmutableRebind)?;
            if &existing != obs {
                return Err(StoreError::ImmutableRebind);
            }
        }
        Ok(())
    }

    fn get_observations(
        &mut self,
        attempt: AttemptId,
    ) -> Result<Vec<ObservationRecord>, StoreError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, argv, workdir, result_commit, environment, exit_status,
                        stdout_digest, stderr_digest, at
                 FROM observation WHERE attempt=?1 ORDER BY at",
            )
            .map_err(backend)?;
        let rows = stmt
            .query_map(params![id16(attempt.as_bytes())], |r| {
                Ok(ObservationRecord {
                    id: parse_id16(&r.get::<_, String>(0)?),
                    attempt,
                    argv: split_list(&r.get::<_, String>(1)?),
                    working_directory_identity: r.get(2)?,
                    result_commit: commit(&r.get::<_, String>(3)?),
                    environment_description: r.get(4)?,
                    exit_status: r.get(5)?,
                    stdout_digest: parse_digest(&r.get::<_, String>(6)?),
                    stderr_digest: parse_digest(&r.get::<_, String>(7)?),
                    observed_at: ClockReading(r.get::<_, i64>(8)? as u64),
                })
            })
            .map_err(backend)?;
        rows.collect::<Result<_, _>>().map_err(backend)
    }

    fn get_commitment(&mut self, attempt: AttemptId) -> Result<Commitment, StoreError> {
        self.conn
            .query_row(
                "SELECT dispatch, target_ref, previous_value, result_commit, journal_digest, at
                 FROM commitment WHERE attempt=?1",
                params![id16(attempt.as_bytes())],
                |r| {
                    Ok(Commitment {
                        attempt,
                        dispatch: parse_id16(&r.get::<_, String>(0)?),
                        target_ref: refname(&r.get::<_, String>(1)?),
                        previous_value: commit(&r.get::<_, String>(2)?),
                        result_commit: commit(&r.get::<_, String>(3)?),
                        journal_digest: parse_digest(&r.get::<_, String>(4)?),
                        committed_at: ClockReading(r.get::<_, i64>(5)? as u64),
                    })
                },
            )
            .optional()
            .map_err(backend)?
            .ok_or(StoreError::NotFound)
    }

    fn get_indeterminate(&mut self, attempt: AttemptId) -> Result<IndeterminateRecord, StoreError> {
        self.conn
            .query_row(
                "SELECT dispatch, last_journal_digest, at FROM indeterminate_outcome
                 WHERE attempt=?1",
                params![id16(attempt.as_bytes())],
                |r| {
                    Ok(IndeterminateRecord {
                        attempt,
                        dispatch: parse_id16(&r.get::<_, String>(0)?),
                        last_journal_digest: r
                            .get::<_, Option<String>>(1)?
                            .map(|d| parse_digest(&d)),
                        recorded_at: ClockReading(r.get::<_, i64>(2)? as u64),
                    })
                },
            )
            .optional()
            .map_err(backend)?
            .ok_or(StoreError::NotFound)
    }

    fn find_commitment_owner(
        &mut self,
        result_commit: &gwr_core::work_request::CommitHash,
    ) -> Result<Option<AttemptId>, StoreError> {
        self.conn
            .query_row(
                "SELECT attempt FROM commitment WHERE result_commit=?1",
                params![result_commit.as_str()],
                |r| Ok(parse_id16::<AttemptId>(&r.get::<_, String>(0)?)),
            )
            .optional()
            .map_err(backend)
    }

    fn record_reliance_admission(&mut self, adm: &ReviewQueueAdmission) -> Result<(), StoreError> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO reliance_admission (attempt, observation, result_commit, at)
                 VALUES (?1,?2,?3,?4)",
                params![
                    id16(adm.attempt.as_bytes()),
                    id16(adm.observation.as_bytes()),
                    adm.result_commit.as_str(),
                    adm.admitted_at.0 as i64
                ],
            )
            .map_err(backend)?;
        Ok(())
    }

    fn record_reliance_refusal(
        &mut self,
        attempt: AttemptId,
        refusal: &RelianceRefusal,
        at: ClockReading,
    ) -> Result<(), StoreError> {
        let (kind, detail) = reliance_refusal_tags(refusal);
        self.conn
            .execute(
                "INSERT INTO reliance_refusal (attempt, kind, detail, at) VALUES (?1,?2,?3,?4)",
                params![id16(attempt.as_bytes()), kind, detail, at.0 as i64],
            )
            .map_err(backend)?;
        Ok(())
    }

    fn create_residual_obligation(&mut self, ob: &ResidualObligation) -> Result<(), StoreError> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO residual_obligation (id, attempt, kind, at)
                 VALUES (?1,?2,?3,?4)",
                params![
                    id16(ob.id.as_bytes()),
                    id16(ob.attempt.as_bytes()),
                    obligation_tag(ob.kind),
                    ob.recorded_at.0 as i64
                ],
            )
            .map_err(backend)?;
        Ok(())
    }

    fn get_residual_obligations(
        &mut self,
        attempt: AttemptId,
    ) -> Result<Vec<ResidualObligation>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, kind, at FROM residual_obligation WHERE attempt=?1 ORDER BY at")
            .map_err(backend)?;
        let rows = stmt
            .query_map(params![id16(attempt.as_bytes())], |r| {
                Ok(ResidualObligation {
                    id: parse_id16(&r.get::<_, String>(0)?),
                    attempt,
                    kind: parse_obligation_tag(&r.get::<_, String>(1)?),
                    recorded_at: ClockReading(r.get::<_, i64>(2)? as u64),
                })
            })
            .map_err(backend)?;
        rows.collect::<Result<_, _>>().map_err(backend)
    }

    fn record_reconciliation(&mut self, rec: &Reconciliation) -> Result<(), StoreError> {
        let retained: Vec<String> = rec
            .retained_obligations
            .iter()
            .map(|o| id16(o.as_bytes()))
            .collect();
        self.conn
            .execute(
                "INSERT OR IGNORE INTO reconciliation (attempt, retained, at) VALUES (?1,?2,?3)",
                params![
                    id16(rec.attempt.as_bytes()),
                    join_list(&retained),
                    rec.reconciled_at.0 as i64
                ],
            )
            .map_err(backend)?;
        Ok(())
    }

    fn timeline(&mut self, attempt: AttemptId) -> Result<Vec<TimelineEntry>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT seq, kind, at FROM timeline WHERE attempt=?1 ORDER BY seq")
            .map_err(backend)?;
        let rows = stmt
            .query_map(params![id16(attempt.as_bytes())], |r| {
                Ok(TimelineEntry {
                    seq: r.get::<_, i64>(0)? as u64,
                    kind: r.get(1)?,
                    at: ClockReading(r.get::<_, i64>(2)? as u64),
                })
            })
            .map_err(backend)?;
        rows.collect::<Result<_, _>>().map_err(backend)
    }

    fn list_attempts(&mut self) -> Result<Vec<AttemptId>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM attempt ORDER BY admitted_at, id")
            .map_err(backend)?;
        let rows = stmt
            .query_map([], |r| Ok(parse_id16::<AttemptId>(&r.get::<_, String>(0)?)))
            .map_err(backend)?;
        rows.collect::<Result<_, _>>().map_err(backend)
    }
}
