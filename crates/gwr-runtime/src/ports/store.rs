//! The store port: transactional current-state projections plus immutable typed
//! ledger records.
//!
//! Every consequential change atomically validates the current projection
//! version, inserts an immutable typed record, updates the projection, and
//! increments the version. Normal operation reads projections; nothing replays a
//! generic event stream. Historical records are never rewritten.

use gwr_core::domain::reservation::ReservationClaim;
use gwr_core::domain::standing::{StandingGrant, StandingUse};
use gwr_core::ids::*;
use gwr_core::lifecycle::AttemptState;
use gwr_core::observation_plan::ObservationRecord;
use gwr_core::outcome::{Commitment, DispatchRefusalRecord, IndeterminateRecord};
use gwr_core::preparation::{CandidateArtifact, PreparationEnd, PreparationRun};
use gwr_core::prepared_attempt::PreparedAttempt;
use gwr_core::receipt::{DispatchEnvelope, RatificationReceipt, ReviewQueueAdmission};
use gwr_core::reconciliation::{Reconciliation, ResidualObligation};
use gwr_core::recovery::{RecoveryFact, RecoveryResolution};
use gwr_core::refusal::RelianceRefusal;
use gwr_core::work_request::{ClockReading, WorkRequest};

#[derive(Debug, PartialEq, Eq)]
pub enum StoreError {
    /// Optimistic concurrency: the projection moved since it was read.
    StaleVersion {
        expected: u64,
        actual: u64,
    },
    NotFound,
    /// An immutable identity was presented with different content. Identical
    /// duplicate commands are idempotent; rebinding is refused.
    ImmutableRebind,
    /// A reservation for the same repository and target ref is active.
    ReservationConflict,
    /// A standing or reservation use was already consumed.
    AlreadyConsumed,
    Backend(String),
}

/// A projected attempt: current state plus its optimistic version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectedAttempt {
    pub attempt: PreparedAttempt,
    pub state: AttemptState,
    pub version: u64,
}

/// One row of an attempt's timeline projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineEntry {
    pub seq: u64,
    pub kind: String,
    pub at: ClockReading,
}

pub trait Store {
    // Work requests, preparation, candidates.
    fn create_work_request(&mut self, wr: &WorkRequest) -> Result<(), StoreError>;
    fn get_work_request(&mut self, id: WorkRequestId) -> Result<WorkRequest, StoreError>;
    fn create_preparation_run(&mut self, run: &PreparationRun) -> Result<(), StoreError>;
    fn get_preparation_run(&mut self, id: PreparationRunId) -> Result<PreparationRun, StoreError>;
    fn end_preparation_run(
        &mut self,
        id: PreparationRunId,
        end: PreparationEnd,
        at: ClockReading,
    ) -> Result<(), StoreError>;
    fn ingest_candidate(&mut self, artifact: &CandidateArtifact) -> Result<(), StoreError>;
    fn get_candidate(&mut self, id: CandidateArtifactId) -> Result<CandidateArtifact, StoreError>;

    // Attempts.
    fn admit_attempt(&mut self, attempt: &PreparedAttempt) -> Result<(), StoreError>;
    fn get_attempt(&mut self, id: AttemptId) -> Result<ProjectedAttempt, StoreError>;
    fn find_attempt_dispatch(&mut self, id: AttemptId) -> Result<Option<DispatchId>, StoreError>;

    // Standing.
    fn create_standing_grant(&mut self, grant: &StandingGrant) -> Result<(), StoreError>;
    fn get_standing_grant(&mut self, id: StandingGrantId) -> Result<StandingGrant, StoreError>;

    // Reservation. Creation checks exclusivity atomically.
    fn create_reservation(
        &mut self,
        claim: &ReservationClaim,
        now: ClockReading,
    ) -> Result<(), StoreError>;
    fn get_reservation(&mut self, id: ReservationId) -> Result<ReservationClaim, StoreError>;

    // Consequential transitions. Each is one atomic ledger-insert + projection
    // update, gated on the attempt projection version.
    fn record_ratification(
        &mut self,
        expected_version: u64,
        receipt: &RatificationReceipt,
        new_state: &AttemptState,
        consumed_grant: &StandingGrant,
        standing_use: &StandingUse,
    ) -> Result<(), StoreError>;
    /// Advance the projection to `Reserved` after the claim was created. The
    /// claim's one use is not spent here; dispatch spends it.
    fn record_reserved(
        &mut self,
        expected_version: u64,
        attempt: AttemptId,
        new_state: &AttemptState,
        at: ClockReading,
    ) -> Result<(), StoreError>;
    fn record_dispatch(
        &mut self,
        expected_version: u64,
        envelope: &DispatchEnvelope,
        new_state: &AttemptState,
        consumed_claim: &ReservationClaim,
    ) -> Result<(), StoreError>;
    fn record_commitment(
        &mut self,
        expected_version: u64,
        commitment: &Commitment,
        new_state: &AttemptState,
    ) -> Result<(), StoreError>;
    fn record_dispatch_refusal(
        &mut self,
        expected_version: u64,
        refusal: &DispatchRefusalRecord,
        new_state: &AttemptState,
    ) -> Result<(), StoreError>;
    fn record_indeterminate(
        &mut self,
        expected_version: u64,
        record: &IndeterminateRecord,
        new_state: &AttemptState,
    ) -> Result<(), StoreError>;
    fn record_recovery_resolution(
        &mut self,
        expected_version: u64,
        resolution: &RecoveryResolution,
        new_state: &AttemptState,
        consumed_grant: &StandingGrant,
        standing_use: &StandingUse,
    ) -> Result<(), StoreError>;

    // Associated records (no attempt-state change).
    fn record_recovery_fact(&mut self, fact: &RecoveryFact) -> Result<(), StoreError>;
    fn get_recovery_fact(&mut self, id: RecoveryFactId) -> Result<RecoveryFact, StoreError>;
    fn record_observation(&mut self, obs: &ObservationRecord) -> Result<(), StoreError>;
    fn get_observations(
        &mut self,
        attempt: AttemptId,
    ) -> Result<Vec<ObservationRecord>, StoreError>;
    fn get_commitment(&mut self, attempt: AttemptId) -> Result<Commitment, StoreError>;
    fn record_reliance_admission(&mut self, adm: &ReviewQueueAdmission) -> Result<(), StoreError>;
    fn record_reliance_refusal(
        &mut self,
        attempt: AttemptId,
        refusal: &RelianceRefusal,
        at: ClockReading,
    ) -> Result<(), StoreError>;
    fn create_residual_obligation(&mut self, ob: &ResidualObligation) -> Result<(), StoreError>;
    fn get_residual_obligations(
        &mut self,
        attempt: AttemptId,
    ) -> Result<Vec<ResidualObligation>, StoreError>;
    fn record_reconciliation(&mut self, rec: &Reconciliation) -> Result<(), StoreError>;

    // Projections for the operator.
    fn timeline(&mut self, attempt: AttemptId) -> Result<Vec<TimelineEntry>, StoreError>;
    fn list_attempts(&mut self) -> Result<Vec<AttemptId>, StoreError>;
}
