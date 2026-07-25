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
use gwr_core::work_request::{ClockReading, CommitHash, WorkRequest};

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
    /// The caller asked to persist a state that is not a legal successor of the
    /// attempt's current state.
    IllegalTransition {
        from: String,
        to: String,
    },
    /// A persisted record failed to decode: a malformed column is a typed read
    /// error, never a panic and never a defaulted value.
    Corrupt(String),
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

/// What a reliance refusal was about: which observation, presented to which
/// consumer, for which claim. Persisted with the refusal so a stored refusal
/// can say what was refused for whom (finding N-5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelianceSubject {
    pub observation: ObservationId,
    pub consumer: String,
    pub claim: gwr_core::domain::evidence::Claim,
}

/// A persisted reliance refusal as read back from the ledger. Rows written
/// before the subject columns existed genuinely lack a subject; that absence is
/// exposed as absence, never defaulted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelianceRefusalRecord {
    pub attempt: AttemptId,
    pub refusal: RelianceRefusal,
    pub subject: Option<RelianceSubject>,
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
    /// The attempt a persisted dispatch identity belongs to, if any. The
    /// schema guarantees at most one (`dispatch.id` is the primary key and
    /// `dispatch.attempt` is unique), so this cannot be multiply bound.
    fn find_dispatch_attempt(&mut self, id: DispatchId) -> Result<Option<AttemptId>, StoreError>;
    /// The dispatch envelope persisted for an attempt, so a runtime that died
    /// mid-dispatch can present it to the broker again for inspection.
    fn get_dispatch_envelope(&mut self, id: AttemptId) -> Result<DispatchEnvelope, StoreError>;

    // Standing. `create_standing_grant` records a locally-authorized grant;
    // `create_upstream_standing_grant` records one justified by a verified
    // upstream issuance. The issuance is the *basis*: it never becomes the
    // grant, and one issuance can justify at most one grant.
    fn create_standing_grant(&mut self, grant: &StandingGrant) -> Result<(), StoreError>;
    fn record_authz_issuance(
        &mut self,
        issuance: &gwr_core::authorization::AcceptedIssuance,
    ) -> Result<(), StoreError>;
    fn get_authz_issuance(
        &mut self,
        issuance_id: &str,
    ) -> Result<Option<gwr_core::authorization::AcceptedIssuance>, StoreError>;
    /// The issuance recorded for an attempt, if any.
    fn find_attempt_issuance(
        &mut self,
        attempt: AttemptId,
    ) -> Result<Option<gwr_core::authorization::AcceptedIssuance>, StoreError>;
    fn create_upstream_standing_grant(
        &mut self,
        grant: &StandingGrant,
        issuance_id: &str,
    ) -> Result<(), StoreError>;
    /// The authorization source recorded for a grant. `None` means the grant
    /// predates source recording and reads as unrecorded — never as either
    /// source.
    fn get_grant_authorization(
        &mut self,
        grant: StandingGrantId,
    ) -> Result<Option<(gwr_core::authorization::AuthorizationSource, Option<String>)>, StoreError>;
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
    /// The indeterminate outcome recorded for an attempt, if any. Carries the
    /// broker journal digest established at the moment of indeterminacy.
    fn get_indeterminate(&mut self, attempt: AttemptId) -> Result<IndeterminateRecord, StoreError>;
    /// The attempt whose committed effect produced this result commit, if the
    /// runtime already recorded one. A commit already attributed to another
    /// attempt cannot settle this one.
    fn find_commitment_owner(
        &mut self,
        result_commit: &CommitHash,
    ) -> Result<Option<AttemptId>, StoreError>;
    fn record_reliance_admission(&mut self, adm: &ReviewQueueAdmission) -> Result<(), StoreError>;
    /// Record a reliance refusal with its subject where one exists. A refusal
    /// produced outside any observation context (e.g. a missing-bridge
    /// crossing) has no subject to record.
    fn record_reliance_refusal(
        &mut self,
        attempt: AttemptId,
        refusal: &RelianceRefusal,
        subject: Option<&RelianceSubject>,
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

    // Read paths over ledger records the runtime already owns. These exist so
    // the operator read surface can expose what was recorded; none of them
    // manufactures a fact or mutates anything.
    fn get_ratification(
        &mut self,
        attempt: AttemptId,
    ) -> Result<Option<RatificationReceipt>, StoreError>;
    fn get_standing_use(&mut self, id: StandingUseId) -> Result<Option<StandingUse>, StoreError>;
    fn get_dispatch_refusal(
        &mut self,
        attempt: AttemptId,
    ) -> Result<Option<DispatchRefusalRecord>, StoreError>;
    fn get_recovery_facts(&mut self, attempt: AttemptId) -> Result<Vec<RecoveryFact>, StoreError>;
    fn get_recovery_resolution(
        &mut self,
        attempt: AttemptId,
    ) -> Result<Option<RecoveryResolution>, StoreError>;
    fn get_reliance_admissions(
        &mut self,
        attempt: AttemptId,
    ) -> Result<Vec<ReviewQueueAdmission>, StoreError>;
    fn get_reliance_refusals(
        &mut self,
        attempt: AttemptId,
    ) -> Result<Vec<RelianceRefusalRecord>, StoreError>;
    fn get_reconciliation(
        &mut self,
        attempt: AttemptId,
    ) -> Result<Option<Reconciliation>, StoreError>;
}
