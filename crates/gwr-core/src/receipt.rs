//! Receipts: exact records of what a trusted component established.
//!
//! A receipt never asserts more than was established, and carries no hazard
//! hints, confidence markers, severity fields, or consumer advice — the hazard
//! lives in the reliance relation, not in a producer-side noun. Producer records
//! stay lean; calibration lives in the consumer.

use crate::digest::Sha256Digest;
use crate::ids::{
    ActorId, AttemptId, DispatchId, ObservationId, RatificationId, ReservationUseId, StandingUseId,
};
use crate::work_request::{ClockReading, CommitHash, RefName, RepositoryIdentity};

/// This actor, holding this standing, ratified this exact prepared attempt.
/// Not approval, not correctness — a commitment to an exact digest.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RatificationReceipt {
    pub ratification: RatificationId,
    pub attempt: AttemptId,
    pub prepared_attempt_digest: Sha256Digest,
    pub actor: ActorId,
    pub standing_use: StandingUseId,
    pub clock_reading: ClockReading,
}

/// The persisted dispatch envelope: everything the broker is allowed to know,
/// persisted before the broker sees it. The one `DispatchId` for the attempt.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DispatchEnvelope {
    pub dispatch: DispatchId,
    pub attempt: AttemptId,
    pub prepared_attempt_digest: Sha256Digest,
    pub reservation_use: ReservationUseId,
    pub repository: RepositoryIdentity,
    pub target_ref: RefName,
    pub expected_basis: CommitHash,
    pub patch_digest: Sha256Digest,
    pub allowed_paths: Vec<String>,
    pub created_at: ClockReading,
}

/// The one claim `ObservationToReviewQueueV1` may admit: this exact result
/// commit was produced by the admitted effect, and the named command exited
/// successfully against it. Nothing more.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ReviewQueueAdmission {
    pub attempt: AttemptId,
    pub observation: ObservationId,
    pub result_commit: CommitHash,
    pub admitted_at: ClockReading,
}
