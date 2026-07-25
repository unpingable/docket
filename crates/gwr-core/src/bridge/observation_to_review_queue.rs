//! `ObservationToReviewQueueV1` — from "this exact command exited zero against
//! this exact result commit" to admission of exactly one claim into the
//! human-review queue:
//!
//! > This exact result commit was produced by the admitted effect, and the named
//! > command exited successfully against it.
//!
//! It refuses claims equivalent to: the patch is correct; the task is complete;
//! the result is safe to merge; the obligation is discharged; the work may be
//! closed. Precision lost: output reduced to digests and exit status,
//! environment reduced to its description; nothing about *why* the command
//! passed crosses. Nothing is consumed; neither admission nor refusal mutates
//! the observation.

use crate::domain::evidence::{observation_in_scope, Claim};
use crate::observation_plan::ObservationRecord;
use crate::outcome::Commitment;
use crate::receipt::ReviewQueueAdmission;
use crate::refusal::{ObservationRefusal, RelianceRefusal};
use crate::work_request::ClockReading;

pub const VERSION: u32 = 1;

#[derive(Clone, Debug)]
pub struct Input<'a> {
    pub version: u32,
    pub observation: &'a ObservationRecord,
    pub commitment: &'a Commitment,
    pub claim: Claim,
    pub now: ClockReading,
}

pub fn cross(input: Input<'_>) -> Result<ReviewQueueAdmission, RelianceRefusal> {
    if input.version != VERSION {
        return Err(RelianceRefusal::BridgeVersionUnsupported {
            presented: input.version,
        });
    }
    observation_in_scope(input.observation, input.commitment)
        .map_err(RelianceRefusal::Observation)?;
    if !input.observation.succeeded() {
        return Err(RelianceRefusal::Observation(
            ObservationRefusal::ObservationFailed,
        ));
    }
    match input.claim {
        Claim::ExactResultCommitProducedAndCommandExitedZero => Ok(ReviewQueueAdmission {
            attempt: input.commitment.attempt,
            observation: input.observation.id,
            result_commit: input.commitment.result_commit.clone(),
            admitted_at: input.now,
        }),
        Claim::PatchIsCorrect
        | Claim::TaskIsComplete
        | Claim::SafeToMerge
        | Claim::ObligationDischarged
        | Claim::WorkMayBeClosed => Err(RelianceRefusal::ClaimNotAdmissible),
    }
}
