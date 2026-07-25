//! Evidence scope and claims.
//!
//! Reliance is consumer-indexed and claim-indexed: whether this consumer may
//! treat this artifact as establishing this claim. A single artifact admits some
//! claims and refuses others; a reliance decision that returns one boolean has
//! already lost.

use crate::observation_plan::ObservationRecord;
use crate::outcome::Commitment;
use crate::refusal::ObservationRefusal;

/// The claims a consumer might present against an observation. Exactly one is
/// admissible through `ObservationToReviewQueueV1`; the others are the named
/// refusals — an observation establishes nothing about them, in either
/// direction.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Claim {
    /// The one admissible claim: this exact result commit was produced by the
    /// admitted effect, and the named command exited successfully against it.
    ExactResultCommitProducedAndCommandExitedZero,
    PatchIsCorrect,
    TaskIsComplete,
    SafeToMerge,
    ObligationDischarged,
    WorkMayBeClosed,
}

/// Pure scope check: does this observation speak about this commitment at all?
/// An observation of commit A supports no claim about commit B.
pub fn observation_in_scope(
    observation: &ObservationRecord,
    commitment: &Commitment,
) -> Result<(), ObservationRefusal> {
    if observation.attempt != commitment.attempt
        || observation.result_commit != commitment.result_commit
    {
        return Err(ObservationRefusal::ScopeMismatch);
    }
    Ok(())
}
