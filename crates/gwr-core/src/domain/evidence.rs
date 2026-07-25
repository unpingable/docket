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

impl Claim {
    /// The one claim vocabulary, shared by the CLI, the store encoding, and the
    /// read surfaces. A claim that round-trips through persistence must come
    /// back as the same claim.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::ExactResultCommitProducedAndCommandExitedZero => "effect-and-command",
            Self::PatchIsCorrect => "patch-correct",
            Self::TaskIsComplete => "task-complete",
            Self::SafeToMerge => "safe-to-merge",
            Self::ObligationDischarged => "obligation-discharged",
            Self::WorkMayBeClosed => "work-closed",
        }
    }

    pub fn from_tag(tag: &str) -> Option<Self> {
        Some(match tag {
            "effect-and-command" => Self::ExactResultCommitProducedAndCommandExitedZero,
            "patch-correct" => Self::PatchIsCorrect,
            "task-complete" => Self::TaskIsComplete,
            "safe-to-merge" => Self::SafeToMerge,
            "obligation-discharged" => Self::ObligationDischarged,
            "work-closed" => Self::WorkMayBeClosed,
            _ => return None,
        })
    }
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
