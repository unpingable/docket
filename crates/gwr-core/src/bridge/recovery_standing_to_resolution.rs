//! `RecoveryStandingToResolutionV1` — from (an authentic recovery fact bound to
//! exactly this attempt and dispatch) AND (separately held recovery standing) to
//! resolution of an indeterminate attempt as exactly `CommittedViaRecovery` or
//! `ProvenNotCommitted`.
//!
//! Either half alone is refused: authenticity is not authority, and authority
//! without exactly-bound evidence resolves nothing. Conflicting evidence is not
//! weighed — it produces no resolution and the attempt remains indeterminate.
//! Does not transport: fault, blame, correctness, retry wisdom, or any
//! reclassification of `DispatchRefused`.
//!
//! **Premise carried, not proved.** Both verdicts are derived from a reading of
//! the governed target ref, so both are conditional on
//! `recovery::ExclusiveRefCustody` — the deployment's assertion that the
//! governed broker is the sole writer of that ref from dispatch through the
//! recovery observation. The premise is a required field of the
//! `AuthoritativeBinding` this bridge consumes, so no caller can reach a verdict
//! without naming it. This bridge does not verify it and cannot: what else may
//! write a Git ref is a property of the deployment, not of this process.

use crate::domain::standing::{StandingAct, StandingGrant};
use crate::ids::{ActorId, RecoveryResolutionId, StandingUseId};
use crate::lifecycle::{RecoveryResolutionRef, RecoveryVerdict};
use crate::recovery::{
    validate_fact_binding, AuthoritativeBinding, RecoveryFact, RecoveryResolution,
};
use crate::refusal::{RecoveryRefusal, StandingRefusal};
use crate::work_request::ClockReading;

pub const VERSION: u32 = 1;

#[derive(Clone, Debug)]
pub struct Input<'a> {
    pub version: u32,
    pub fact: &'a RecoveryFact,
    pub grant: &'a StandingGrant,
    pub actor: ActorId,
    /// Everything the runtime established about this dispatch. The verdict is
    /// derived from this and nothing else; the fact must merely agree with it.
    pub authoritative: AuthoritativeBinding<'a>,
    pub now: ClockReading,
    pub new_resolution: RecoveryResolutionId,
    pub new_use: StandingUseId,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Output {
    pub resolution: RecoveryResolution,
    pub consumed_grant: StandingGrant,
    pub resolution_ref: RecoveryResolutionRef,
    pub verdict: RecoveryVerdict,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refusal {
    VersionUnsupported { presented: u32 },
    Recovery(RecoveryRefusal),
}

#[allow(clippy::result_large_err)]
pub fn cross(input: Input<'_>) -> Result<Output, Refusal> {
    if input.version != VERSION {
        return Err(Refusal::VersionUnsupported {
            presented: input.version,
        });
    }
    let authoritative = input.authoritative;
    // A commit the ledger attributes to another attempt is structurally
    // incapable of settling this one; say so with its own refusal rather than
    // letting it fall through as merely inconclusive.
    if let Some(owner) = authoritative.observed_ref_owner {
        if owner != authoritative.attempt {
            return Err(Refusal::Recovery(
                RecoveryRefusal::CommitAttributedElsewhere,
            ));
        }
    }
    validate_fact_binding(input.fact, &authoritative).map_err(Refusal::Recovery)?;
    let Some(verdict) = authoritative.establishes() else {
        return Err(Refusal::Recovery(RecoveryRefusal::ConflictingEvidence));
    };
    let (consumed_grant, standing_use) = input
        .grant
        .consume(
            input.actor,
            StandingAct::ResolveRecovery,
            authoritative.repository,
            authoritative.prepared_attempt_digest,
            input.now,
            input.new_use,
        )
        .map_err(|e| {
            Refusal::Recovery(match e {
                StandingRefusal::ScopeMismatch | StandingRefusal::IntegrityFailure => {
                    RecoveryRefusal::StandingInsufficient
                }
                StandingRefusal::Expired => RecoveryRefusal::StandingExpired,
                StandingRefusal::AlreadyUsed => RecoveryRefusal::StandingAlreadyUsed,
            })
        })?;
    let resolution = RecoveryResolution {
        id: input.new_resolution,
        attempt: authoritative.attempt,
        dispatch: authoritative.dispatch,
        fact: input.fact.id,
        verdict,
        recovery_standing_use: standing_use.id,
        resolved_at: input.now,
    };
    Ok(Output {
        resolution,
        consumed_grant,
        resolution_ref: RecoveryResolutionRef {
            resolution: input.new_resolution,
        },
        verdict,
    })
}
