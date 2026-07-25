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

use crate::digest::Sha256Digest;
use crate::domain::standing::{StandingAct, StandingGrant};
use crate::ids::{ActorId, AttemptId, DispatchId, RecoveryResolutionId, StandingUseId};
use crate::lifecycle::{RecoveryResolutionRef, RecoveryVerdict};
use crate::recovery::{validate_fact_binding, RecoveryFact, RecoveryResolution};
use crate::refusal::{RecoveryRefusal, StandingRefusal};
use crate::work_request::{ClockReading, RepositoryIdentity};

pub const VERSION: u32 = 1;

#[derive(Clone, Debug)]
pub struct Input<'a> {
    pub version: u32,
    pub fact: &'a RecoveryFact,
    pub grant: &'a StandingGrant,
    pub actor: ActorId,
    pub attempt: AttemptId,
    pub dispatch: DispatchId,
    pub prepared_attempt_digest: Sha256Digest,
    pub repository: &'a RepositoryIdentity,
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
    validate_fact_binding(
        input.fact,
        input.attempt,
        input.dispatch,
        &input.prepared_attempt_digest,
    )
    .map_err(Refusal::Recovery)?;
    let Some(verdict) = input.fact.establishes() else {
        return Err(Refusal::Recovery(RecoveryRefusal::ConflictingEvidence));
    };
    let (consumed_grant, standing_use) = input
        .grant
        .consume(
            input.actor,
            StandingAct::ResolveRecovery,
            input.repository,
            &input.prepared_attempt_digest,
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
        attempt: input.attempt,
        dispatch: input.dispatch,
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
