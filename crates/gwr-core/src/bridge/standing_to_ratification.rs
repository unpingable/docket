//! `StandingToRatificationV1` — from "this standing is mechanically valid" to
//! "this actor is ratified onto this exact prepared attempt, by digest."
//!
//! Transports: actor identity, exact scope binding, expiry validity at a named
//! clock reading, one-use consumption. Does not transport: why the standing was
//! granted, whether the grant was wise, anything about candidate correctness.
//! Success consumes the standing use exactly once; every refusal consumes
//! nothing.

use crate::digest::Sha256Digest;
use crate::domain::standing::{StandingAct, StandingGrant};
use crate::ids::{ActorId, RatificationId, StandingUseId};
use crate::lifecycle::RatificationRef;
use crate::prepared_attempt::PreparedAttempt;
use crate::receipt::RatificationReceipt;
use crate::refusal::StandingRefusal;
use crate::work_request::{ClockReading, CommitHash};

pub const VERSION: u32 = 1;

#[derive(Clone, Debug)]
pub struct Input<'a> {
    pub version: u32,
    pub grant: &'a StandingGrant,
    pub actor: ActorId,
    pub attempt: &'a PreparedAttempt,
    /// The digest the actor believes they are ratifying. An actor who approves
    /// the idea and ratifies a different digest has done nothing.
    pub ratified_digest: Sha256Digest,
    /// The basis the actor believes the attempt is specified against.
    pub ratified_basis: CommitHash,
    pub now: ClockReading,
    pub new_ratification: RatificationId,
    pub new_use: StandingUseId,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Output {
    pub receipt: RatificationReceipt,
    pub consumed_grant: StandingGrant,
    pub ratification_ref: RatificationRef,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// Only version 1 exists. No fallback.
    VersionUnsupported {
        presented: u32,
    },
    /// The ratification names a different digest than the attempt carries.
    DigestMismatch,
    /// The ratification names a different basis than the attempt carries.
    BasisMismatch,
    Standing(StandingRefusal),
}

#[allow(clippy::result_large_err)]
pub fn cross(input: Input<'_>) -> Result<Output, Refusal> {
    if input.version != VERSION {
        return Err(Refusal::VersionUnsupported {
            presented: input.version,
        });
    }
    if input.ratified_digest != input.attempt.prepared_attempt_digest {
        return Err(Refusal::DigestMismatch);
    }
    if input.ratified_basis != input.attempt.basis {
        return Err(Refusal::BasisMismatch);
    }
    let (consumed_grant, standing_use) = input
        .grant
        .consume(
            input.actor,
            StandingAct::Ratify,
            &input.attempt.repository,
            &input.attempt.prepared_attempt_digest,
            input.now,
            input.new_use,
        )
        .map_err(Refusal::Standing)?;
    let receipt = RatificationReceipt {
        ratification: input.new_ratification,
        attempt: input.attempt.attempt_id,
        prepared_attempt_digest: input.attempt.prepared_attempt_digest,
        actor: input.actor,
        standing_use: standing_use.id,
        clock_reading: input.now,
    };
    let ratification_ref = RatificationRef {
        ratification: input.new_ratification,
        prepared_attempt_digest: input.attempt.prepared_attempt_digest,
        standing_use: standing_use.id,
    };
    Ok(Output {
        receipt,
        consumed_grant,
        ratification_ref,
    })
}
