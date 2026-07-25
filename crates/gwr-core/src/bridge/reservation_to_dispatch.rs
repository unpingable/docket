//! `ReservationToDispatchV1` — from "an exclusive one-use reservation is held
//! for exactly this tuple" to "exactly one dispatch may be minted for this
//! attempt."
//!
//! Transports: the exclusivity fact, the exact reservation tuple, expiry
//! validity, consumption, the ratification linkage. Does not transport: any
//! prediction of success, candidate correctness, ratification wisdom, contention
//! history. Success consumes the reservation use once; refusals consume nothing.

use crate::domain::reservation::ReservationClaim;
use crate::ids::{DispatchId, ReservationUseId};
use crate::lifecycle::{DispatchRef, RatificationRef, ReservationRef};
use crate::prepared_attempt::PreparedAttempt;
use crate::receipt::DispatchEnvelope;
use crate::refusal::ReservationRefusal;
use crate::work_request::ClockReading;

pub const VERSION: u32 = 1;

#[derive(Clone, Debug)]
pub struct Input<'a> {
    pub version: u32,
    pub claim: &'a ReservationClaim,
    /// Dispatch is unreachable without ratification; the caller must present it.
    pub ratification: &'a RatificationRef,
    pub attempt: &'a PreparedAttempt,
    /// The dispatch identity already persisted for this attempt, if any. A
    /// different identity is refused; the same identity is inspected at the
    /// service layer, never re-crossed here.
    pub existing_dispatch: Option<DispatchId>,
    pub now: ClockReading,
    pub new_dispatch: DispatchId,
    pub new_use: ReservationUseId,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Output {
    pub envelope: DispatchEnvelope,
    pub consumed_claim: ReservationClaim,
    pub reservation_ref: ReservationRef,
    pub dispatch_ref: DispatchRef,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refusal {
    VersionUnsupported {
        presented: u32,
    },
    /// The presented ratification does not bind this attempt's digest.
    RatificationMismatch,
    Reservation(ReservationRefusal),
}

#[allow(clippy::result_large_err)]
pub fn cross(input: Input<'_>) -> Result<Output, Refusal> {
    if input.version != VERSION {
        return Err(Refusal::VersionUnsupported {
            presented: input.version,
        });
    }
    if input.ratification.prepared_attempt_digest != input.attempt.prepared_attempt_digest {
        return Err(Refusal::RatificationMismatch);
    }
    if let Some(existing) = input.existing_dispatch {
        if existing != input.new_dispatch {
            return Err(Refusal::Reservation(
                ReservationRefusal::DispatchIdentityConflict,
            ));
        }
        // Same identity: nothing to cross; the existing dispatch is inspected,
        // never repeated. The service layer answers inspection.
        return Err(Refusal::Reservation(ReservationRefusal::AlreadyUsed));
    }
    let (consumed_claim, reservation_use) = input
        .claim
        .consume(input.attempt.attempt_id, input.now, input.new_use)
        .map_err(Refusal::Reservation)?;
    let envelope = DispatchEnvelope {
        dispatch: input.new_dispatch,
        attempt: input.attempt.attempt_id,
        prepared_attempt_digest: input.attempt.prepared_attempt_digest,
        reservation_use: reservation_use.id,
        repository: input.attempt.repository.clone(),
        target_ref: input.attempt.effect.target_ref.clone(),
        expected_basis: input.attempt.effect.expected_basis.clone(),
        patch_digest: input.attempt.effect.patch_digest,
        allowed_paths: input.attempt.effect.allowed_paths.clone(),
        created_at: input.now,
    };
    let reservation_ref = ReservationRef {
        reservation: input.claim.id,
        reservation_use: reservation_use.id,
    };
    let dispatch_ref = DispatchRef {
        dispatch: input.new_dispatch,
    };
    Ok(Output {
        envelope,
        consumed_claim,
        reservation_ref,
        dispatch_ref,
    })
}
