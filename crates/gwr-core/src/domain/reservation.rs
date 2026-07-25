//! Reservation: an exclusive one-use claim on a contested resource — here, a
//! target ref under an expected basis, for one attempt, with expiry.
//!
//! Not a lock (a lock is held and released; a reservation is consumed) and not a
//! queue position (conflict produces refusal, not waiting). A reservation that
//! survives its use is a bug of the same family as replayed standing.

use crate::ids::{AttemptId, ReservationId, ReservationUseId};
use crate::refusal::ReservationRefusal;
use crate::work_request::{ClockReading, CommitHash, RefName, RepositoryIdentity};

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ClaimState {
    Active,
    Consumed { used_as: ReservationUseId },
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ReservationClaim {
    pub id: ReservationId,
    pub repository: RepositoryIdentity,
    pub target_ref: RefName,
    pub basis: CommitHash,
    pub attempt: AttemptId,
    pub expires_at: ClockReading,
    pub state: ClaimState,
}

/// The immutable record of the one reservation use.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ReservationUse {
    pub id: ReservationUseId,
    pub reservation: ReservationId,
    pub used_at: ClockReading,
}

impl ReservationClaim {
    /// Whether granting `other` would violate this claim's exclusivity: same
    /// repository and target ref, both alive at `now`.
    pub fn conflicts_with(
        &self,
        repository: &RepositoryIdentity,
        target_ref: &RefName,
        now: ClockReading,
    ) -> bool {
        matches!(self.state, ClaimState::Active)
            && now < self.expires_at
            && &self.repository == repository
            && &self.target_ref == target_ref
    }

    /// Consume the one use for the named attempt. Pure; refusals consume
    /// nothing. A replayed consumption refuses.
    pub fn consume(
        &self,
        attempt: AttemptId,
        now: ClockReading,
        use_id: ReservationUseId,
    ) -> Result<(ReservationClaim, ReservationUse), ReservationRefusal> {
        if self.attempt != attempt {
            return Err(ReservationRefusal::AttemptMismatch);
        }
        if now >= self.expires_at {
            return Err(ReservationRefusal::Expired);
        }
        if matches!(self.state, ClaimState::Consumed { .. }) {
            return Err(ReservationRefusal::AlreadyUsed);
        }
        let consumed = ReservationClaim {
            state: ClaimState::Consumed { used_as: use_id },
            ..self.clone()
        };
        let record = ReservationUse {
            id: use_id,
            reservation: self.id,
            used_at: now,
        };
        Ok((consumed, record))
    }
}
