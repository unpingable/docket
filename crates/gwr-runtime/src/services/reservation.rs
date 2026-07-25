//! Reservation: an exclusive one-use claim on the target ref under its expected
//! basis, for one attempt, with expiry. Conflict produces refusal, not waiting.

use crate::ports::adapters::{Clock, IdSource};
use crate::ports::store::{Store, StoreError};
use gwr_core::domain::reservation::ReservationClaim;
use gwr_core::ids::{AttemptId, ReservationId};
use gwr_core::refusal::TransitionRefusal;

#[derive(Debug, PartialEq, Eq)]
pub enum ReserveError {
    Store(StoreError),
    /// Another active reservation holds the same repository and target ref.
    Conflict,
    Transition(TransitionRefusal),
}

impl From<StoreError> for ReserveError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::ReservationConflict => Self::Conflict,
            other => Self::Store(other),
        }
    }
}

/// Reserve the attempt's target ref exclusively. The claim's one use is spent
/// later, by dispatch.
pub fn reserve(
    store: &mut dyn Store,
    attempt_id: AttemptId,
    ttl_ms: u64,
    clock: &dyn Clock,
    ids: &mut dyn IdSource,
) -> Result<ReservationClaim, ReserveError> {
    let projected = store.get_attempt(attempt_id)?;
    let now = clock.now();
    let claim = ReservationClaim::claim(
        ReservationId::from_bytes(ids.fresh16()),
        projected.attempt.repository.clone(),
        projected.attempt.effect.target_ref.clone(),
        projected.attempt.effect.expected_basis.clone(),
        attempt_id,
        gwr_core::work_request::ClockReading(now.0 + ttl_ms),
    );
    // Validate the transition before creating the claim, so a malformed request
    // does not leave an orphan reservation holding the ref.
    let new_state = projected
        .state
        .reserve(claim.id())
        .map_err(ReserveError::Transition)?;
    store.create_reservation(&claim, now)?;
    store.record_reserved(projected.version, attempt_id, &new_state, now)?;
    Ok(claim)
}
