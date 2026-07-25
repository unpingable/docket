//! Ratification: an actor with standing binds itself to an exact prepared
//! attempt, by digest, through `StandingToRatificationV1`.

use crate::ports::adapters::{Clock, IdSource};
use crate::ports::store::{Store, StoreError};
use gwr_core::bridge::standing_to_ratification as rat_bridge;
use gwr_core::digest::Sha256Digest;
use gwr_core::domain::standing::StandingUse;
use gwr_core::ids::{ActorId, AttemptId, RatificationId, StandingGrantId, StandingUseId};
use gwr_core::receipt::RatificationReceipt;
use gwr_core::refusal::TransitionRefusal;
use gwr_core::work_request::CommitHash;

#[derive(Debug, PartialEq, Eq)]
pub enum RatifyError {
    Store(StoreError),
    Bridge(rat_bridge::Refusal),
    Transition(TransitionRefusal),
}

impl From<StoreError> for RatifyError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

/// Ratify an exact prepared attempt. Consumes the standing use exactly once on
/// success; refusals consume nothing.
#[allow(clippy::too_many_arguments)]
pub fn ratify(
    store: &mut dyn Store,
    attempt_id: AttemptId,
    grant_id: StandingGrantId,
    actor: ActorId,
    ratified_digest: Sha256Digest,
    ratified_basis: CommitHash,
    clock: &dyn Clock,
    ids: &mut dyn IdSource,
) -> Result<RatificationReceipt, RatifyError> {
    let projected = store.get_attempt(attempt_id)?;
    let grant = store.get_standing_grant(grant_id)?;
    let now = clock.now();
    let out = rat_bridge::cross(rat_bridge::Input {
        version: rat_bridge::VERSION,
        grant: &grant,
        actor,
        attempt: &projected.attempt,
        ratified_digest,
        ratified_basis,
        now,
        new_ratification: RatificationId::from_bytes(ids.fresh16()),
        new_use: StandingUseId::from_bytes(ids.fresh16()),
    })
    .map_err(RatifyError::Bridge)?;
    let new_state = projected
        .state
        .ratify(out.ratification_ref.clone())
        .map_err(RatifyError::Transition)?;
    let standing_use = StandingUse {
        id: out.receipt.standing_use,
        grant: grant.id(),
        used_at: now,
    };
    store.record_ratification(
        projected.version,
        &out.receipt,
        &new_state,
        &grant,
        &standing_use,
    )?;
    Ok(out.receipt)
}
