//! Recovery resolution through `RecoveryStandingToResolutionV1`.
//!
//! A recovery fact cannot apply itself. A separately authorized actor applies
//! it; authentic evidence and separate authority are both required, and either
//! alone is refused. The only resolutions are `CommittedViaRecovery` and
//! `ProvenNotCommitted`; unresolved conflicting evidence remains indeterminate.

use crate::ports::adapters::{Clock, IdSource};
use crate::ports::store::{Store, StoreError};
use gwr_core::bridge::recovery_standing_to_resolution as rec_bridge;
use gwr_core::domain::standing::StandingUse;
use gwr_core::ids::{
    ActorId, AttemptId, RecoveryFactId, RecoveryResolutionId, StandingGrantId, StandingUseId,
};
use gwr_core::lifecycle::AttemptState;
use gwr_core::recovery::RecoveryResolution;
use gwr_core::refusal::TransitionRefusal;

#[derive(Debug, PartialEq, Eq)]
pub enum ResolveError {
    Store(StoreError),
    Bridge(rec_bridge::Refusal),
    Transition(TransitionRefusal),
}

impl From<StoreError> for ResolveError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

/// Apply a recovery fact to an indeterminate attempt, under separate recovery
/// standing. Refusals leave the attempt, the fact, and the standing unchanged.
#[allow(clippy::too_many_arguments)]
pub fn resolve(
    store: &mut dyn Store,
    attempt_id: AttemptId,
    fact_id: RecoveryFactId,
    grant_id: StandingGrantId,
    actor: ActorId,
    clock: &dyn Clock,
    ids: &mut dyn IdSource,
) -> Result<RecoveryResolution, ResolveError> {
    let projected = store.get_attempt(attempt_id)?;
    let AttemptState::Indeterminate { dispatch, .. } = &projected.state else {
        return Err(ResolveError::Transition(
            TransitionRefusal::NotIndeterminate,
        ));
    };
    let fact = store.get_recovery_fact(fact_id)?;
    let grant = store.get_standing_grant(grant_id)?;
    let now = clock.now();
    let out = rec_bridge::cross(rec_bridge::Input {
        version: rec_bridge::VERSION,
        fact: &fact,
        grant: &grant,
        actor,
        attempt: attempt_id,
        dispatch: dispatch.dispatch,
        prepared_attempt_digest: projected.attempt.prepared_attempt_digest,
        repository: &projected.attempt.repository,
        now,
        new_resolution: RecoveryResolutionId::from_bytes(ids.fresh16()),
        new_use: StandingUseId::from_bytes(ids.fresh16()),
    })
    .map_err(ResolveError::Bridge)?;
    let new_state = projected
        .state
        .resolve(out.resolution_ref.clone(), out.verdict)
        .map_err(ResolveError::Transition)?;
    let standing_use = StandingUse {
        id: out.resolution.recovery_standing_use,
        grant: grant.id,
        used_at: now,
    };
    store.record_recovery_resolution(
        projected.version,
        &out.resolution,
        &new_state,
        &grant,
        &standing_use,
    )?;
    Ok(out.resolution)
}
