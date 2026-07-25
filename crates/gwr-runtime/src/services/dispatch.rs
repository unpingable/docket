//! Dispatch: hand the one persisted envelope to the broker and record exactly
//! what came back — commitment, refusal, or indeterminacy. No automatic retry
//! follows ambiguous dispatch, and no success or failure is minted from it.

use crate::ports::adapters::{Clock, IdSource};
use crate::ports::effect_broker::{BrokerOutcome, EffectBroker};
use crate::ports::store::{Store, StoreError};
use gwr_core::bridge::reservation_to_dispatch as rsv_bridge;
use gwr_core::ids::{AttemptId, DispatchId, ReservationUseId};
use gwr_core::lifecycle::AttemptState;
use gwr_core::outcome::{Commitment, DispatchRefusalRecord, IndeterminateRecord};
use gwr_core::refusal::TransitionRefusal;

#[derive(Debug, PartialEq, Eq)]
pub enum DispatchError {
    Store(StoreError),
    Bridge(rsv_bridge::Refusal),
    Transition(TransitionRefusal),
}

impl From<StoreError> for DispatchError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum DispatchOutcome {
    Committed(Commitment),
    Refused(DispatchRefusalRecord),
    Indeterminate(IndeterminateRecord),
    /// A dispatch already exists for this attempt. Its state is returned for
    /// inspection; the effect is never repeated.
    AlreadyDispatched {
        state: AttemptState,
    },
}

/// Dispatch a reserved attempt through the broker.
pub fn dispatch(
    store: &mut dyn Store,
    attempt_id: AttemptId,
    broker: &mut dyn EffectBroker,
    clock: &dyn Clock,
    ids: &mut dyn IdSource,
) -> Result<DispatchOutcome, DispatchError> {
    let projected = store.get_attempt(attempt_id)?;

    // Idempotency: one persisted DispatchId per attempt, ever. Same identity
    // inspects; a different identity for the same attempt is never minted.
    if store.find_attempt_dispatch(attempt_id)?.is_some() {
        return Ok(DispatchOutcome::AlreadyDispatched {
            state: projected.state,
        });
    }

    let AttemptState::Reserved { reservation, .. } = &projected.state else {
        return Err(DispatchError::Transition(TransitionRefusal::NotReserved));
    };
    let claim = store.get_reservation(*reservation)?;
    let ratification = match &projected.state {
        AttemptState::Reserved { ratification, .. } => ratification.clone(),
        _ => unreachable!(),
    };
    let now = clock.now();
    let out = rsv_bridge::cross(rsv_bridge::Input {
        version: rsv_bridge::VERSION,
        claim: &claim,
        ratification: &ratification,
        attempt: &projected.attempt,
        existing_dispatch: None,
        now,
        new_dispatch: DispatchId::from_bytes(ids.fresh16()),
        new_use: ReservationUseId::from_bytes(ids.fresh16()),
    })
    .map_err(DispatchError::Bridge)?;
    let dispatching = projected
        .state
        .dispatch(out.reservation_ref.clone(), out.dispatch_ref.clone())
        .map_err(DispatchError::Transition)?;
    store.record_dispatch(
        projected.version,
        &out.envelope,
        &dispatching,
        &out.consumed_claim,
    )?;
    let version = projected.version + 1;

    // The effect. Whatever comes back is recorded exactly; nothing is guessed.
    match broker.execute(&out.envelope) {
        BrokerOutcome::Committed {
            previous,
            result_commit,
            journal_digest,
        } => {
            let commitment = Commitment {
                attempt: attempt_id,
                dispatch: out.envelope.dispatch,
                target_ref: out.envelope.target_ref.clone(),
                previous_value: previous,
                result_commit,
                journal_digest,
                committed_at: clock.now(),
            };
            let state = dispatching.commit().map_err(DispatchError::Transition)?;
            store.record_commitment(version, &commitment, &state)?;
            Ok(DispatchOutcome::Committed(commitment))
        }
        BrokerOutcome::Refused {
            ground,
            journal_digest,
        } => {
            let record = DispatchRefusalRecord {
                attempt: attempt_id,
                dispatch: out.envelope.dispatch,
                ground,
                journal_digest,
                refused_at: clock.now(),
            };
            let state = dispatching
                .refuse_dispatch(ground)
                .map_err(DispatchError::Transition)?;
            store.record_dispatch_refusal(version, &record, &state)?;
            Ok(DispatchOutcome::Refused(record))
        }
        BrokerOutcome::Uncertain {
            last_journal_digest,
        } => {
            let record = IndeterminateRecord {
                attempt: attempt_id,
                dispatch: out.envelope.dispatch,
                last_journal_digest,
                recorded_at: clock.now(),
            };
            let state = dispatching
                .mark_indeterminate()
                .map_err(DispatchError::Transition)?;
            store.record_indeterminate(version, &record, &state)?;
            Ok(DispatchOutcome::Indeterminate(record))
        }
    }
}
