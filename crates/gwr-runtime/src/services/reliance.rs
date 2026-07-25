//! Consumer-specific reliance for the human-review queue, through
//! `ObservationToReviewQueueV1`. Admission and refusal are both recorded;
//! neither mutates the observation or the commitment.

use crate::ports::adapters::Clock;
use crate::ports::store::{Store, StoreError};
use gwr_core::bridge::observation_to_review_queue as obs_bridge;
use gwr_core::domain::evidence::Claim;
use gwr_core::ids::{AttemptId, ObservationId};
use gwr_core::receipt::ReviewQueueAdmission;
use gwr_core::refusal::RelianceRefusal;

#[derive(Debug, PartialEq, Eq)]
pub enum RelyError {
    Store(StoreError),
    /// The bridge refused. The refusal has been recorded as a first-class
    /// reliance record; the source evidence is untouched.
    Refused(RelianceRefusal),
}

impl From<StoreError> for RelyError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

pub fn rely_review_queue(
    store: &mut dyn Store,
    attempt_id: AttemptId,
    observation_id: ObservationId,
    claim: Claim,
    clock: &dyn Clock,
) -> Result<ReviewQueueAdmission, RelyError> {
    let commitment = store.get_commitment(attempt_id)?;
    let observation = store
        .get_observations(attempt_id)?
        .into_iter()
        .find(|o| o.id == observation_id)
        .ok_or(RelyError::Store(StoreError::NotFound))?;
    let now = clock.now();
    match obs_bridge::cross(obs_bridge::Input {
        version: obs_bridge::VERSION,
        observation: &observation,
        commitment: &commitment,
        claim,
        now,
    }) {
        Ok(admission) => {
            store.record_reliance_admission(&admission)?;
            Ok(admission)
        }
        Err(refusal) => {
            store.record_reliance_refusal(attempt_id, &refusal, now)?;
            Err(RelyError::Refused(refusal))
        }
    }
}
