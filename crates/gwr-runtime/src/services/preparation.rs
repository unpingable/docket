//! Preparation coordination: run a provider under a bounded assignment and
//! ingest what it produced — or record exactly how it ended without one.
//!
//! Provider death mints nothing about any effect. A late candidate is not
//! admitted. The runtime computes artifact digests; provider-reported digests
//! are compared and the mismatch recorded, never trusted.

use crate::ports::adapters::{ArtifactStore, Clock, IdSource, ProvenanceSink};
use crate::ports::labor_provider::{
    BoundedAssignment, LaborProvider, PreparationOutcome, ProviderError, SequencedEvent,
};
use crate::ports::store::{Store, StoreError};
use gwr_core::ids::CandidateArtifactId;
use gwr_core::preparation::{CandidateArtifact, PreparationEnd, PreparationRun};

/// The label under which a provider may report its own digest of the patch.
pub const REPORTED_DIGEST_LABEL: &str = "reported_patch_digest";

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PreparationResult {
    CandidateIngested {
        artifact: CandidateArtifact,
        /// The provider reported a digest and it did not match the runtime's.
        /// The runtime's digest stands; this is a recorded fact about the
        /// provider's testimony.
        reported_digest_mismatch: bool,
    },
    Refused,
    Failed,
    /// The candidate arrived after the run's deadline. It was not ingested and
    /// cannot be admitted; the run is expired and expired runs do not revive.
    LateCandidate,
}

#[derive(Debug)]
pub enum PreparationServiceError {
    Store(StoreError),
    Artifact(String),
    /// The provider's event sequence was not strictly increasing. The run is
    /// ended as provider failure; nothing is ingested.
    DuplicateEventSequence,
}

impl From<StoreError> for PreparationServiceError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

fn sequence_is_strict(events: &[SequencedEvent]) -> bool {
    events.windows(2).all(|w| w[1].seq > w[0].seq)
}

/// Run one bounded preparation to its end state. The `run` must already exist
/// in the store as `Running`.
#[allow(clippy::too_many_arguments)]
pub fn run_preparation(
    store: &mut dyn Store,
    provider: &mut dyn LaborProvider,
    run: &PreparationRun,
    assignment: &BoundedAssignment,
    artifacts: &mut dyn ArtifactStore,
    provenance: &mut dyn ProvenanceSink,
    clock: &dyn Clock,
    ids: &mut dyn IdSource,
) -> Result<PreparationResult, PreparationServiceError> {
    let report = match provider.prepare(assignment) {
        Ok(report) => report,
        Err(ProviderError::Died(_)) => {
            store.end_preparation_run(run.id, PreparationEnd::ProviderFailed, clock.now())?;
            return Ok(PreparationResult::Failed);
        }
    };

    provenance
        .record(run.id, &report.provenance)
        .map_err(PreparationServiceError::Artifact)?;

    if !sequence_is_strict(&report.events) {
        store.end_preparation_run(run.id, PreparationEnd::ProviderFailed, clock.now())?;
        return Err(PreparationServiceError::DuplicateEventSequence);
    }

    match report.outcome {
        PreparationOutcome::Candidate { patch } => {
            let now = clock.now();
            if now > run.deadline {
                store.end_preparation_run(run.id, PreparationEnd::Expired, now)?;
                return Ok(PreparationResult::LateCandidate);
            }
            let (digest, len) = artifacts
                .put(&patch)
                .map_err(PreparationServiceError::Artifact)?;
            let reported_digest_mismatch = report
                .provenance
                .iter()
                .filter(|p| p.label == REPORTED_DIGEST_LABEL)
                .any(|p| p.content != digest.to_hex());
            let artifact = CandidateArtifact {
                id: CandidateArtifactId::from_bytes(ids.fresh16()),
                preparation_run: run.id,
                content_digest: digest,
                content_len: len,
                ingested_at: now,
            };
            store.ingest_candidate(&artifact)?;
            store.end_preparation_run(run.id, PreparationEnd::CandidateProduced, now)?;
            Ok(PreparationResult::CandidateIngested {
                artifact,
                reported_digest_mismatch,
            })
        }
        PreparationOutcome::Refused { .. } => {
            store.end_preparation_run(run.id, PreparationEnd::ProviderRefused, clock.now())?;
            Ok(PreparationResult::Refused)
        }
        PreparationOutcome::Failed { .. } => {
            store.end_preparation_run(run.id, PreparationEnd::ProviderFailed, clock.now())?;
            Ok(PreparationResult::Failed)
        }
    }
}
