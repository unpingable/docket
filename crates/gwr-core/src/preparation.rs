//! Bounded provider invocations and immutable candidate artifacts.
//!
//! Provider identity never appears here: a preparation run is identified only by
//! its `PreparationRunId`. Everything a provider says is provenance, stored
//! elsewhere and never believed.

use crate::digest::Sha256Digest;
use crate::ids::{CandidateArtifactId, PreparationRunId, WorkRequestId};
use crate::work_request::ClockReading;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PreparationEnd {
    /// The run returned a candidate artifact.
    CandidateProduced,
    /// The provider refused the assignment. Its explanation is provenance.
    ProviderRefused,
    /// The provider died or the adapter lost it. Not an effect outcome: provider
    /// death mints nothing about any effect.
    ProviderFailed,
    /// Best-effort cancellation was accepted.
    Cancelled,
    /// The run's deadline passed. Expired runs do not revive.
    Expired,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PreparationStatus {
    Running,
    Ended(PreparationEnd),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PreparationRun {
    pub id: PreparationRunId,
    pub work_request: WorkRequestId,
    pub started_at: ClockReading,
    pub deadline: ClockReading,
    pub status: PreparationStatus,
}

/// An immutable candidate artifact: content, not identity. The digest and length
/// are computed by the runtime from the exact bytes; a provider-reported digest
/// is provenance and is never used in its place. Two attempts may carry
/// byte-identical candidates and remain distinct attempts.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CandidateArtifact {
    pub id: CandidateArtifactId,
    pub preparation_run: PreparationRunId,
    pub content_digest: Sha256Digest,
    pub content_len: u64,
    pub ingested_at: ClockReading,
}
