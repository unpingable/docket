//! Small neutral ports: clock, identity generation, artifact storage, and
//! adapter-local provenance recording.

use gwr_core::digest::Sha256Digest;
use gwr_core::ids::PreparationRunId;
use gwr_core::work_request::ClockReading;

use super::labor_provider::ProvenanceEntry;

/// Runtime clock readings control expiry. Core code only compares readings.
pub trait Clock {
    fn now(&self) -> ClockReading;
}

/// Fresh identity bytes. Randomness is an adapter concern.
pub trait IdSource {
    fn fresh16(&mut self) -> [u8; 16];
}

/// Immutable artifact storage. The digest is computed by the runtime from the
/// exact bytes stored.
pub trait ArtifactStore {
    fn put(&mut self, bytes: &[u8]) -> Result<(Sha256Digest, u64), String>;
    fn get(&mut self, digest: &Sha256Digest) -> Result<Vec<u8>, String>;
}

/// Adapter-local provenance sink. Provenance is stored as-said, never believed,
/// and never enters core records or core tables.
pub trait ProvenanceSink {
    fn record(&mut self, run: PreparationRunId, entries: &[ProvenanceEntry]) -> Result<(), String>;
}
