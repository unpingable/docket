//! The neutral labor-provider port.
//!
//! A provider adapter may: submit bounded work, emit sequenced neutral events,
//! return immutable candidate artifacts, report provider refusal or failure,
//! accept best-effort cancellation. It may not: admit attempts, ratify, reserve,
//! dispatch, resolve recovery, produce trusted observations, decide reliance,
//! discharge obligations, or close work — no such operations exist on this port.
//!
//! Nothing here names a provider. Everything a provider says arrives as
//! provenance: stored as-said, never believed.

use gwr_core::ids::PreparationRunId;
use gwr_core::work_request::{ClockReading, CommitHash};
use std::path::PathBuf;

/// The bounded work handed to a provider: a disposable workspace, an exact
/// basis, a goal, and a deadline. No credentials, no standing, no reservation
/// handles, no dispatch permits, no recovery authority.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BoundedAssignment {
    pub preparation_run: PreparationRunId,
    pub goal: String,
    pub basis: CommitHash,
    /// A disposable workspace populated by the runtime. Never the governed
    /// target repository.
    pub workspace: PathBuf,
    pub deadline: ClockReading,
}

/// Neutral events, sequenced by the adapter. Untrusted records.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ProviderEvent {
    Started,
    Progress(String),
    /// A tool request from the provider. Carries no authority; it is a record
    /// of what was asked, nothing more.
    ToolRequest(String),
    CandidateReady,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SequencedEvent {
    pub seq: u64,
    pub event: ProviderEvent,
}

/// What the provider said about its own work. Provenance only.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProvenanceEntry {
    pub label: String,
    pub content: String,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PreparationOutcome {
    /// The provider produced candidate bytes. The runtime computes the digest;
    /// any provider-reported digest is provenance.
    Candidate {
        patch: Vec<u8>,
    },
    Refused {
        explanation: String,
    },
    Failed {
        reason: String,
    },
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PreparationReport {
    pub events: Vec<SequencedEvent>,
    pub outcome: PreparationOutcome,
    pub provenance: Vec<ProvenanceEntry>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ProviderError {
    /// The provider died or the adapter lost it before any outcome.
    Died(String),
}

pub trait LaborProvider {
    fn prepare(
        &mut self,
        assignment: &BoundedAssignment,
    ) -> Result<PreparationReport, ProviderError>;

    /// Best-effort cancellation. Default: unsupported, no-op.
    fn cancel(&mut self, _run: PreparationRunId) {}
}
