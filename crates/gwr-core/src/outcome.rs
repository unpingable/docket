//! Exact execution outcomes.
//!
//! The governed effect is the atomic target-ref transition. A commitment records
//! that the ref moved — that is all it means. Commitment is distinct from
//! observation success, and no outcome record is ever rewritten by a later
//! observation.

use crate::digest::Sha256Digest;
use crate::ids::{AttemptId, DispatchId};
use crate::refusal::DispatchRefusalGround;
use crate::work_request::{ClockReading, CommitHash, RefName};

/// The broker acknowledged the atomic ref update.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Commitment {
    pub attempt: AttemptId,
    pub dispatch: DispatchId,
    pub target_ref: RefName,
    pub previous_value: CommitHash,
    pub result_commit: CommitHash,
    pub journal_digest: Sha256Digest,
    pub committed_at: ClockReading,
}

/// The broker definitively refused; no ref update occurred. Distinct forever
/// from indeterminacy and from a later `ProvenNotCommitted`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DispatchRefusalRecord {
    pub attempt: AttemptId,
    pub dispatch: DispatchId,
    pub ground: DispatchRefusalGround,
    pub journal_digest: Sha256Digest,
    pub refused_at: ClockReading,
}

/// The outcome of the dispatch is unknown, and the runtime has no admissible
/// basis for deciding. A positive fact, durably recorded, surviving restart.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IndeterminateRecord {
    pub attempt: AttemptId,
    pub dispatch: DispatchId,
    /// Digest of the last broker journal state that was established, if any.
    pub last_journal_digest: Option<Sha256Digest>,
    pub recorded_at: ClockReading,
}
