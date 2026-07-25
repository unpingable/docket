//! Exact observation plans and observation records.
//!
//! An observation is a recorded execution of an exact command against an exact
//! result state. It proves nothing but itself: that the named command exited with
//! the named status against the named commit. It is not correctness, completion,
//! merge safety, or discharge, and it cannot rewrite an effect commitment.

use crate::digest::{Sha256Digest, Transcript};
use crate::ids::{AttemptId, ObservationId};
use crate::work_request::{ClockReading, CommitHash};

/// What will be run, exactly, against the exact result commit.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ObservationPlan {
    pub argv: Vec<String>,
    /// Human-meaningful description of the required environment. Recorded, not
    /// enforced by core.
    pub environment_description: String,
}

impl ObservationPlan {
    pub fn transcribe(&self, t: Transcript) -> Transcript {
        let mut t = t.text_field("plan.kind", "command-observation:v1");
        for a in &self.argv {
            t = t.text_field("plan.argv", a);
        }
        t.text_field("plan.environment", &self.environment_description)
    }
}

/// An associated record. Never an execution-state variant.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ObservationRecord {
    pub id: ObservationId,
    pub attempt: AttemptId,
    pub argv: Vec<String>,
    pub working_directory_identity: String,
    /// The exact commit the command ran against.
    pub result_commit: CommitHash,
    pub environment_description: String,
    pub exit_status: i32,
    pub stdout_digest: Sha256Digest,
    pub stderr_digest: Sha256Digest,
    pub observed_at: ClockReading,
}

impl ObservationRecord {
    pub fn succeeded(&self) -> bool {
        self.exit_status == 0
    }
}
