//! Attempt-bound recovery.
//!
//! A recovery fact is evidence binding a specific attempt and dispatch to an
//! observable state of the world. Authenticity is not authority: a perfectly
//! valid recovery fact sitting in the store changes nothing. Applying one
//! requires separately held recovery standing, distinct from and not implied by
//! the standing that ratified the attempt. A fact for attempt A says nothing
//! about attempt B, including when the attempts are byte-identical.

use crate::digest::Sha256Digest;
use crate::ids::{AttemptId, DispatchId, RecoveryFactId, RecoveryResolutionId, StandingUseId};
use crate::lifecycle::RecoveryVerdict;
use crate::refusal::RecoveryRefusal;
use crate::work_request::{ClockReading, CommitHash, RefName, RepositoryIdentity};

/// Where a recovery fact came from. Recorded exactly; never graded for truth.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum FactSource {
    BrokerJournal,
    RefInspection,
    OperatorSupplied(String),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RecoveryFact {
    pub id: RecoveryFactId,
    pub attempt: AttemptId,
    pub dispatch: DispatchId,
    pub prepared_attempt_digest: Sha256Digest,
    pub repository: RepositoryIdentity,
    pub target_ref: RefName,
    pub basis: CommitHash,
    /// The value the target ref was observed to hold.
    pub observed_ref: CommitHash,
    /// The result commit the effect would have produced, where computable.
    pub expected_result_commit: Option<CommitHash>,
    pub journal_digest: Sha256Digest,
    pub source: FactSource,
    pub recorded_at: ClockReading,
}

impl RecoveryFact {
    /// What this fact establishes about its own attempt — and only its own.
    /// Conflicting or insufficient evidence establishes nothing.
    pub fn establishes(&self) -> Option<RecoveryVerdict> {
        match &self.expected_result_commit {
            Some(expected) if &self.observed_ref == expected => {
                Some(RecoveryVerdict::CommittedViaRecovery)
            }
            _ if self.observed_ref == self.basis => Some(RecoveryVerdict::ProvenNotCommitted),
            _ => None,
        }
    }
}

/// Pure validation that a fact may resolve a given attempt's dispatch. This
/// checks binding only; standing validity is the domain's job and both are
/// required by the bridge.
pub fn validate_fact_binding(
    fact: &RecoveryFact,
    attempt: AttemptId,
    dispatch: DispatchId,
    prepared_attempt_digest: &Sha256Digest,
) -> Result<(), RecoveryRefusal> {
    if fact.attempt != attempt {
        return Err(RecoveryRefusal::AttemptMismatch {
            fact_names: fact.attempt,
            resolving: attempt,
        });
    }
    if fact.dispatch != dispatch {
        return Err(RecoveryRefusal::DispatchMismatch {
            fact_names: fact.dispatch,
            resolving: dispatch,
        });
    }
    if &fact.prepared_attempt_digest != prepared_attempt_digest {
        return Err(RecoveryRefusal::BindingIncomplete);
    }
    Ok(())
}

/// A separately authorized application of a recovery fact.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RecoveryResolution {
    pub id: RecoveryResolutionId,
    pub attempt: AttemptId,
    pub dispatch: DispatchId,
    pub fact: RecoveryFactId,
    pub verdict: RecoveryVerdict,
    /// The recovery-standing use this resolution consumed. Separate authority;
    /// not the ratification standing.
    pub recovery_standing_use: StandingUseId,
    pub resolved_at: ClockReading,
}
