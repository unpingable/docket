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

/// The authoritative binding a fact is checked against: the admitted attempt's
/// own fields and the attempt's one dispatch identity, never the fact's.
///
/// A recovery fact carries a copy of every binding field. Those copies are the
/// fact's testimony, not the yardstick: comparing the fact against itself would
/// reduce validation to "does this document agree with itself?" and would let a
/// fact manufacture a verdict about an attempt it never touched.
#[derive(Clone, Copy, Debug)]
pub struct AuthoritativeBinding<'a> {
    pub attempt: AttemptId,
    pub dispatch: DispatchId,
    pub prepared_attempt_digest: &'a Sha256Digest,
    pub repository: &'a RepositoryIdentity,
    pub target_ref: &'a RefName,
    pub basis: &'a CommitHash,
}

impl RecoveryFact {
    /// What this fact establishes about the attempt named by `authoritative` —
    /// and only that attempt. The comparison baseline is the attempt's own
    /// basis, never the fact's copy of it. Conflicting or insufficient evidence
    /// establishes nothing and leaves the attempt indeterminate.
    pub fn establishes(&self, authoritative: &AuthoritativeBinding<'_>) -> Option<RecoveryVerdict> {
        // The ref still holds the attempt's real basis: the effect did not land.
        if &self.observed_ref == authoritative.basis {
            return Some(RecoveryVerdict::ProvenNotCommitted);
        }
        // The ref holds exactly the commit the broker journal established this
        // dispatch would produce: the effect landed. A result equal to the basis
        // is not a commitment, and is rejected above.
        match &self.expected_result_commit {
            Some(expected) if &self.observed_ref == expected && expected != authoritative.basis => {
                Some(RecoveryVerdict::CommittedViaRecovery)
            }
            _ => None,
        }
    }
}

/// Pure validation that a fact may resolve a given attempt's dispatch. Every
/// semantically binding field is compared against `authoritative`; nothing is
/// taken on the fact's own word. This checks binding only — standing validity is
/// separate authority, and the bridge requires both.
pub fn validate_fact_binding(
    fact: &RecoveryFact,
    authoritative: &AuthoritativeBinding<'_>,
) -> Result<(), RecoveryRefusal> {
    if fact.attempt != authoritative.attempt {
        return Err(RecoveryRefusal::AttemptMismatch {
            fact_names: fact.attempt,
            resolving: authoritative.attempt,
        });
    }
    if fact.dispatch != authoritative.dispatch {
        return Err(RecoveryRefusal::DispatchMismatch {
            fact_names: fact.dispatch,
            resolving: authoritative.dispatch,
        });
    }
    if &fact.prepared_attempt_digest != authoritative.prepared_attempt_digest {
        return Err(RecoveryRefusal::BindingIncomplete);
    }
    if &fact.repository != authoritative.repository {
        return Err(RecoveryRefusal::RepositoryMismatch);
    }
    if &fact.target_ref != authoritative.target_ref {
        return Err(RecoveryRefusal::TargetRefMismatch);
    }
    if &fact.basis != authoritative.basis {
        return Err(RecoveryRefusal::BasisMismatch);
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
