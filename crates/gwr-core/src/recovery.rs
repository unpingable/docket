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

/// Everything the runtime itself established about an indeterminate dispatch.
///
/// A recovery fact carries a copy of every one of these. Those copies are the
/// fact's *testimony*; this struct is the *record*. The verdict is derived from
/// this struct alone — a fact contributes no value to it — because a document
/// that supplies both the proposition and its comparison baseline reduces
/// validation to "does this agree with itself?"
///
/// Sources, none of them the fact:
/// - identity, repository, ref, basis: the admitted attempt and its persisted
///   dispatch;
/// - `journal_digest`: recorded when the dispatch became indeterminate;
/// - `expected_result`: parsed from the broker journal *after* that journal is
///   confirmed to hash to `journal_digest`;
/// - `observed_ref`: read from the repository by the runtime at resolution;
/// - `observed_ref_owner`: the commitment ledger's attribution of that commit.
///
/// Journal-digest binding answers "was this altered since we recorded it?", not
/// "was this true?" — which is why commit attribution is checked separately.
#[derive(Clone, Copy, Debug)]
pub struct AuthoritativeBinding<'a> {
    pub attempt: AttemptId,
    pub dispatch: DispatchId,
    pub prepared_attempt_digest: &'a Sha256Digest,
    pub repository: &'a RepositoryIdentity,
    pub target_ref: &'a RefName,
    pub basis: &'a CommitHash,
    pub journal_digest: &'a Sha256Digest,
    pub observed_ref: &'a CommitHash,
    pub expected_result: Option<&'a CommitHash>,
    pub observed_ref_owner: Option<AttemptId>,
}

impl AuthoritativeBinding<'_> {
    /// What the runtime's own records establish about this dispatch. The fact
    /// is not consulted: it has already been required to agree with all of this
    /// by `validate_fact_binding`, and it is evidence of an observation, not a
    /// source of the verdict.
    pub fn establishes(&self) -> Option<RecoveryVerdict> {
        // A commit the ledger attributes to a different attempt cannot settle
        // this one, in either direction. Structural, not a careful comparison.
        if let Some(owner) = self.observed_ref_owner {
            if owner != self.attempt {
                return None;
            }
        }
        // The ref still holds this attempt's real basis: the effect did not land.
        if self.observed_ref == self.basis {
            return Some(RecoveryVerdict::ProvenNotCommitted);
        }
        // The ref holds exactly the commit this dispatch's own journal recorded
        // creating. A "result" equal to the basis is not a commitment.
        match self.expected_result {
            Some(expected) if self.observed_ref == expected && expected != self.basis => {
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
    // The fact's observations must agree with what the runtime established. A
    // fact that disagrees is not a usable observation of this dispatch — and
    // since the verdict comes from the record rather than the fact, a fact that
    // agrees adds no authority either.
    if &fact.journal_digest != authoritative.journal_digest {
        return Err(RecoveryRefusal::JournalDigestMismatch);
    }
    if &fact.observed_ref != authoritative.observed_ref {
        return Err(RecoveryRefusal::ObservedRefMismatch);
    }
    if fact.expected_result_commit.as_ref() != authoritative.expected_result {
        return Err(RecoveryRefusal::ExpectedResultMismatch);
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
