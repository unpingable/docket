//! Recovery resolution through `RecoveryStandingToResolutionV1`.
//!
//! A recovery fact cannot apply itself, and it cannot supply its own verdict.
//! The runtime establishes what the world says — the current ref value, the
//! broker journal for this dispatch verified against the digest recorded at
//! indeterminacy, and the commitment ledger's attribution of the observed
//! commit — and derives the verdict from that record. The fact is required to
//! agree with all of it; agreement makes it a usable observation, not an
//! authority. Applying it additionally requires separately held recovery
//! standing, and either half alone is refused.
//!
//! **What the ref reading can and cannot establish.** The current ref value is
//! the entire evidentiary basis for `ProvenNotCommitted`. From "the ref holds
//! the basis" this service concludes non-occurrence, which is sound only while
//! the governed broker is the sole writer of that ref — the premise named by
//! `ExclusiveRefCustody` and asserted here on the deployment's behalf. If any
//! other writer can reach the ref, the same reading is equally consistent with
//! an effect that landed and was reverted, and no durable evidence separates the
//! two: `refs/gwr/*` carries no reflog under Git's default settings. See
//! `docs/governed-runtime/trust-model.md`.

use crate::ports::adapters::{Clock, IdSource};
use crate::ports::recovery_evidence::{expected_result_from_journal, RecoveryEvidenceSource};
use crate::ports::store::{Store, StoreError};
use gwr_core::bridge::recovery_standing_to_resolution as rec_bridge;
use gwr_core::digest::Sha256Digest;
use gwr_core::domain::standing::StandingUse;
use gwr_core::ids::{
    ActorId, AttemptId, RecoveryFactId, RecoveryResolutionId, StandingGrantId, StandingUseId,
};
use gwr_core::lifecycle::AttemptState;
use gwr_core::recovery::{AuthoritativeBinding, ExclusiveRefCustody, RecoveryResolution};
use gwr_core::refusal::{RecoveryRefusal, TransitionRefusal};

#[derive(Debug, PartialEq, Eq)]
pub enum ResolveError {
    Store(StoreError),
    Bridge(rec_bridge::Refusal),
    Transition(TransitionRefusal),
    /// The runtime could not establish the world's current state for itself.
    Evidence(String),
}

impl From<StoreError> for ResolveError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

/// Apply a recovery fact to an indeterminate attempt, under separate recovery
/// standing. Refusals leave the attempt, the fact, and the standing unchanged.
#[allow(clippy::too_many_arguments)]
pub fn resolve(
    store: &mut dyn Store,
    attempt_id: AttemptId,
    fact_id: RecoveryFactId,
    grant_id: StandingGrantId,
    actor: ActorId,
    evidence: &mut dyn RecoveryEvidenceSource,
    clock: &dyn Clock,
    ids: &mut dyn IdSource,
) -> Result<RecoveryResolution, ResolveError> {
    let projected = store.get_attempt(attempt_id)?;
    let AttemptState::Indeterminate { dispatch, .. } = &projected.state else {
        return Err(ResolveError::Transition(
            TransitionRefusal::NotIndeterminate,
        ));
    };
    let dispatch_id = dispatch.dispatch;
    let attempt = &projected.attempt;

    // What the runtime recorded when this dispatch became indeterminate.
    let indeterminate = store.get_indeterminate(attempt_id)?;
    let recorded_digest = indeterminate
        .last_journal_digest
        .unwrap_or(Sha256Digest::of_bytes(b""));

    // The journal, verified against that digest before a word of it is read.
    let journal = evidence
        .read_journal(dispatch_id)
        .map_err(ResolveError::Evidence)?;
    let journal_digest = Sha256Digest::of_bytes(&journal);
    if journal_digest != recorded_digest {
        return Err(ResolveError::Bridge(rec_bridge::Refusal::Recovery(
            RecoveryRefusal::JournalDigestMismatch,
        )));
    }
    let expected_result = expected_result_from_journal(&journal);

    // The world, read by the runtime rather than reported to it.
    let observed_ref = evidence
        .read_target_ref(&attempt.repository, &attempt.effect.target_ref)
        .map_err(ResolveError::Evidence)?;
    let observed_ref_owner = store.find_commitment_owner(&observed_ref)?;

    let authoritative = AuthoritativeBinding {
        attempt: attempt_id,
        dispatch: dispatch_id,
        prepared_attempt_digest: &attempt.prepared_attempt_digest,
        repository: &attempt.repository,
        target_ref: &attempt.effect.target_ref,
        basis: &attempt.effect.expected_basis,
        journal_digest: &journal_digest,
        observed_ref: &observed_ref,
        expected_result: expected_result.as_ref(),
        observed_ref_owner,
        // The deployment asserts that the governed broker is the only writer of
        // this target ref. The runtime cannot check that, and does not claim to:
        // without it, `ProvenNotCommitted` reports only that the effect is not
        // presently reflected in the ref, not that it never landed.
        custody: ExclusiveRefCustody::asserted_by_deployment(),
    };

    let fact = store.get_recovery_fact(fact_id)?;
    let grant = store.get_standing_grant(grant_id)?;
    let now = clock.now();
    let out = rec_bridge::cross(rec_bridge::Input {
        version: rec_bridge::VERSION,
        fact: &fact,
        grant: &grant,
        actor,
        authoritative,
        now,
        new_resolution: RecoveryResolutionId::from_bytes(ids.fresh16()),
        new_use: StandingUseId::from_bytes(ids.fresh16()),
    })
    .map_err(ResolveError::Bridge)?;
    let new_state = projected
        .state
        .resolve(out.resolution_ref.clone(), out.verdict)
        .map_err(ResolveError::Transition)?;
    let standing_use = StandingUse {
        id: out.resolution.recovery_standing_use,
        grant: grant.id(),
        used_at: now,
    };
    store.record_recovery_resolution(
        projected.version,
        &out.resolution,
        &new_state,
        &grant,
        &standing_use,
    )?;
    Ok(out.resolution)
}
