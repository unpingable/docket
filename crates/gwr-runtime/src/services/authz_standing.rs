//! Minting local standing from a verified upstream authorization issuance.
//!
//! The upstream office decided; Docket does not re-decide. What happens here
//! is custody, not policy: given an issuance the adapter has already
//! authenticated and bound to this exact attempt, record it as the basis and
//! mint **Docket's own** standing — local, bound to the exact prepared digest,
//! single-use, expiring no later than the issuance.
//!
//! Three laws are enforced here rather than described:
//!
//! - one issuance justifies at most one grant (the store's unique index);
//! - a grant's expiry is never wider than its issuance's;
//! - the grant is an ordinary Docket grant afterwards — consumed once by the
//!   ordinary ratification path, with no upstream re-animation.

use crate::ports::store::{Store, StoreError};
use gwr_core::authorization::AcceptedIssuance;
use gwr_core::domain::standing::{StandingAct, StandingGrant, StandingScope};
use gwr_core::ids::{ActorId, StandingGrantId};
use gwr_core::work_request::ClockReading;

#[derive(Debug, PartialEq, Eq)]
pub enum MintError {
    Store(StoreError),
    /// The issuance already justified a grant. It cannot justify a second one,
    /// for this attempt or any other.
    AlreadyMinted {
        issuance_id: String,
    },
    /// A different signed body was presented under an issuance identity that
    /// was already accepted — substitution, not repetition.
    IssuanceSubstitution {
        issuance_id: String,
    },
    /// The issuance has expired against the runtime clock; an expired
    /// authorization cannot justify fresh standing.
    Expired {
        expires_at: u64,
        now: u64,
    },
    /// The attempt's stored prepared digest disagrees with the accepted
    /// issuance. Defence in depth: intake already compared these.
    DigestMismatch,
}

impl From<StoreError> for MintError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

/// Record the verified issuance and mint the standing it justifies.
///
/// `ttl_ms` is the caller's requested local lifetime; the grant's expiry is
/// the earlier of that and the issuance's own expiry, so Docket standing is
/// never live longer than the authorization behind it.
pub fn mint_from_issuance(
    store: &mut dyn Store,
    issuance: &AcceptedIssuance,
    actor: ActorId,
    act: StandingAct,
    grant_id: StandingGrantId,
    now: ClockReading,
    ttl_ms: u64,
) -> Result<StandingGrant, MintError> {
    if now.0 >= issuance.expires_at.0 {
        return Err(MintError::Expired {
            expires_at: issuance.expires_at.0,
            now: now.0,
        });
    }
    let projected = store.get_attempt(issuance.attempt)?;
    if projected.attempt.prepared_attempt_digest != issuance.prepared_digest {
        return Err(MintError::DigestMismatch);
    }
    // Idempotent record. A different body under the same issuance identity is
    // substitution — including an issuance identity reused for a second
    // attempt — and cannot justify standing.
    match store.record_authz_issuance(issuance) {
        Ok(()) => {}
        Err(StoreError::ImmutableRebind) => {
            return Err(MintError::IssuanceSubstitution {
                issuance_id: issuance.issuance_id.clone(),
            })
        }
        Err(e) => return Err(MintError::Store(e)),
    }

    let expires_at = ClockReading(now.0.saturating_add(ttl_ms).min(issuance.expires_at.0));
    let grant = StandingGrant::issue(
        grant_id,
        StandingScope {
            actor,
            act,
            repository: projected.attempt.repository.clone(),
            attempt_digest: projected.attempt.prepared_attempt_digest,
        },
        expires_at,
    );
    match store.create_upstream_standing_grant(&grant, &issuance.issuance_id) {
        Ok(()) => Ok(grant),
        Err(StoreError::ImmutableRebind) => Err(MintError::AlreadyMinted {
            issuance_id: issuance.issuance_id.clone(),
        }),
        Err(e) => Err(MintError::Store(e)),
    }
}
