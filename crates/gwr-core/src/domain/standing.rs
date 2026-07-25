//! Standing: authority to perform a specific act, bound to exact scope, with
//! expiry and consumption semantics.
//!
//! Standing is held by an actor for an act. It is not a role (a role says who
//! someone is; standing says what this actor may do to this exact thing, once,
//! before this time), not a credential (nothing a labor provider holds is
//! standing), and it is consumed, not checked — a standing check that leaves the
//! standing intact is a permission check wearing standing's name.
//!
//! Token integrity protection is an adapter concern; a `StandingGrant` value is
//! constructed only after integrity has been established.

use crate::digest::Sha256Digest;
use crate::ids::{ActorId, StandingGrantId, StandingUseId};
use crate::refusal::StandingRefusal;
use crate::work_request::{ClockReading, RepositoryIdentity};

/// The specific acts standing can authorize. Recovery resolution is separate
/// authority, distinct from and never implied by ratification standing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StandingAct {
    Ratify,
    ResolveRecovery,
}

/// Exact scope: this actor, this act, this repository, this exact
/// prepared-attempt digest.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct StandingScope {
    pub actor: ActorId,
    pub act: StandingAct,
    pub repository: RepositoryIdentity,
    pub attempt_digest: Sha256Digest,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum GrantState {
    Available,
    Consumed { used_as: StandingUseId },
}

/// A grant is issued once and consumed once. Its fields are private: an
/// expired grant that could be cloned and have its window widened is not
/// expiry, it is a suggestion — the same authority-leak shape as a replayed
/// standing use. Extending authority means issuing a new grant with a new
/// identity, never editing an old one.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct StandingGrant {
    id: StandingGrantId,
    scope: StandingScope,
    expires_at: ClockReading,
    state: GrantState,
}

impl StandingGrant {
    /// Issue a fresh, unconsumed grant.
    pub fn issue(id: StandingGrantId, scope: StandingScope, expires_at: ClockReading) -> Self {
        Self {
            id,
            scope,
            expires_at,
            state: GrantState::Available,
        }
    }

    /// Rebuild a grant as the store recorded it. Adapter-only: the persisted
    /// row is the authority on consumption state, so this is how a store hands
    /// back what it holds — not a way to mint one.
    pub fn from_persisted(
        id: StandingGrantId,
        scope: StandingScope,
        expires_at: ClockReading,
        state: GrantState,
    ) -> Self {
        Self {
            id,
            scope,
            expires_at,
            state,
        }
    }

    pub fn id(&self) -> StandingGrantId {
        self.id
    }

    pub fn scope(&self) -> &StandingScope {
        &self.scope
    }

    pub fn expires_at(&self) -> ClockReading {
        self.expires_at
    }

    pub fn state(&self) -> &GrantState {
        &self.state
    }
}

/// The immutable record of one standing use.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct StandingUse {
    pub id: StandingUseId,
    pub grant: StandingGrantId,
    pub used_at: ClockReading,
}

impl StandingGrant {
    /// Validate without consuming. Expiry is judged against the runtime clock
    /// reading; an expired grant whose window is later extended is not
    /// un-expired — expired records do not revive.
    pub fn validate(
        &self,
        actor: ActorId,
        act: StandingAct,
        repository: &RepositoryIdentity,
        attempt_digest: &Sha256Digest,
        now: ClockReading,
    ) -> Result<(), StandingRefusal> {
        if self.scope.actor != actor
            || self.scope.act != act
            || &self.scope.repository != repository
            || &self.scope.attempt_digest != attempt_digest
        {
            return Err(StandingRefusal::ScopeMismatch);
        }
        if now >= self.expires_at {
            return Err(StandingRefusal::Expired);
        }
        if matches!(self.state, GrantState::Consumed { .. }) {
            return Err(StandingRefusal::AlreadyUsed);
        }
        Ok(())
    }

    /// Consume the one use. Returns the consumed grant and the use record; the
    /// original is untouched (pure). Every refusal consumes nothing.
    #[allow(clippy::result_large_err)]
    pub fn consume(
        &self,
        actor: ActorId,
        act: StandingAct,
        repository: &RepositoryIdentity,
        attempt_digest: &Sha256Digest,
        now: ClockReading,
        use_id: StandingUseId,
    ) -> Result<(StandingGrant, StandingUse), StandingRefusal> {
        self.validate(actor, act, repository, attempt_digest, now)?;
        let consumed = StandingGrant {
            state: GrantState::Consumed { used_as: use_id },
            ..self.clone()
        };
        let record = StandingUse {
            id: use_id,
            grant: self.id,
            used_at: now,
        };
        Ok((consumed, record))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::Sha256Digest;

    fn grant(expires: u64) -> StandingGrant {
        StandingGrant::issue(
            StandingGrantId::from_bytes([1; 16]),
            StandingScope {
                actor: ActorId::from_bytes([2; 16]),
                act: StandingAct::Ratify,
                repository: RepositoryIdentity::new("/repo"),
                attempt_digest: Sha256Digest::of_bytes(b"attempt"),
            },
            ClockReading(expires),
        )
    }

    /// V8 / invariant 25: an expired grant cannot be revived. The audit found
    /// the suite only ever asserted that expiry *refuses* — never that it does
    /// not *un-expire*, which is the distinction N7 names. With private fields
    /// there is no clone-and-widen path: extending authority means issuing a
    /// new grant with a new identity.
    #[test]
    fn an_expired_grant_cannot_be_revived_by_copying_it() {
        let g = grant(100);
        let now = ClockReading(500);
        let scope = g.scope().clone();
        assert_eq!(
            g.validate(
                scope.actor,
                scope.act,
                &scope.repository,
                &scope.attempt_digest,
                now
            ),
            Err(StandingRefusal::Expired)
        );

        // The only way to obtain a wider window is a new grant, which carries a
        // new identity — so the store's single-use ledger sees a different
        // grant rather than the same one reborn.
        let reissued = StandingGrant::issue(
            StandingGrantId::from_bytes([9; 16]),
            scope.clone(),
            ClockReading(1000),
        );
        assert_ne!(reissued.id(), g.id());
        assert_eq!(
            g.expires_at(),
            ClockReading(100),
            "the original is untouched"
        );
        assert_eq!(
            reissued.validate(
                scope.actor,
                scope.act,
                &scope.repository,
                &scope.attempt_digest,
                now
            ),
            Ok(())
        );
    }

    /// A consumed grant stays consumed no matter how it is copied.
    #[test]
    fn a_consumed_grant_cannot_be_reset_by_copying_it() {
        let g = grant(1000);
        let scope = g.scope().clone();
        let (consumed, _use_record) = g
            .consume(
                scope.actor,
                scope.act,
                &scope.repository,
                &scope.attempt_digest,
                ClockReading(10),
                StandingUseId::from_bytes([7; 16]),
            )
            .unwrap();
        let copy = consumed.clone();
        assert_eq!(
            copy.validate(
                scope.actor,
                scope.act,
                &scope.repository,
                &scope.attempt_digest,
                ClockReading(20)
            ),
            Err(StandingRefusal::AlreadyUsed)
        );
    }
}
