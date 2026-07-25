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

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct StandingGrant {
    pub id: StandingGrantId,
    pub scope: StandingScope,
    pub expires_at: ClockReading,
    pub state: GrantState,
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
