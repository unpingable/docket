//! The exact attempt lifecycle: pure transition validation.
//!
//! States are typed variants, never optional-field records. Observations,
//! reliance decisions, reconciliation, and residual obligations are associated
//! records and never appear here. Transitions are monotone; invalid transitions
//! return a typed refusal and mutate nothing (all functions take `&self` and
//! return a fresh state).
//!
//! Ratification and reservation appear here as reference types only — opaque
//! handles the lifecycle requires. How they are earned (construction, expiry,
//! consumption) is domain and service work, not lifecycle work.

use crate::digest::Sha256Digest;
use crate::ids::{
    DispatchId, RatificationId, RecoveryResolutionId, ReservationId, ReservationUseId,
    StandingUseId,
};
use crate::refusal::{DispatchRefusalGround, TransitionRefusal};

/// Opaque handle proving a ratification exists for this attempt. Binds the exact
/// prepared-attempt digest and the standing use it consumed.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RatificationRef {
    pub ratification: RatificationId,
    pub prepared_attempt_digest: Sha256Digest,
    pub standing_use: StandingUseId,
}

/// Opaque handle proving an exclusive one-use reservation was consumed for this
/// attempt.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ReservationRef {
    pub reservation: ReservationId,
    pub reservation_use: ReservationUseId,
}

/// Handle for the one dispatch of an attempt.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DispatchRef {
    pub dispatch: DispatchId,
}

/// Handle proving a separately authorized recovery resolution.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RecoveryResolutionRef {
    pub resolution: RecoveryResolutionId,
}

/// The two ways out of indeterminacy — and the only two.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecoveryVerdict {
    CommittedViaRecovery,
    ProvenNotCommitted,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AttemptState {
    Prepared,
    Ratified {
        ratification: RatificationRef,
    },
    Reserved {
        ratification: RatificationRef,
        reservation: ReservationRef,
    },
    Dispatching {
        ratification: RatificationRef,
        reservation: ReservationRef,
        dispatch: DispatchRef,
    },
    Committed {
        ratification: RatificationRef,
        reservation: ReservationRef,
        dispatch: DispatchRef,
    },
    DispatchRefused {
        ratification: RatificationRef,
        reservation: ReservationRef,
        dispatch: DispatchRef,
        ground: DispatchRefusalGround,
    },
    Indeterminate {
        ratification: RatificationRef,
        reservation: ReservationRef,
        dispatch: DispatchRef,
    },
    CommittedViaRecovery {
        ratification: RatificationRef,
        reservation: ReservationRef,
        dispatch: DispatchRef,
        resolution: RecoveryResolutionRef,
    },
    ProvenNotCommitted {
        ratification: RatificationRef,
        reservation: ReservationRef,
        dispatch: DispatchRef,
        resolution: RecoveryResolutionRef,
    },
}

impl AttemptState {
    pub fn ratify(&self, ratification: RatificationRef) -> Result<Self, TransitionRefusal> {
        match self {
            Self::Prepared => Ok(Self::Ratified { ratification }),
            _ => Err(TransitionRefusal::NotPrepared),
        }
    }

    pub fn reserve(&self, reservation: ReservationRef) -> Result<Self, TransitionRefusal> {
        match self {
            Self::Ratified { ratification } => Ok(Self::Reserved {
                ratification: ratification.clone(),
                reservation,
            }),
            _ => Err(TransitionRefusal::NotRatified),
        }
    }

    /// Begin the one dispatch. Only reachable from `Reserved`; every later state
    /// refuses with `AlreadyDispatched` — a second dispatch identity is never
    /// minted for an attempt.
    pub fn dispatch(&self, dispatch: DispatchRef) -> Result<Self, TransitionRefusal> {
        match self {
            Self::Reserved {
                ratification,
                reservation,
            } => Ok(Self::Dispatching {
                ratification: ratification.clone(),
                reservation: reservation.clone(),
                dispatch,
            }),
            Self::Prepared | Self::Ratified { .. } => Err(TransitionRefusal::NotReserved),
            _ => Err(TransitionRefusal::AlreadyDispatched),
        }
    }

    pub fn commit(&self) -> Result<Self, TransitionRefusal> {
        match self {
            Self::Dispatching {
                ratification,
                reservation,
                dispatch,
            } => Ok(Self::Committed {
                ratification: ratification.clone(),
                reservation: reservation.clone(),
                dispatch: dispatch.clone(),
            }),
            _ => Err(TransitionRefusal::NotDispatching),
        }
    }

    pub fn refuse_dispatch(
        &self,
        ground: DispatchRefusalGround,
    ) -> Result<Self, TransitionRefusal> {
        match self {
            Self::Dispatching {
                ratification,
                reservation,
                dispatch,
            } => Ok(Self::DispatchRefused {
                ratification: ratification.clone(),
                reservation: reservation.clone(),
                dispatch: dispatch.clone(),
                ground,
            }),
            _ => Err(TransitionRefusal::NotDispatching),
        }
    }

    /// Record that the outcome of the dispatch is unknown. A positive, durable
    /// fact — not the absence of information.
    pub fn mark_indeterminate(&self) -> Result<Self, TransitionRefusal> {
        match self {
            Self::Dispatching {
                ratification,
                reservation,
                dispatch,
            } => Ok(Self::Indeterminate {
                ratification: ratification.clone(),
                reservation: reservation.clone(),
                dispatch: dispatch.clone(),
            }),
            _ => Err(TransitionRefusal::NotDispatching),
        }
    }

    /// The only exit from indeterminacy: a separately authorized recovery
    /// resolution. Indeterminate cannot become success or failure directly.
    pub fn resolve(
        &self,
        resolution: RecoveryResolutionRef,
        verdict: RecoveryVerdict,
    ) -> Result<Self, TransitionRefusal> {
        match self {
            Self::Indeterminate {
                ratification,
                reservation,
                dispatch,
            } => Ok(match verdict {
                RecoveryVerdict::CommittedViaRecovery => Self::CommittedViaRecovery {
                    ratification: ratification.clone(),
                    reservation: reservation.clone(),
                    dispatch: dispatch.clone(),
                    resolution,
                },
                RecoveryVerdict::ProvenNotCommitted => Self::ProvenNotCommitted {
                    ratification: ratification.clone(),
                    reservation: reservation.clone(),
                    dispatch: dispatch.clone(),
                    resolution,
                },
            }),
            _ => Err(TransitionRefusal::NotIndeterminate),
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Committed { .. }
                | Self::DispatchRefused { .. }
                | Self::CommittedViaRecovery { .. }
                | Self::ProvenNotCommitted { .. }
        )
    }

    /// The one dispatch identity, if the attempt ever dispatched.
    pub fn dispatch_id(&self) -> Option<DispatchId> {
        match self {
            Self::Prepared | Self::Ratified { .. } | Self::Reserved { .. } => None,
            Self::Dispatching { dispatch, .. }
            | Self::Committed { dispatch, .. }
            | Self::DispatchRefused { dispatch, .. }
            | Self::Indeterminate { dispatch, .. }
            | Self::CommittedViaRecovery { dispatch, .. }
            | Self::ProvenNotCommitted { dispatch, .. } => Some(dispatch.dispatch),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::*;

    fn rat() -> RatificationRef {
        RatificationRef {
            ratification: RatificationId::from_bytes([1; 16]),
            prepared_attempt_digest: Sha256Digest::of_bytes(b"attempt"),
            standing_use: StandingUseId::from_bytes([2; 16]),
        }
    }

    fn rsv() -> ReservationRef {
        ReservationRef {
            reservation: ReservationId::from_bytes([3; 16]),
            reservation_use: ReservationUseId::from_bytes([4; 16]),
        }
    }

    fn dsp() -> DispatchRef {
        DispatchRef {
            dispatch: DispatchId::from_bytes([5; 16]),
        }
    }

    fn res() -> RecoveryResolutionRef {
        RecoveryResolutionRef {
            resolution: RecoveryResolutionId::from_bytes([6; 16]),
        }
    }

    #[test]
    fn dispatch_before_ratification_is_impossible() {
        let s = AttemptState::Prepared;
        assert_eq!(s.dispatch(dsp()), Err(TransitionRefusal::NotReserved));
        assert_eq!(
            s,
            AttemptState::Prepared,
            "invalid transition must not mutate"
        );
    }

    #[test]
    fn dispatch_before_reservation_is_impossible() {
        let s = AttemptState::Prepared.ratify(rat()).unwrap();
        assert_eq!(s.dispatch(dsp()), Err(TransitionRefusal::NotReserved));
    }

    #[test]
    fn only_one_dispatch_may_exist() {
        let s = AttemptState::Prepared
            .ratify(rat())
            .unwrap()
            .reserve(rsv())
            .unwrap()
            .dispatch(dsp())
            .unwrap();
        assert_eq!(
            s.dispatch(DispatchRef {
                dispatch: DispatchId::from_bytes([9; 16])
            }),
            Err(TransitionRefusal::AlreadyDispatched)
        );
        let committed = s.commit().unwrap();
        assert_eq!(
            committed.dispatch(dsp()),
            Err(TransitionRefusal::AlreadyDispatched)
        );
    }

    #[test]
    fn indeterminate_cannot_become_success_or_failure_directly() {
        let s = AttemptState::Prepared
            .ratify(rat())
            .unwrap()
            .reserve(rsv())
            .unwrap()
            .dispatch(dsp())
            .unwrap()
            .mark_indeterminate()
            .unwrap();
        // No commit, no refusal from indeterminacy — only resolution.
        assert_eq!(s.commit(), Err(TransitionRefusal::NotDispatching));
        assert_eq!(
            s.refuse_dispatch(crate::refusal::DispatchRefusalGround::BasisMoved),
            Err(TransitionRefusal::NotDispatching)
        );
        let resolved = s
            .resolve(res(), RecoveryVerdict::ProvenNotCommitted)
            .unwrap();
        assert!(matches!(resolved, AttemptState::ProvenNotCommitted { .. }));
        // DispatchRefused and ProvenNotCommitted remain distinct variants.
        assert!(!matches!(resolved, AttemptState::DispatchRefused { .. }));
    }

    #[test]
    fn invalid_transitions_do_not_mutate_state() {
        let s = AttemptState::Prepared
            .ratify(rat())
            .unwrap()
            .reserve(rsv())
            .unwrap();
        let before = s.clone();
        assert!(s.commit().is_err());
        assert!(s.mark_indeterminate().is_err());
        assert!(s
            .resolve(res(), RecoveryVerdict::CommittedViaRecovery)
            .is_err());
        assert_eq!(s, before);
    }

    #[test]
    fn terminal_states_are_terminal() {
        let s = AttemptState::Prepared
            .ratify(rat())
            .unwrap()
            .reserve(rsv())
            .unwrap()
            .dispatch(dsp())
            .unwrap()
            .commit()
            .unwrap();
        assert!(s.is_terminal());
        assert!(s.ratify(rat()).is_err());
        assert!(s.reserve(rsv()).is_err());
        assert!(s.commit().is_err());
        assert!(s
            .resolve(res(), RecoveryVerdict::CommittedViaRecovery)
            .is_err());
    }
}
