//! Typed, domain-narrow refusals.
//!
//! Refusals are evidence, not errors: things the system correctly declined, each
//! carrying what was refused, on what ground, within which domain. There is
//! deliberately no shared refusal trait, no unified refusal type, and no
//! conversion between refusal domains — a unifier is the failure this design
//! exists to prevent.

use crate::ids::{AttemptId, DispatchId};

/// Refusals from validating standing at the ratification bridge.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StandingRefusal {
    IntegrityFailure,
    ScopeMismatch,
    Expired,
    AlreadyUsed,
}

/// Refusals from ratification itself.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RatificationRefusal {
    DigestMismatch,
    BasisMismatch,
    Standing(StandingRefusal),
}

/// Refusals from reservation and its use at dispatch.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReservationRefusal {
    Conflict,
    Expired,
    AlreadyUsed,
    AttemptMismatch,
    RatificationMissing,
    /// A second dispatch identity was presented for the same attempt.
    DispatchIdentityConflict,
}

/// Grounds on which the broker definitively refused the effect. A refusal here
/// means the ref update did not occur — distinct forever from indeterminacy and
/// from a later `ProvenNotCommitted`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DispatchRefusalGround {
    BasisMoved,
    ForbiddenPath,
    InvalidPatch,
    EnvelopeMismatch,
}

/// Refusals of pure lifecycle transitions. An invalid transition mutates nothing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TransitionRefusal {
    NotPrepared,
    NotRatified,
    NotReserved,
    NotDispatching,
    NotIndeterminate,
    AlreadyDispatched,
    AlreadyTerminal,
    /// The presented reservation use does not belong to the reserved claim.
    ReservationMismatch,
}

/// Refusals from the observation admission path.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ObservationRefusal {
    /// The observation ran against a different commit than the effect produced.
    ScopeMismatch,
    /// The named command did not exit successfully; it admits nothing.
    ObservationFailed,
}

/// Consumer-side reliance refusals. First-class: the absence of a bridge, or an
/// inadmissible claim, produces one of these — never a default, a fallback, or a
/// pass-through. A reliance refusal does not mutate its source record.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RelianceRefusal {
    /// No bridge exists for this source, consumer, and claim.
    NoBridge,
    /// The bridge exists but not at the presented version. No fallback.
    BridgeVersionUnsupported {
        presented: u32,
    },
    /// The claim is one this bridge refuses to transport (e.g. correctness,
    /// completion, merge safety, discharge, closure).
    ClaimNotAdmissible,
    /// The source record is outside the scope the bridge transports.
    OutOfScope,
    Observation(ObservationRefusal),
}

/// Refusals from recovery resolution.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecoveryRefusal {
    AttemptMismatch {
        fact_names: AttemptId,
        resolving: AttemptId,
    },
    DispatchMismatch {
        fact_names: DispatchId,
        resolving: DispatchId,
    },
    BindingIncomplete,
    StandingInsufficient,
    StandingExpired,
    StandingAlreadyUsed,
    /// Conflicting evidence resolves nothing; the attempt remains indeterminate.
    ConflictingEvidence,
}
