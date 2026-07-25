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

impl DispatchRefusalGround {
    /// The one tag vocabulary, shared by the store encoding and every read
    /// surface.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::BasisMoved => "basis_moved",
            Self::ForbiddenPath => "forbidden_path",
            Self::InvalidPatch => "invalid_patch",
            Self::EnvelopeMismatch => "envelope_mismatch",
        }
    }

    pub fn from_tag(tag: &str) -> Option<Self> {
        Some(match tag {
            "basis_moved" => Self::BasisMoved,
            "forbidden_path" => Self::ForbiddenPath,
            "invalid_patch" => Self::InvalidPatch,
            "envelope_mismatch" => Self::EnvelopeMismatch,
            _ => return None,
        })
    }
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

impl RelianceRefusal {
    /// Stable kind tag plus optional detail, shared by the store encoding and
    /// every read surface.
    pub fn tags(&self) -> (&'static str, Option<String>) {
        match self {
            Self::NoBridge => ("no_bridge", None),
            Self::BridgeVersionUnsupported { presented } => {
                ("bridge_version_unsupported", Some(presented.to_string()))
            }
            Self::ClaimNotAdmissible => ("claim_not_admissible", None),
            Self::OutOfScope => ("out_of_scope", None),
            Self::Observation(ObservationRefusal::ScopeMismatch) => {
                ("observation_scope_mismatch", None)
            }
            Self::Observation(ObservationRefusal::ObservationFailed) => {
                ("observation_failed", None)
            }
        }
    }

    pub fn from_tags(kind: &str, detail: Option<&str>) -> Option<Self> {
        Some(match kind {
            "no_bridge" => Self::NoBridge,
            "bridge_version_unsupported" => Self::BridgeVersionUnsupported {
                presented: detail?.parse().ok()?,
            },
            "claim_not_admissible" => Self::ClaimNotAdmissible,
            "out_of_scope" => Self::OutOfScope,
            "observation_scope_mismatch" => Self::Observation(ObservationRefusal::ScopeMismatch),
            "observation_failed" => Self::Observation(ObservationRefusal::ObservationFailed),
            _ => return None,
        })
    }
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
    /// The fact names a different repository than the attempt it would resolve.
    RepositoryMismatch,
    /// The fact names a different target ref than the attempt's effect.
    TargetRefMismatch,
    /// The fact names a different basis than the attempt was specified against.
    BasisMismatch,
    /// The fact's journal digest is not the one recorded when this dispatch
    /// became indeterminate: the journal it describes is not the journal the
    /// runtime saw.
    JournalDigestMismatch,
    /// The fact's observed ref disagrees with what the runtime read.
    ObservedRefMismatch,
    /// The fact's expected result disagrees with the digest-verified journal.
    ExpectedResultMismatch,
    /// The observed commit is already attributed to a different attempt, so it
    /// cannot settle this one.
    CommitAttributedElsewhere,
    StandingInsufficient,
    StandingExpired,
    StandingAlreadyUsed,
    /// Conflicting evidence resolves nothing; the attempt remains indeterminate.
    ConflictingEvidence,
}
