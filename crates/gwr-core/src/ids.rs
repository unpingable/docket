//! Opaque typed identities.
//!
//! Identity is distinct from content: two records with byte-identical content and
//! different identities are different governed objects. The runtime's adapters
//! generate identity bytes; this crate only holds and compares them.

use std::fmt;

macro_rules! define_id {
    ($(#[$doc:meta])* $name:ident, $prefix:literal) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name([u8; 16]);

        impl $name {
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}-", $prefix)?;
                for b in self.0 {
                    write!(f, "{b:02x}")?;
                }
                Ok(())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{self}")
            }
        }
    };
}

define_id!(
    /// The requested work. Retryable and vague; never describes an exact effect.
    WorkRequestId,
    "wrq"
);
define_id!(
    /// One bounded provider invocation. A replacement provider gets a new one.
    PreparationRunId,
    "prep"
);
define_id!(
    /// An immutable candidate artifact as ingested (content addressed separately).
    CandidateArtifactId,
    "cand"
);
define_id!(
    /// An exact attempt: minted only at candidate admission, when repository,
    /// basis, artifact digest, effect specification, and observation plan are all
    /// fixed. Never reused; a retry is a different attempt.
    AttemptId,
    "att"
);
define_id!(RatificationId, "rat");
define_id!(StandingGrantId, "stg");
define_id!(StandingUseId, "stu");
define_id!(ReservationId, "rsv");
define_id!(ReservationUseId, "rsu");
define_id!(
    /// Exactly one per attempt, ever.
    DispatchId,
    "dsp"
);
define_id!(ObservationId, "obs");
define_id!(RecoveryFactId, "rcf");
define_id!(RecoveryResolutionId, "rcr");
define_id!(ObligationId, "obl");
define_id!(ActorId, "act");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_differs_from_content() {
        // Same bytes under different identity types are different values entirely
        // (they do not even share a type); same type with different bytes differ.
        let a = AttemptId::from_bytes([1; 16]);
        let b = AttemptId::from_bytes([2; 16]);
        assert_ne!(a, b);
        let c = AttemptId::from_bytes([1; 16]);
        assert_eq!(a, c);
        assert_eq!(a.to_string(), "att-01010101010101010101010101010101");
    }
}
