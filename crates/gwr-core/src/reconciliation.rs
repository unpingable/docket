//! Reconciliation and residual obligations.
//!
//! Something can still be owed after the mechanical transition succeeded.
//! Residual obligations are not failures and not warnings; they remain visible
//! after commitment and after passing observation, and nothing in the low-level
//! path discharges them. Whether an obligation is discharged is a domain
//! judgment this runtime never makes.

use crate::ids::{AttemptId, ObligationId};
use crate::work_request::ClockReading;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ObligationKind {
    /// The v0 instance: a human must review before any merge, regardless of
    /// commitment and observation results.
    HumanReviewBeforeMerge,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ResidualObligation {
    pub id: ObligationId,
    pub attempt: AttemptId,
    pub kind: ObligationKind,
    pub recorded_at: ClockReading,
}

/// The closing account for an attempt: what mechanical work concluded and what
/// remains owed. Reconciliation retains obligations; it never discharges them.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Reconciliation {
    pub attempt: AttemptId,
    pub retained_obligations: Vec<ObligationId>,
    pub reconciled_at: ClockReading,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{AttemptId, ObligationId};

    #[test]
    fn reconciliation_retains_rather_than_discharges() {
        let ob = ResidualObligation {
            id: ObligationId::from_bytes([1; 16]),
            attempt: AttemptId::from_bytes([2; 16]),
            kind: ObligationKind::HumanReviewBeforeMerge,
            recorded_at: ClockReading(10),
        };
        let rec = Reconciliation {
            attempt: ob.attempt,
            retained_obligations: vec![ob.id],
            reconciled_at: ClockReading(20),
        };
        // The obligation survives reconciliation; there is no discharge API.
        assert_eq!(rec.retained_obligations, vec![ob.id]);
    }
}
