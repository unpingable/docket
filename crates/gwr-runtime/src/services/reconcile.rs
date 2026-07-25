//! Reconciliation: the closing account. Retains residual obligations; never
//! discharges them. `HumanReviewBeforeMerge` survives effect commitment and
//! passing observation — nothing in the low-level path removes it.

use crate::ports::adapters::{Clock, IdSource};
use crate::ports::store::{Store, StoreError};
use gwr_core::ids::{AttemptId, ObligationId};
use gwr_core::reconciliation::{ObligationKind, Reconciliation, ResidualObligation};

/// Reconcile an attempt: ensure the v0 residual obligation exists, then record
/// a reconciliation retaining every obligation on file.
pub fn reconcile(
    store: &mut dyn Store,
    attempt_id: AttemptId,
    clock: &dyn Clock,
    ids: &mut dyn IdSource,
) -> Result<Reconciliation, StoreError> {
    let now = clock.now();
    let existing = store.get_residual_obligations(attempt_id)?;
    let obligations = if existing.is_empty() {
        let ob = ResidualObligation {
            id: ObligationId::from_bytes(ids.fresh16()),
            attempt: attempt_id,
            kind: ObligationKind::HumanReviewBeforeMerge,
            recorded_at: now,
        };
        store.create_residual_obligation(&ob)?;
        vec![ob]
    } else {
        existing
    };
    let reconciliation = Reconciliation {
        attempt: attempt_id,
        retained_obligations: obligations.iter().map(|o| o.id).collect(),
        reconciled_at: now,
    };
    store.record_reconciliation(&reconciliation)?;
    Ok(reconciliation)
}
