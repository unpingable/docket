# Greenfield known gaps

What `gwr-greenfield-v0.1` does not do, recorded so that no reader mistakes silence for a
guarantee. Nothing here blocks the freeze; everything here is a deliberate v0.1.0
boundary.

## Environment premises, not enforcement

| gap | consequence if violated | where stated |
|---|---|---|
| Exclusive broker custody of the target ref | `ProvenNotCommitted` establishes only "not presently reflected in the ref", not non-occurrence | [`trust-model.md`](trust-model.md) §2; `ExclusiveRefCustody`; `tests/ref_custody_boundary.rs` |
| Same-UID trust of provider and broker | A provider can read the state directory by absolute path; the broker binary can be invoked directly | [`trust-model.md`](trust-model.md) §1 |
| Monotone clock readings | A backward reading revives an otherwise-expired record | [`trust-model.md`](trust-model.md) §3; invariant 26 |

The first two are deployment boundaries — real ref mediation and provider confinement
(separate UID, mount namespace, or container, plus binding the provider executable's
identity). Neither is implementable from inside this process.

## Non-enforcement inside stated scope

- **Missing-bridge crossings (invariant 30, `tested-only`).** `RelianceRefusal::NoBridge`
  exists and unsupported bridge *versions* are genuinely checked, but no runtime API
  accepts an undeclared source/consumer/claim crossing and produces the refusal. Callers
  select it by convention. Operator-ruled as a documented protocol obligation.
- **Reliance refusal detail (N-5).** Persisted refusals retain attempt, kind, detail, and
  time only. The observation, consumer, and claim are dropped, so a stored refusal cannot
  say what was refused for whom.
- **Claim-check ordering (N-4).** A failed observation short-circuits before the claim
  match, so an inadmissible claim returns `ObservationFailed` — implying it would have
  been admissible had the command passed.
- **Value-level authority mints (N-6).** `StandingGrant::from_persisted` and
  `ReservationClaim::from_persisted` are public. No service path reaches them; every
  service loads grants from the store by identity.
- **Non-canonical list decoding (N-7).** `split_list` drops trailing bytes after the last
  well-formed element. The attempt digest is recomputed from the decoded value so no
  semantic drift is possible, but the stored `prepared_digest` column is never compared on
  read, so database-level corruption is not detected there.
- **Reconciliation is not forced.** Commitment does not create the residual obligation;
  `reconcile` can be skipped, or invoked before completion.
- **Broker envelope (N-8).** Unauthenticated and under-parsed — `attempt` and
  `prepared_digest` are written but never read back, and missing fields default to empty.
  Not a privilege boundary, so not charged as a defect.

## Scope exclusions

Everything in [`non-goals.md`](non-goals.md) remains excluded, including the nine proved
negatives. Nothing in this freeze reaches for one.

## Not attempted

- Distributed operation, multi-tenancy, remote attestation, federated identity.
- Any effect other than the atomic Git target-ref transition.
- Semantic correctness, merge safety, obligation discharge, domain closure — excluded by
  the packet, and the receipt types carry no field that could assert them.
- Comparison with prior implementations. Locked to Task 14, which requires a separate
  operator instruction naming exact paths. **No such comparison informed this result**;
  that isolation is the entire basis of the Task 14 deliverable.
