# Open defects and operator classifications

Findings from the Task 12 conformance audit (`conformance-v0.md`, fresh codex session,
2026-07-24) with the operator's ruling on each. Recorded here so the freeze gate has a
single place to check.

## Closed

### Invariant 8 — recovery facts bind the exact attempt and dispatch (`proved`)

**Was:** blocking correctness defect. `validate_fact_binding` compared only attempt,
dispatch, and prepared-attempt digest; `establishes()` compared the observed ref against
the fact's *own* `basis` field. The recovery artifact therefore carried both the
proposition and the comparison baseline, so validation degenerated into "does this
document agree with itself?" A fact naming the correct attempt, dispatch, and digest but a
foreign repository, ref, and basis was accepted and drove a false `ProvenNotCommitted`.

**Fixed 2026-07-24.** `AuthoritativeBinding` now carries the admitted attempt's own fields
plus the persisted dispatch identity; `validate_fact_binding` compares every semantically
binding field against it (new typed refusals `RepositoryMismatch`, `TargetRefMismatch`,
`BasisMismatch`), and `establishes()` takes the authoritative basis rather than the fact's
copy. `RecoveryStandingToResolutionV1` takes `&PreparedAttempt` instead of loose copies,
so checking a fact against anything but the real attempt is structurally impossible.
Regression suite: `crates/gwr-core/tests/recovery_binding.rs` — the audit witness
unchanged in construction (now refused), per-field independence, both positive verdicts,
and the degenerate result-equals-basis case.

## Open — operator-classified, not yet actioned

### Store prior/next validation — architectural exposure defect

`Store::record_*` methods accept a caller-supplied `AttemptState` and validate only the
optimistic version, never the prior/next pair. Lifecycle law is enforced in the service
path over a structurally permissive substrate. Operator ruling: *acceptable only if `Store`
is explicitly an internal trusted port that cannot be implemented or called by untrusted
code; if it is public extension surface, the invariant claims are overstated.* Choose one:
harden (validate the transition inside the store) or narrow the claims and the visibility.

Affects conformance rows 1, 2, 5, 6, 14, 16, 27, 29 ("checked but looser") and 11.

### Clone-and-extend on core domain values — authority-leak shape

`StandingGrant` and `ReservationClaim` have public fields, so a caller using a bridge
directly can clone an expired value, extend `expires_at`, and present it as valid; only
the persisted store path prevents that revival (conformance row 25). Operator ruling: same
authority-leak shape as the store issue; **likely requires constructor/privacy hardening
rather than more bridge checks.**

### N3 / invariant 30 — missing-bridge refusal is a protocol obligation

`RelianceRefusal::NoBridge` exists and unsupported *versions* are checked by each bridge,
but no runtime API accepts an undeclared crossing and produces the refusal; callers
construct it by convention (conformance row 30, `tested-only`). Operator ruling: **not
enforced; document as a protocol obligation unless you choose to encode it.** Documented
here.

## Freeze gate

Task 13 remains blocked until Task 12 is re-run against the patched tree and shows no
`proved`-tagged invariant classified `tested-only` or `unenforced`.
