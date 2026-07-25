# Conformance re-audit — second blind pass

Blind re-audit of the patched tree (2026-07-25), performed against the claimed invariants
rather than the patch diff. Supersedes section 3 of [`conformance-v0.md`](conformance-v0.md).

Method: every row was traced to its actual enforcing mechanism, classified, and given an
attempted counterexample. Every previously recorded witness was re-run. Witnesses were
written in a crate outside this repository consuming only the public APIs of `gwr-core`,
`gwr-runtime`, and `gwr-local`, plus end-to-end runs of the real `docket` CLI.

## Gate commands

| command | exit |
|---|---|
| `cargo fmt --check` | 0 |
| `cargo clippy --workspace --all-targets -- -D warnings` | 0 |
| `cargo test --workspace` | 0 — 125 tests |
| `cargo test --workspace --release` | 0 — 125 tests |

Clippy is re-run after `touch crates/*/src/lib.rs`: a cached invocation returns in
hundredths of a second and proves nothing. The release run exists because a defect was
found whose behaviour differed between profiles (N-2, below).

## Classification

`checked` means a normal runtime path validates the condition and returns a typed
negative. `type-level` means the illegal state is unrepresentable or unreachable by
construction.

| # | tag | class | mechanism, and what the counterexample did |
|---|---|---|---|
| 1 | proved | checked | Dispatch requires a projected `Reserved` attempt; the store now validates the successor relation. Direct broker-binary use remains possible and confers no authority the same UID lacks (`trust-model.md` §1) |
| 2 | proved | checked | `AlreadyDispatched` at service and lifecycle; broker inspects an existing journal. Four racing dispatches → one commitment |
| 3 | impl-choice | type-level | `dispatch.attempt UNIQUE`; one `DispatchRef` per state. Four racers → one journal |
| 4 | impl-choice | checked | Existing journal inspected, never re-executed; re-entry re-presents the persisted envelope |
| 5 | proved | checked | `DispatchIdentityConflict`; UNIQUE constraint; `AlreadyDispatched` |
| 6 | proved † | checked | `commit`/`refuse_dispatch` accept only `Dispatching`; `Indeterminate` exits only via `resolve`; **store successor table closes the former bypass** — `prepared→committed` and `prepared→indeterminate` both refused `IllegalTransition`. *Was: looser than specified* |
| 7 | proved | checked | Persisted-dispatch check; incomplete journal → `Uncertain` without execution |
| 8 | proved † | checked | `AuthoritativeBinding` + `validate_fact_binding` compare nine fields; the verdict is derived from the runtime's record; the journal is verified against the digest recorded at indeterminacy before it is read. Invented result fields, an edited journal, a deleted journal, and each of eight foreign context fields were all refused with distinct typed refusals. *Was: looser than specified — journal digest and expected result unverified* |
| 9 | proved | checked | Attempt/dispatch mismatch typed; commitment-ledger attribution → `CommitAttributedElsewhere` |
| 10 | doctrine | type-level | `RecoveryFact` has no transition operation; fact recording and resolution are separate store methods |
| 11 | doctrine | checked | Bridge requires `ResolveRecovery` scope and validates actor, repository, digest, expiry, use. `Ratify` standing refused `StandingInsufficient` |
| 12 | proved | checked | Consumed grants refuse; atomic `consumed_by IS NULL`. Four concurrent ratifications → exactly one succeeded |
| 13 | proved | checked | Consumed claims refuse; atomic projection consumption. Three racers → `AlreadyConsumed` |
| 14 | proved | checked | Presented digest, basis, and scope checked against the admitted attempt |
| 15 | proved | checked | `ImmutableRebind`; content-addressed artifacts; broker rechecks patch bytes |
| 16 | proved | checked | Versioned transcript over basis, artifact, effect, plan |
| 17 | doctrine | type-level | Three narrow receipt types; no correctness, completion, merge-safety, discharge, hazard, confidence, or severity field exists to set |
| 18 | proved | type-level | Observations are absent from `AttemptState`; separate records with no transition |
| 19 | proved | checked | One claim admitted, five refused in an **exhaustive match with no catch-all** — a new `Claim` variant fails to compile rather than defaulting to admitted. Minor ordering issue: N-4 |
| 20 | proved | type-level | Four concrete bridge modules; no registry, blanket conversion, or universal judgment type |
| 21 | proved | type-level (types) / looser (values) | Separate refusal enums, no cross-domain conversions. Persisted reliance refusals retain only attempt, kind, detail, time: N-5 |
| 22 | proved | type-level | Consumer fixed by the named bridge; sources `&`-borrowed; separate narrow output |
| 23 | doctrine | type-level | Neutral provider trait; no provider-identity type in core and **no provider column in any migration** |
| 24 | doctrine | type-level | `ToolRequest` is text only; `BoundedAssignment` carries no standing, reservation, dispatch identity, or credential. Within the v0.1.0 same-UID scope ruling |
| 25 | doctrine | **tested-only** | Private fields on `StandingGrant`/`ReservationClaim` with validated constructors; clone-and-widen does not typecheck; non-revival asserted directly in `domain::standing::tests`. Residual: N-6. *Was: unenforced — this was the sole freeze blocker* |
| 26 | impl-choice | checked | Services obtain `Clock::now` and pass it into core expiry checks. Backward clock readings: `trust-model.md` §3 |
| 27 | proved | checked | Per-transition predecessor checks in the lifecycle **and** `transition_permitted` in the store. Three illegal transitions refused, projection and version untouched. *Was: looser than specified* |
| 28 | proved † | type-level | Distinct variants from distinct predecessors; distinct ledger tables and projection tags |
| 29 | proved | checked | `HumanReviewBeforeMerge` created and retained; no discharge variant exists. Reconciliation remains optional and can precede completion |
| 30 | doctrine | tested-only | `NoBridge` exists and unsupported versions are checked per bridge, but no runtime API produces it for an undeclared crossing. Unchanged; operator-ruled as a documented protocol obligation |

† Rows 6, 8, and 28 hold relative to the exclusive-ref-custody premise. See
[`invariants-v0.md` § Custody premise](invariants-v0.md) and
[`trust-model.md`](trust-model.md) §2.

## Verdict

**The classification gate passes.** Every `proved` row is `checked` or `type-level`. Rows
25 and 30 are `tested-only`, the minimum their `doctrine-unproved` tag requires. Row 25 —
the sole blocker of the first audit — is closed.

No accepted execution applied an unadmitted effect, bypassed authority, or lost an
acknowledged effect outside recoverable settlement.

## Findings of the second pass

Three were fixed before the freeze; the rest are recorded as post-v0.1.0 work in
[`open-defects.md`](open-defects.md).

| id | finding | disposition |
|---|---|---|
| N-1 | `ProvenNotCommitted` unsound under external mutation of the target ref; the premise was documented nowhere | **fixed** — premise made explicit and required: `ExclusiveRefCustody` field, `trust-model.md`, invariant-table note, verdict and API docs, boundary specimen |
| N-2 | Standing-token MAC tags non-canonical: panic in debug, accepted in release | **fixed** — strict lowercase hex, whole-token canonical re-encode check in every profile, `debug_assert` removed as a correctness mechanism |
| N-3 | `observe()` panicked on an empty observation plan, permanently stranding a committed attempt | **fixed** — typed `EmptyObservationPlan` refusal before anything runs; empty plans refused at admission |
| N-4 | `ObservationFailed` returned before the claim check | open, recorded |
| N-5 | Persisted reliance refusals lose observation, consumer, claim | open, recorded |
| N-6 | `from_persisted` is a public value-level mint; no service path reaches it | open, recorded |
| N-7 | `split_list` accepts non-canonical encodings; stored `prepared_digest` never compared on read | open, recorded |
| N-8 | Broker envelope unauthenticated and under-parsed | not a defect — the broker is not a privilege boundary (`trust-model.md` §1) |
