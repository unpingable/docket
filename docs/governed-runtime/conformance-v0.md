# Governed Runtime v0 Conformance Audit

## 1 — Enforcement table

The classifications below describe the code that exists, including its public seams, not
the architecture documents' intended behavior. “Checked” means there is a normal runtime
path that validates the condition and returns a typed negative result. A “looser” finding
records any material bypass or missing part even when that normal path is checked.

| invariant | provenance tag | enforced where (file + mechanism) | enforcement kind | finding |
|---|---|---|---|---|
| 1. No effect without an admitted exact attempt | proved | `crates/gwr-runtime/src/services/dispatch.rs`: `dispatch` must load a projected attempt and reach `Reserved`; `crates/gwr-core/src/lifecycle.rs`: `AttemptState::dispatch` returns `NotReserved`; `crates/gwr-local/src/store/mod.rs`: admitted attempts start at `Prepared` | checked | looser than specified — `DispatchEnvelope` has public fields, `EffectBroker::execute` is public, and the broker binary accepts an envelope file without proving that the envelope or attempt was persisted; the public `Store::record_*` port also accepts caller-supplied next states |
| 2. No retry under the same `AttemptId` | proved | `crates/gwr-runtime/src/services/dispatch.rs`: an existing attempt dispatch returns `AlreadyDispatched`; `crates/gwr-core/src/lifecycle.rs`: every post-`Reserved` dispatch returns `AlreadyDispatched`; `crates/gwr-local/src/broker/mod.rs`: an existing journal is inspected | checked | looser than specified — the governed service path cannot retry, but direct use of the public broker with a newly fabricated envelope and journal location is outside that check |
| 3. One persisted `DispatchId` per attempt | implementation-choice | `crates/gwr-local/migrations/0001_init.sql`: `dispatch.attempt` is `UNIQUE`; `crates/gwr-core/src/lifecycle.rs`: every dispatched state contains exactly one `DispatchRef` | type-level | conformant |
| 4. Same `DispatchId` inspects rather than repeats | implementation-choice | `crates/gwr-local/src/broker/mod.rs` and `crates/gwr-local/src/bin/gwr-git-broker.rs`: an existing per-dispatch journal is inspected and an incomplete journal returns uncertainty; `crates/gwr-runtime/src/services/dispatch.rs`: a persisted dispatch returns its projected state | checked | conformant |
| 5. Different `DispatchId` for the same attempt is refused | proved | `crates/gwr-core/src/bridge/reservation_to_dispatch.rs`: `existing_dispatch` mismatch returns `DispatchIdentityConflict`; `crates/gwr-local/migrations/0001_init.sql`: unique attempt in `dispatch`; `crates/gwr-core/src/lifecycle.rs`: later dispatch returns `AlreadyDispatched` | checked | conformant |
| 6. No success or failure minted from indeterminacy | proved | `crates/gwr-core/src/lifecycle.rs`: `commit` and `refuse_dispatch` accept only `Dispatching`; `Indeterminate` exits only through `resolve`, otherwise returning typed `TransitionRefusal`; `crates/gwr-runtime/src/services/recovery.rs` uses that path | checked | looser than specified — the public store transition methods validate only optimistic version, so a caller can supply a `Committed` or `DispatchRefused` next projection after `Indeterminate` without the lifecycle check |
| 7. No automatic retry after ambiguous dispatch | proved | `crates/gwr-runtime/src/services/dispatch.rs`: the persisted dispatch check returns `AlreadyDispatched`, including for `Indeterminate`; `crates/gwr-local/src/broker/mod.rs`: incomplete existing journal returns `Uncertain` without execution | checked | looser than specified — direct broker use is not tied to the persisted attempt projection and can evade the service-level no-retry check |
| 8. Recovery facts bind exact attempt and dispatch | proved | `crates/gwr-core/src/recovery.rs`: `AuthoritativeBinding` plus `validate_fact_binding` compares attempt, dispatch, prepared digest, repository, target ref, and basis and returns typed mismatch refusals; `crates/gwr-core/src/bridge/recovery_standing_to_resolution.rs` derives the binding from the admitted attempt and persisted dispatch | checked | looser than specified — authenticity is not represented in the input type, and neither the fact's journal digest nor its claimed expected result commit is checked against a persisted broker journal; `Store::record_recovery_fact` accepts caller-constructed facts, so a correctly contextualized but self-authored expected result can drive a verdict |
| 9. Recovery facts cannot resolve another attempt | proved | `crates/gwr-core/src/recovery.rs`: attempt, digest, repository, ref, basis, and dispatch mismatches are typed refusals; `crates/gwr-runtime/src/services/recovery.rs`: resolution supplies the target attempt and its persisted dispatch | checked | looser than specified — the checked recovery service refuses cross-attempt use, but the public `Store::record_recovery_resolution` method can persist a caller-supplied resolution and next state without validating their relation to the prior projection |
| 10. Authentic recovery evidence does not apply itself | doctrine-unproved | `crates/gwr-local/src/recover.rs`: `produce_fact` only records a `RecoveryFact`; `crates/gwr-runtime/src/ports/store.rs` separates `record_recovery_fact` from resolution; `crates/gwr-core/src/recovery.rs` gives `RecoveryFact` no state-transition operation | type-level | conformant |
| 11. Recovery requires separately valid resolution standing | doctrine-unproved | `crates/gwr-core/src/bridge/recovery_standing_to_resolution.rs`: requires a `StandingGrant` scoped to `ResolveRecovery`, validates actor, repository, digest, expiry and use, and returns typed recovery-standing refusals; the runtime service persists its consumption atomically | checked | looser than specified — the public store port can record a recovery resolution directly, bypassing the bridge and its separate-standing check |
| 12. No standing use is replayed | proved | `crates/gwr-core/src/domain/standing.rs`: consumed grants return `AlreadyUsed`; `crates/gwr-local/src/store/mod.rs`: atomic `consumed_by IS NULL` update returns `AlreadyConsumed`; ratification and recovery persist the use in the same transaction | checked | conformant |
| 13. No resource reservation is replayed | proved | `crates/gwr-core/src/domain/reservation.rs`: consumed claims return `AlreadyUsed`; `crates/gwr-local/src/store/mod.rs`: atomic reservation projection consumption returns `AlreadyConsumed`; `crates/gwr-runtime/src/services/dispatch.rs` consumes once before broker execution | checked | conformant |
| 14. Ratification binds the exact prepared-attempt digest | proved | `crates/gwr-core/src/bridge/standing_to_ratification.rs`: presented digest, basis, and standing scope are checked against `PreparedAttempt`, with typed refusals; `RatificationReceipt` records the digest | checked | looser than specified — the bridge enforces the binding, but `RatificationRef`, `RatificationReceipt`, and the public store recording method are constructible/callable without that bridge and the store does not revalidate the receipt against the admitted attempt |
| 15. Candidate content is immutable after admission | proved | `crates/gwr-local/src/store/mod.rs`: candidate and attempt inserts reject identity rebinding with `ImmutableRebind`; `crates/gwr-local/src/adapters.rs`: artifacts are content-addressed and verified on read; the broker rechecks patch bytes against the admitted digest | checked | conformant |
| 16. Changing basis, patch, effect, or plan requires another attempt | proved | `crates/gwr-core/src/prepared_attempt.rs` and `effect_spec.rs`: the versioned prepared-attempt digest transcribes basis, artifact digest, full effect, and observation plan; `crates/gwr-local/src/store/mod.rs`: reusing an admitted `AttemptId` with changed content returns `ImmutableRebind` | checked | conformant |
| 17. No receipt asserts more than the trusted component established | doctrine-unproved | `crates/gwr-core/src/receipt.rs`: three narrow receipt types have no correctness, completion, merge-safety, discharge, hazard, confidence, or severity fields; recovery and outcome records are separate types; `crates/gwr-core/src/bridge/observation_to_review_queue.rs` can construct only the one narrow admission | type-level | conformant |
| 18. Effect commitment is distinct from observation success | proved | `crates/gwr-core/src/lifecycle.rs` and `outcome.rs`: commitment is an execution state/record while observations are absent from the state enum; `crates/gwr-core/src/observation_plan.rs`: observations are separate associated records with no lifecycle transition | type-level | conformant |
| 19. Observation success is distinct from correctness, completion, merge safety, and discharge | proved | `crates/gwr-core/src/domain/evidence.rs`: these are separate `Claim` variants; `crates/gwr-core/src/bridge/observation_to_review_queue.rs`: all five broader claims return `ClaimNotAdmissible`; `ReviewQueueAdmission` has no field for them | checked | conformant |
| 20. No silent lift between domains | proved | `crates/gwr-core/src/bridge/`: four source/target-specific modules with distinct inputs, outputs, and refusals; no bridge registry, blanket conversion, universal judgment type, or generic evaluator exists | type-level | conformant |
| 21. Refusals remain domain-narrow | proved | `crates/gwr-core/src/refusal.rs`: standing, reservation, transition, observation, reliance, recovery, and dispatch grounds are distinct enums with no shared refusal trait or cross-domain conversions | type-level | looser than specified — the types preserve the domain, but most values do not carry the exact refused subject/scope; notably persisted reliance refusals omit observation, consumer, and claim, retaining only attempt, kind, optional detail, and time |
| 22. Consumer-specific reliance does not mutate or broaden the source receipt or refusal | proved | `crates/gwr-core/src/bridge/observation_to_review_queue.rs`: the consumer is fixed by the named bridge, the claim is explicit, sources are borrowed, and output is a separate narrow type; `crates/gwr-runtime/src/services/reliance.rs` records a separate admission/refusal | type-level | conformant |
| 23. Provider identity absent from core lifecycle types and schemas | doctrine-unproved | `crates/gwr-runtime/src/ports/labor_provider.rs`: provider implementation is behind a neutral trait; `crates/gwr-core` has no provider-identity type or field; `crates/gwr-local/migrations/0001_init.sql` has no provider-identity column; persistence and provider-contract tests scan this boundary | type-level | conformant |
| 24. Provider tool requests carry no authority | doctrine-unproved | `crates/gwr-runtime/src/ports/labor_provider.rs`: `ToolRequest` contains only untrusted text and `BoundedAssignment` contains no standing, reservation, dispatch, recovery, or target credential; no provider-port method crosses into governed services | type-level | conformant |
| 25. Expired records do not revive | doctrine-unproved | `crates/gwr-core/src/domain/standing.rs` and `domain/reservation.rs` check only the presented `now` against public `expires_at`; `crates/gwr-local/src/store/mod.rs` makes the persisted expiry immutable, but records no irreversible expired state | unenforced | looser than specified — after one expired check, a backward clock reading makes the same available record valid again; direct callers can also clone a public grant/claim and extend `expires_at`; existing tests assert expiry refusal, not non-revival |
| 26. Runtime clock readings control expiry | implementation-choice | `crates/gwr-runtime/src/ports/adapters.rs`: services obtain `Clock::now`; ratification, reservation, dispatch and recovery pass that reading into core expiry checks; `crates/gwr-local/src/adapters.rs` supplies `SystemClock` | checked | conformant |
| 27. State transitions are monotone | proved | `crates/gwr-core/src/lifecycle.rs`: each transition accepts only its predecessor and returns typed `TransitionRefusal`; terminal states have no legal exit; invalid methods borrow and return a new value | checked | looser than specified — `AttemptState` variants are publicly constructible and public `Store::record_*` methods accept a caller-supplied next state while checking only version, not the prior/next transition pair |
| 28. `DispatchRefused` stays distinct from `ProvenNotCommitted` | proved | `crates/gwr-core/src/lifecycle.rs`: they are distinct enum variants reached from different predecessor states; `crates/gwr-local/migrations/0001_init.sql` stores dispatch refusals and recovery resolutions in distinct typed ledger tables and projection tags | type-level | conformant |
| 29. Residual obligations remain visible after low-level completion | proved | `crates/gwr-runtime/src/services/reconcile.rs`: creates `HumanReviewBeforeMerge` if absent and retains every stored obligation; `crates/gwr-core/src/reconciliation.rs`: there is no discharge variant or API; CLI and vertical-slice tests expose the retained obligation | checked | looser than specified — commitment itself does not create the obligation, reconciliation can be skipped or invoked before completion, and the public store accepts an empty caller-constructed `Reconciliation` without validating retained obligations |
| 30. Absence of a bridge produces a first-class reliance refusal | doctrine-unproved | `crates/gwr-core/src/refusal.rs`: `RelianceRefusal::NoBridge` exists; `crates/gwr-core/tests/bridges.rs` and `crates/gwr-local/tests/failure_injection.rs` manually construct and record it; unsupported versions are genuinely checked by each bridge | tested-only | looser than specified — no runtime API accepts an undeclared source/consumer/claim crossing and produces `NoBridge`; the tests assert a value callers must choose by convention |

## 2 — Proved negatives

### N1 — The universal governed-transition record is vacuous

The natural drift point is persistence and the lifecycle, where attempts, outcomes,
observations, recovery, reliance, and obligations all overlap. It is kept out by the
variant `AttemptState` in `crates/gwr-core/src/lifecycle.rs`, the separate record types in
`outcome.rs`, `recovery.rs`, `receipt.rs`, and `reconciliation.rs`, and the separate typed
ledger tables in `crates/gwr-local/migrations/0001_init.sql`. No universal optional-field
record exists.

### N2 — No unifier

The natural drift point is the four domain crossings and their errors. It is kept out by
the four concrete modules under `crates/gwr-core/src/bridge/` and the separate refusal
enums in `crates/gwr-core/src/refusal.rs`. There is no `Decision`/`Verdict` trait, bridge
registry, universal evaluator, or common refusal conversion.

### N3 — No free-standing bridge

The natural drift point is unsupported bridge versions and requests for an undeclared
source/consumer/claim crossing. Every concrete bridge rejects unsupported versions, and
`RelianceRefusal::NoBridge` plus `unsupported_bridge_version_is_rejected` keep the
version-fallback design out. Nothing fully keeps out the missing-crossing design:
`missing_or_unsupported_bridge_produces_a_reliance_refusal` merely constructs `NoBridge`
itself, and no runtime dispatcher produces it for an absent crossing.

### N4 — Reliance does not factor through a fixed interface projection

The natural drift point is `rely_review_queue` in
`crates/gwr-runtime/src/services/reliance.rs`. It is kept out by the named,
consumer-specific `ObservationToReviewQueueV1`, whose input includes both the observation
and the exact commitment plus an explicit `Claim`. The bridge admits one claim and
refuses five; there is no `may_rely(receipt) -> bool` function.

### N5 — A refusal establishes what the attempt returned, not what was true

The natural drift point is downstream use of a `DispatchRefusalRecord` or standing
refusal. It is kept out structurally by the absence of any bridge or accessor from those
records to `ProvenNotCommitted`, lack-of-standing, discharge, or another negated domain
claim. `unsafe_refusal_reliance_is_rejected` preserves the dispatch refusal while
recording `NoBridge`, although that missing-bridge refusal is manually selected rather
than produced by a checked crossing.

### N6 — Identical endpoint states are not identical transitions

The natural drift point is attempt admission and content-addressed candidate storage. It
is kept out by `AttemptId` being included in the prepared-attempt transcript in
`crates/gwr-core/src/prepared_attempt.rs`, by immutable identity rebinding checks in
`crates/gwr-local/src/store/mod.rs`, and by
`identical_candidate_bytes_may_exist_under_different_attempts`. The implementation does
not deduplicate attempts on artifact digest or endpoint commit.

### N7 — Revocation is not restoration

The natural v0 drift point is `expires_at` on `StandingGrant` and `ReservationClaim`.
Persisted expiration values cannot be rebound under the same identity in
`SqliteStore`, and expiry checks reject a record at or after its deadline. Nothing keeps
the full negative out: there is no irreversible expired state or monotone-clock
requirement, public values can be cloned with a later expiry, and a backward clock
reading revives an otherwise available expired record. There is no non-revival test.

### N8 — Standing does not reduce to a role

The natural drift point is authority for ratification and recovery. It is kept out by
`StandingScope` in `crates/gwr-core/src/domain/standing.rs`, which binds actor, act,
repository, exact attempt digest, expiry, and one-use state; by the atomic consumption
projection in `crates/gwr-local/src/store/mod.rs`; and by the ratification/recovery tests
for wrong scope, expiry, and replay. The public-field clone/extend gap noted under N7
weakens value encapsulation but does not turn the persisted service path into RBAC.

### N9 — The hazard lives in the reliance relation, not in a producer-side noun

The natural drift point is receipt and refusal design. It is kept out by the narrow
receipt structs in `crates/gwr-core/src/receipt.rs`, which have no hazard, confidence,
severity, or consumer-advice fields, and by claim calibration in
`ObservationToReviewQueueV1`. No carrier/stranding ontology or `StrandedDemand` type
exists.

## 3 — Verdict

`cargo test --workspace` passed: 92 tests passed and none failed. That is not by itself a
conformance verdict.

**The release freeze is blocked by row 25.** It is tagged `doctrine-unproved` but is
classified `unenforced`, below the required minimum of `tested-only`: the suite checks
that an expired record refuses at a later clock reading, but neither code nor test
prevents revival after clock rollback or public clone-and-extension.

No `proved` row is classified `tested-only` or `unenforced`; therefore no proved row
independently triggers the gate's classification rule. Rows 1, 2, 6–9, 14, 21, 27, and
29 are nevertheless materially looser than specified for the gaps stated in the table.
Row 30 meets only the minimum doctrine threshold (`tested-only`) and does not implement
the protocol obligation it names. The freeze must not proceed until a fresh audit can
classify row 25 at least `tested-only` (and any implementation change is audited on what
it actually enforces).
