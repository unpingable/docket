# Invariants v0

Every invariant carries its provenance tag from the packet's `invariant-provenance.md`
(walked and operator-ratified 2026-07-24). Tags:

- **proved** — a theorem or exhaustive enumeration exists, cited by name. Non-negotiable;
  must be type-level or checked in the implementation. A contradiction exposed during
  implementation is reported, not resolved.
- **doctrine-unproved** — binding; at minimum tested-only. Reportable if implementation
  exposes a genuine contradiction; the operator rules.
- **implementation-choice** — revisable with a recorded rationale in the conformance
  document.

Proof custody shorthand: *GTK* = Governed Transition Kernel (machine-checked, proved
private unpromoted); *DCR* = DestroyedCarrierRefusal / `safe_consumers_only` (enumerated,
7,077,888 input-policy configurations over four consumer shapes — bounded, not universal);
*v14* / *v15* = released public lineage (DOIs 10.5281/zenodo.21435270 / minted v15.0.0).

| # | Invariant | Tag | Provenance |
|---|---|---|---|
| 1 | No effect without an admitted exact attempt. | proved | GTK admit gate; `committed_step_was_admitted`, `unresolved_step_was_admitted` |
| 2 | No retry under the same `AttemptId`. | proved | GTK `identical_endpoint_distinct_receipts`; released endpoint siblings (v14) |
| 3 | One persisted `DispatchId` per attempt. | implementation-choice | mechanism realizing 6–7; revisable with recorded rationale |
| 4 | Reusing the same `DispatchId` inspects the existing dispatch rather than repeating it. | implementation-choice | as 3 |
| 5 | A different `DispatchId` for the same attempt is refused. | proved | GTK replay theorems (fixture-level `decide`) |
| 6 | No success or failure is minted from indeterminacy. [†](#-custody-premise) | proved | GTK `fabricated_success_after_ambiguity_is_refused`, `unresolved_is_not_committed` |
| 7 | No automatic retry follows ambiguous dispatch. | proved | corollary of 6 |
| 8 | Recovery facts bind the exact attempt and dispatch. [†](#-custody-premise) | proved | GTK `reconciliation_is_recovery_sourced` + `reconcile` typed mismatch refusals |
| 9 | Recovery facts cannot resolve another attempt. | proved | as 8, plus `identical_endpoint_distinct_receipts` |
| 10 | Authentic recovery evidence does not apply itself. | doctrine-unproved | argued; explicitly not a finding (research intake, Kill-C) |
| 11 | Recovery requires separately valid resolution standing. | doctrine-unproved | argued; explicitly not a finding |
| 12 | No standing use is replayed. | proved | GTK replay theorems; released `replay_refused` (v14) |
| 13 | No resource reservation is replayed. | proved | GTK `admitted_reservation_conserved` (general); released `wf_conserves` (v14) |
| 14 | Ratification binds the exact prepared-attempt digest. | proved | GTK `committed_step_has_exact_effect`, `mediated_commitment_bundle` |
| 15 | Candidate content is immutable after admission. | proved | GTK exact identity binding (architectural mapping to candidate bytes) |
| 16 | Changing basis, patch, effect, or observation plan requires another attempt. | proved | corollary of 14–15 + N6 |
| 17 | No receipt asserts more than the trusted component established. | doctrine-unproved | proved specimens only (`observation_does_not_discharge`, `successful_effect_without_obligation_discharge`, `kernel_does_not_validate_meaningful_closure`); released doctrine "signed is not witnessed" (v14) |
| 18 | Effect commitment is distinct from observation success. | proved | GTK `observation_does_not_discharge`; type-level report trichotomy |
| 19 | Observation success is distinct from correctness, completion, merge safety, and obligation discharge. | proved | discharge component: GTK theorems; consumer-safety form: DCR enumeration |
| 20 | No silent lift occurs between domains. | proved | released screens `no_master_profile` / `MasterFree` / `UniversalReceiptFree` (v14); mechanized breakage in scratch |
| 21 | Refusals remain domain-narrow. | proved | DCR enumeration + GTK typed `RefusalCode` constructors |
| 22 | Consumer-specific reliance does not mutate or broaden the source receipt or refusal. | proved | DCR enumeration, claim-indexed form (checked cases, not a general theorem) |
| 23 | Provider identity does not appear in core lifecycle types or schemas. | doctrine-unproved | argued; consistent with GTK "semantics outside the trusted kernel" |
| 24 | Provider tool requests carry no authority. | doctrine-unproved | argued; governed-inquiry pattern (ratified 2026-07-11) |
| 25 | Expired records do not revive. | doctrine-unproved | argued; no retrievable record for the cited round — held on operator authority |
| 26 | Runtime clock readings control expiry. | implementation-choice | clock authority could be an injected trusted-time port |
| 27 | State transitions are monotone. | proved | GTK `step_sequence_exact`, `step_advances_once` |
| 28 | `DispatchRefused` remains distinct from later `ProvenNotCommitted`. [†](#-custody-premise) | proved | GTK type-level trichotomy; `recoveredNotCommitted` distinct constructor (names are this runtime's vocabulary) |
| 29 | Residual obligations remain visible after low-level completion. | proved | GTK `kernel_does_not_validate_meaningful_closure`; DCR `refusal_closes_accounting_but_blocks_required_completeness` |
| 30 | Absence of a bridge produces a first-class reliance refusal. | doctrine-unproved | released support: bridge-price theorem (v14); producing the refusal is this runtime's obligation |

## † Custody premise

Rows 6, 8, and 28 reach terminal recovery verdicts, and every recovery verdict is
derived from a reading of the governed target ref. Those rows hold **relative to an
explicit premise**:

> `ProvenNotCommitted` is valid only while the target ref is exclusively controlled by
> the governed broker from dispatch through recovery observation.

Without it, "the ref holds the basis" cannot distinguish *the effect never landed* from
*the effect landed and the ref was returned to the basis* — observationally identical
states with different occurrence histories, and no retained evidence separates them
(`refs/gwr/*` carries no reflog under Git's defaults). Under a violated premise these
rows still establish the weaker claim *"the effect is not presently reflected in the
governed ref"*.

The premise is not verified by this runtime and is not claimed to be. It is encoded as
`gwr_core::recovery::ExclusiveRefCustody`, a required field of `AuthoritativeBinding`,
so no code path reaches a verdict without naming it. Full statement:
[`trust-model.md`](trust-model.md). Executable boundary specimen:
`crates/gwr-local/tests/ref_custody_boundary.rs`.

## Enforcement expectations

- **proved** rows must be enforced type-level (illegal states unrepresentable) or checked
  (runtime validation with a typed refusal). Tested-only enforcement of a proved row is a
  defect that blocks the freeze (Task 12 gate).
- **doctrine-unproved** rows must be at minimum tested-only. Rows 10, 11, 17, 25, and 30
  should nonetheless be checked where the design makes it cheap — the tag records proof
  provenance, not importance; 10 and 11 are the two rows the whole recovery design rests
  on.
- **implementation-choice** rows (3, 4, 26) realize proved constraints without being
  derived from them. If a better mechanism appears, the row can change; the proved
  constraint above it cannot.
