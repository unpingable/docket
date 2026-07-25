# Greenfield result — `gwr-greenfield-v0.1`

The frozen comparison baseline, recorded before any prior implementation becomes visible.

## Freeze statement

> No prior implementation of this runtime, and no repository outside this workspace, was
> read during the design or implementation of this frozen result. The requirements source
> was the operator's normative packet — glossary, invariant provenance, proved negatives,
> and implementation plan — which was assembled outside this workspace from prior formal
> work. This result is therefore independent of prior *code*. It is not independent of
> prior *doctrine*, and does not claim to be. Where an invariant is tagged `proved`, the
> proof is external to this repository and is cited by name, not reproduced or re-derived
> here.

## Architecture as implemented

Three crates, dependencies pointing one way only.

- **`gwr-core`** — pure domain. Identities, versioned digest transcripts, the attempt
  lifecycle, effect specification, observation plan, receipts, outcomes, recovery,
  reconciliation, typed refusals, the two authority domains (standing, reservation), and
  the four named bridges. No I/O, no persistence, no provider concept, one dependency
  (`sha2`).
- **`gwr-runtime`** — ports and services. `Store`, `EffectBroker`, `LaborProvider`,
  `RecoveryEvidenceSource`, `Clock`, `IdSource`; services for preparation, ratification,
  reservation, dispatch, recovery, reliance, reconciliation. Holds no authority of its
  own; every consequential step crosses a named bridge.
- **`gwr-local`** — adapters. SQLite store, subprocess Git broker plus its binary, HMAC
  standing-token codec, filesystem artifact and provenance stores, two fake providers, the
  `CodexExecProvider` real adapter, and the `docket` CLI.

### Identities and digests
Sixteen-byte typed identities, distinct types per domain, minted only by adapters. Every
digest is computed over an explicit versioned transcript — a domain tag plus
length-prefixed labelled fields — never over incidental serialization. Field order, label,
and domain tag are all binding; frozen test vectors detect any change to the input format.

### Lifecycle
`Prepared → Ratified → Reserved → Dispatching → {Committed | DispatchRefused |
Indeterminate}`, with `Indeterminate → {CommittedViaRecovery | ProvenNotCommitted}` as the
only exit from indeterminacy. Typed variants, never optional-field records. Transitions
take `&self` and return a fresh state; invalid transitions return a typed
`TransitionRefusal` and mutate nothing. The successor relation is enforced twice: by the
type system for in-process callers, and by `transition_permitted` in the store for
anything reaching persistence directly.

### Persistence
SQLite. Current-state projections plus immutable typed ledger tables — no generic event
stream, no universal record with optional fields. Every consequential change is one atomic
transaction: validate the projection version, validate the successor relation, insert the
typed ledger row, update the projection, increment the version. Encodings are explicit and
length-prefixed; no JSON, no serde.

### Bridges
Four concrete modules, each with its own input, output, and refusal type:
`StandingToRatificationV1`, `ReservationToDispatchV1`,
`ObservationToReviewQueueV1`, `RecoveryStandingToResolutionV1`. There is no bridge
registry, no `Decision`/`Verdict` trait, no universal evaluator, and no cross-domain
refusal conversion.

### Provider contract
Providers submit bounded work, emit sequenced neutral events, and return immutable
candidate bytes. They cannot admit, ratify, reserve, dispatch, resolve recovery, produce
trusted observations, decide reliance, discharge obligations, or close work — no such
operations exist on the port. Nothing in `gwr-core` names a provider, and no migration
carries a provider-identity column. The runtime computes candidate digests; anything the
provider says about its own work is stored as provenance, never believed.

### Real provider adapter
`CodexExecProvider` drives `codex exec` behind the unchanged contract, with zero diff to
`gwr-core` or `gwr-runtime`. Six fake-executable contract tests plus one live
`codex-cli 0.145.0` run through the full slice; transcript in
[`codex-smoke-run.md`](codex-smoke-run.md).

## Trust model

Stated in full in [`trust-model.md`](trust-model.md), and load-bearing for reading
everything above. In summary: one host, one UID, no OS-level confinement between runtime,
broker, provider, and repository; `ProvenNotCommitted` is valid only under exclusive
broker custody of the target ref; expiry is judged against runtime clock readings, so
monotone time is an environment assumption.

## Conformance

The classification that governs this freeze is
[`conformance-v0-second-pass.md`](conformance-v0-second-pass.md): every `proved` row
`checked` or `type-level`; rows 25 and 30 `tested-only`, meeting their doctrine minimum.
The first-pass audit and the eight-finding adversarial review that preceded it are
retained in [`conformance-v0.md`](conformance-v0.md) and
[`open-defects.md`](open-defects.md).

## Negative findings

The nine proved negatives are addressed in `conformance-v0.md` §2. The one that is only
partially kept out is **N3** — nothing produces `RelianceRefusal::NoBridge` for an
undeclared crossing; callers select it by convention. Recorded as a protocol obligation
rather than claimed as enforcement.

## Unresolved assumptions

Carried deliberately, each stated where it is relied upon rather than assumed silently:

1. **Exclusive broker custody of the target ref**, without which `ProvenNotCommitted`
   establishes only "not presently reflected in the ref".
2. **Same-UID trust** of the labor provider and the broker binary.
3. **Monotone clock readings**, without which an expired record can be re-presented as
   valid.
4. **`proved` tags are external.** No proof is reproduced or re-derived in this
   repository; each is cited by name in [`invariants-v0.md`](invariants-v0.md).

## Known omissions

See [`greenfield-known-gaps.md`](greenfield-known-gaps.md).
