# Changelog

Notable changes to the governed work runtime.

## Unreleased — post-pilot legibility and effect boundary — 2026-07-25

Two changes motivated by the first pilot's findings
([`docs/pilot-01.md`](docs/pilot-01.md), dispositions in
[`docs/pilot-01-followup.md`](docs/pilot-01-followup.md)). The frozen tag has not moved.

### Added

- **Canonical attempt dossier** (`2e30762`) — one read model sources both `docket show`
  surfaces; JSON is versioned as `gwr:attempt-dossier:v1`. Exposes goal, actor, grant
  scope and consumption, reservation, dispatch, digests, evidence, obligations,
  reliance records, and timestamped timeline. Recovery verdicts render **qualified**:
  proof basis, the asserted `ExclusiveRefCustody` premise, observed ref, expected result
  commit, and whether the records agree. `proven_not_committed` is no longer presented
  as unconditional history. [`docs/governed-runtime/attempt-dossier.md`](docs/governed-runtime/attempt-dossier.md)
- **Explicit effect-class admission** (`df43d67`) — `GitRefEffect`
  (`git-ref-update:v1`) is the one admitted effect class; its tag was already bound into
  every prepared-attempt digest, and its settlement model is now declared as typed
  premises. Inexpressible proposals refuse with a typed `EffectClassRefusal` at request
  creation / preparation / admission, before authority, reservation, dispatch, provider
  execution, or Git. [`docs/governed-runtime/effect-classes.md`](docs/governed-runtime/effect-classes.md)

### Fixed

- Persisted reliance refusals retain their subject — observation, consumer, claim
  (freeze finding N-5). Narrow migration `0002_reliance_subject.sql`; rows written
  before it read back as subject-absent, never defaulted.
- Store decode is fully fallible: malformed persisted columns surface as
  `StoreError::Corrupt` instead of panicking.
- The CLI's command listing now includes `recover fact` and `recover resolve`
  (pilot finding P-3).

### Compatibility

Pilot-era state opens unchanged under the migration; pre-boundary records (including
the pilot's run-N `mailto` attempt) remain byte-exact readable, and their dossiers
display the historical category error rather than hiding it. 144 tests, identical in
debug and release; all four gates exit 0.

## [gwr-greenfield-v0.1] — 2026-07-25

The frozen greenfield comparison baseline. Tag `gwr-greenfield-v0.1`, commit `c93c747`.

### Freeze statement

> No prior implementation of this runtime, and no repository outside this workspace, was
> read during the design or implementation of this frozen result. The requirements source
> was the operator's normative packet — glossary, invariant provenance, proved negatives,
> and implementation plan — which was assembled outside this workspace from prior formal
> work. This result is therefore independent of prior *code*. It is not independent of
> prior *doctrine*, and does not claim to be. Where an invariant is tagged `proved`, the
> proof is external to this repository and is cited by name, not reproduced or re-derived
> here.

### Added

- Three crates: `gwr-core` (pure domain, no I/O), `gwr-runtime` (ports and services),
  `gwr-local` (SQLite store, subprocess Git broker, HMAC standing tokens, providers, the
  `docket` CLI).
- The exact attempt lifecycle with typed states and typed transition refusals, enforced
  twice: by the type system in-process, and by a successor-relation check in the store.
- Four named domain bridges with distinct inputs, outputs, and refusals. No registry, no
  universal judgment type, no cross-domain refusal conversion.
- Attempt-bound recovery: nine-field binding against the runtime's own record, journal
  verification against the digest recorded at indeterminacy, and commitment-ledger
  attribution.
- Neutral labor-provider port plus a real `codex exec` adapter behind the unchanged
  contract.
- `docs/governed-runtime/`: architecture, invariants, state machine, bridge specifications,
  non-goals, trust model, conformance audits, and the freeze deliverables.

### Verification at freeze

125 tests, identical under `cargo test --workspace` and `cargo test --workspace --release`.
`cargo fmt --check` and `cargo clippy --workspace --all-targets -- -D warnings` both exit 0.

### Fixed before freeze

An independent adversarial review produced eight witnessed violations, repaired in a
campaign covering broker path authorization (rename and copy diffs escaping the allowlist),
recovery binding and verdict derivation, dispatch re-entry after runtime death,
persistence encoding, the store's transition validation, the standing-token codec, and
sealed authority value objects.

A second blind review then re-ran the full invariant table and every recorded witness, and
closed three further findings:

- **Custody premise.** `ProvenNotCommitted` was derived from a ref reading without stating
  the premise that made it sound. Exclusivity is now explicit and required:
  `ExclusiveRefCustody` is a field of `AuthoritativeBinding`, so no path reaches a verdict
  without naming it.
- **Token canonicality.** Uppercase MAC tags passed verification, panicking in debug and
  being accepted in release. Tags must now be canonical lowercase hex, and every accepted
  token must re-encode to exactly the bytes presented, in every build profile.
- **Empty observation plans.** `observe()` indexed an empty argv, stranding a committed
  attempt. Now a typed refusal before anything runs, and refused at admission.

### Known boundaries

Stated rather than enforced, in full in
[`docs/governed-runtime/trust-model.md`](docs/governed-runtime/trust-model.md):
exclusive broker custody of the target ref, same-UID trust of provider and broker, and
monotone clock readings. Remaining non-enforcement is recorded in
[`docs/governed-runtime/greenfield-known-gaps.md`](docs/governed-runtime/greenfield-known-gaps.md).

[gwr-greenfield-v0.1]: https://github.com/unpingable/docket/releases/tag/gwr-greenfield-v0.1
