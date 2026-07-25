# Architecture v0 — Governed Work Runtime

Normative source: the operator's normative packet (glossary, invariant provenance, proved
negatives, implementation plan). This document translates that packet; where they diverge,
the packet governs.

## Product thesis

A local-first governed work runtime for exact AI-mediated repository effects.

The runtime coordinates:

```text
work request
  -> preparation run
  -> candidate artifact
  -> prepared exact attempt
  -> ratification
  -> resource reservation
  -> dispatch
  -> committed | dispatch refused | indeterminate
  -> observation
  -> consumer-specific reliance
  -> reconciliation with residual obligations
```

The trusted runtime establishes **mechanical facts only**. Domain modules own semantic
judgments. Labor providers produce candidate artifacts and untrusted provenance; they do
not authorize, dispatch, reconcile, resolve recovery, or close work.

The honest scope of the trusted seam is capabilities plus resource accounting plus
transactional commit plus append-only exact audit logging. It is not more than that, and
this implementation does not act as though it is.

## Identity decision

Three identities, minted at three different moments, never interchangeable:

- **`WorkRequestId`** — the requested work. Mutable in ambition, retryable, may span many
  preparation runs. Never describes an exact effect.
- **`PreparationRunId`** — one bounded provider invocation. A provider death, refusal, or
  replacement ends a run; the successor is a new `PreparationRunId`. Provider identity is
  adapter-local provenance and never enters core lifecycle content.
- **`AttemptId`** — minted **only** at candidate admission, when five elements are fixed
  exactly: repository identity, basis (an exact commit), artifact digest, effect
  specification, observation plan. An attempt describes both an intention *and* an exact
  effect; the moment it describes only the first, the identity is wrong.

One `AttemptId` is never used for both vague preparation and an exact effect. A retry or
newly admitted candidate receives a new `AttemptId`, even when its bytes match a prior
candidate: identical endpoint states with different request, certificate, spend, or
provenance are not the same governed transition (packet proved negative N6).

Changing any of the five fixed elements produces a different attempt with a different
identity (invariants 14–16).

## Exact attempt lifecycle (summary; normative statement in state-machine-v0.md)

```text
Prepared -> Ratified -> Reserved -> Dispatching -> Committed
                                                -> DispatchRefused
                                                -> Indeterminate
Indeterminate -> CommittedViaRecovery
              -> ProvenNotCommitted
```

Observations, reliance decisions, reconciliations, and residual obligations are
**associated records**, not execution-state variants. They never expand the state enum.

## First vertical slice

One disposable Git repository fixture containing a small Rust crate with a failing test
named `canonicalizes_whitespace`.

The work request asks a labor provider to produce a unified diff that:

- is based on an exact commit;
- modifies only `src/lib.rs`;
- makes that exact test pass;
- does not directly modify the governed target repository or target ref.

The slice exercises, in order: bounded fake-provider preparation; immutable candidate
artifact ingestion; exact attempt admission; exact ratification; one-use target-ref
reservation; broker-mediated Git commit creation; atomic target-ref update; exact command
observation; consumer-specific admission to a human-review queue; reconciliation retaining
`HumanReviewBeforeMerge`; acknowledgement-loss injection; attempt-bound recovery evidence;
separately authorized recovery resolution.

## Mechanical facts (what the trusted runtime may establish)

Runtime-generated identities; exact artifact bytes and digests; runtime clock readings;
token integrity, scope, expiry, and consumption; reservation creation and consumption;
persisted dispatch identity; broker journal records; Git ref values; atomic ref-update
outcome when acknowledged; exact command invocation and termination; output digests; exact
recovery bindings; database transaction outcomes.

## Domain-owned judgments (what the trusted runtime never decides)

Whether authority was institutionally justified; whether the candidate is correct; whether
ratification was wise; whether evidence is semantically meaningful; whether a test is
sufficient for review or promotion; whether an obligation is discharged; whether closure
or forgetting is deserved; whether one domain judgment implies another.

## Untrusted provider claims

Treated as provenance only — stored as-said, never believed: provider-reported hashes;
provider timestamps; explanations; summaries; tool requests; test claims; completion
claims; refusal explanations; claims that a patch is correct or safe.

A provider-reported digest is compared against a runtime-computed digest; it is never used
in its place. Provider tool requests carry no authority (invariant 24).

## Persistence decision

```text
transactional current-state projections
plus
immutable typed ledger records
```

Full event sourcing is rejected for v0: it adds replay and schema machinery without being
required. Mutable current-state-only storage is rejected: it loses refusals, recovery
facts, resource uses, and exact historical receipts.

Every consequential transition:

1. reads the current projected state;
2. validates a pure transition;
3. inserts an immutable typed record;
4. updates the projection and its version;
5. commits atomically.

Normal operation reads current projections and never replays a generic event stream.

## Trust boundary

**Pure deterministic code owns:** typed IDs; digest transcripts; immutable value objects;
lifecycle validation; reservation and standing-use rules; bridge admission; receipt
construction from established facts; recovery-resolution validation; reconciliation rules.

**I/O adapters own:** SQLite; filesystem artifact storage; runtime clock; random identity
generation; provider invocation; subprocesses; Git operations; broker journaling; command
observations.

Digest discipline: no hashing of incidental serialized JSON. Digest input formats are
explicit, versioned, and carried with fixed test vectors.

## Receipts and refusals

A receipt is an exact record of what a trusted component established, bounded by
construction to the facts that component can establish (invariant 17). Receipts carry no
hazard hints, confidence markers, severity fields, or consumer advice: the hazard lives in
the reliance relation, not in a producer-side noun (proved negative N9). Producer refusals
stay lean; calibration lives in the consumer.

A refusal is a typed, domain-narrow negative outcome carrying its scope: what was refused,
on what ground, within what domain. Refusals are evidence, not errors, and they do not
broaden downstream (invariants 21–22).

## Statement on empirical basis

> No empirical workflow corpus has been supplied to this workspace. The normative packet
> and the operator's requirements are the sole normative input. Failure cases are
> requirement-derived synthetic scenarios and are not claimed as historical incidents.
