# Non-Goals

These are exclusions, not deferrals. Reaching for one during implementation is a signal
that scope has drifted, and several are proved negatives (packet `proved-negatives.md`):
each was shown not to work, and each will look like a reasonable simplification when
re-proposed.

## Excluded

- generic agent frameworks;
- universal policy engines;
- universal `GovernedDecision` records (proved negative N1 — optional heterogeneous
  fields carry no shared law);
- generic effect execution;
- arbitrary shell effects;
- generalized accounting;
- complete AG, NQ/NG, LA, or MC implementations;
- semantic correctness;
- merge safety;
- obligation discharge;
- domain closure;
- forgetting;
- provider-specific concepts in core records;
- provider SDK types in core crates;
- plugin systems;
- dynamic policy loading;
- distributed operation;
- multi-tenancy;
- remote attestation;
- cryptographic identity federation;
- web UI;
- dashboards;
- merge, release, deployment, or promotion automation;
- compatibility with prior code;
- comparison with prior implementations (gated separately at Task 14; not performed here).

## Also excluded, by proved negative

- any unified admissibility judgment or `Decision`/`Verdict` trait across domains (N2 —
  the trait is the unifier);
- default behavior where no bridge exists (N3);
- reliance as a pure function of the receipt (N4);
- reading a refusal as its negation (N5);
- deduplicating attempts on content (N6);
- reviving expired records (N7 relevance: expiry is the only place v0 touches this);
- standing flattened to role-based access control (N8);
- producer-side hazard annotations on receipts — confidence markers, severity fields,
  consumer advice (N9).

## Vocabulary deliberately absent

Per the packet glossary, the following belong to the wider constellation and are out of
scope for this runtime; using one is itself a drift signal: coverage debt;
carrier-stranded versus repayable debt; closure; forgetting; erasure; quotient
granularity; enactability; realizability; governance-indexed anything; transport of global
blockage; the promotion theorem; StrandedDemand (a name with no attested referent — the
operator has directed it must not be minted).

## Statement on empirical basis

> No empirical workflow corpus has been supplied to this workspace. The normative packet
> and the operator's requirements are the sole normative input. Failure cases are
> requirement-derived synthetic scenarios and are not claimed as historical incidents.
