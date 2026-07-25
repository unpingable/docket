# The canonical attempt dossier

The supported evidence/read surface for an attempt. Introduced after the first pilot
([`pilot-01.md`](../pilot-01.md)), whose central finding was that the runtime recorded
nearly everything and exposed nearly nothing (P-1), and displayed its one
premise-dependent verdict without the premise (P-2).

## One model, two renderings

`gwr_runtime::services::dossier` defines a single read model, `AttemptDossier`,
assembled from the store alone. Both operator surfaces are pure functions of the same
assembled value:

```bash
docket show --attempt <id>          # human rendering
docket show --attempt <id> --json   # versioned JSON rendering
```

There is no second assembly path, so the surfaces cannot drift. The JSON carries
`"dossier_format": "gwr:attempt-dossier:v1"`; any change to its key set or value
encodings is a version bump, not an edit.

## What it exposes

Only records the runtime already owns — the dossier manufactures no facts:

- **Identity and preparation** — goal, work request, repository, target ref, basis,
  effect class and its declared settlement premises, admitted paths, candidate and
  preparation-run identities, candidate/patch/prepared-attempt digests, observation
  plan, creation/admission timestamps.
- **Authority and reservation** — ratification receipt (actor, standing use, time), the
  ratifying grant's scope and exact digest binding, expiry and consumption status, the
  reservation and its consumption, the one dispatch identity, and — separately — the
  recovery grant where one was consumed. No token text, no MAC material: a grant row
  identifies authority, it does not confer it.
- **Execution and settlement** — lifecycle state, version, timestamped timeline,
  commitment (previous value → result commit, journal digest), dispatch refusal ground,
  indeterminacy record, recovery facts, resolution, and a derived `settlement`
  classification (`normal` / `refused` / `unresolved` / `recovered` / `not_dispatched`).
- **Observation and reliance** — full observation records, reliance admissions, reliance
  refusals **with their subject** (which observation, presented to which consumer, for
  which claim), residual obligations, and the reconciliation that retained them.
- **Qualification** — present exactly when a recovery resolution exists; see below.

Reads are total over honest stores and typed over broken ones: a malformed persisted
column surfaces as `StoreError::Corrupt`, a projection whose ledger record is missing as
`DossierError::MissingRecord` — never a panic, never a defaulted field. Records
persisted before newer columns existed read back with those fields absent, not invented
(e.g. pre-migration reliance refusals show *subject not recorded*).

## Qualified recovery verdicts

A recovery verdict is never rendered as unconditional history. The qualification block
carries:

- the verdict and its proof basis (the runtime's reading of the target ref plus the
  broker journal verified against the digest recorded at indeterminacy);
- the custody premise: `ExclusiveRefCustody`, **asserted by the deployment at
  resolution, not verified by the runtime**;
- the observed ref, the expected result commit from the digest-verified journal, and the
  commitment ledger's attribution of the observed commit;
- whether those records agree (`evidence_concordance` / `evidence_agrees`);
- fixed statements of what the verdict establishes and what it does not.

For `proven_not_committed` the surface states explicitly that external mutation of the
target ref between dispatch and the recovery observation would make the same evidence
consistent with an effect that landed and was reverted. When the digest-verified journal
records an effect commit that the observed ref does not hold, the disagreement is
rendered as disagreement — with both consistent histories stated — and never silently
resolved in either direction. The preserved custody-boundary specimen
(`crates/gwr-local/tests/ref_custody_boundary.rs`, pilot run C) renders exactly this
way; `crates/gwr-local/tests/dossier.rs` asserts it.

## Stability

The JSON form is intended to be stable enough for later ingestion by external tooling
(a cockpit, a witness system). No such integration exists yet, and none is implied by
the format.
