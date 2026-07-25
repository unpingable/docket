# Pilot 01 — follow-up

[`pilot-01.md`](pilot-01.md) is the original pilot record and is preserved unchanged;
its findings describe the runtime as it was on 2026-07-25 at pilot time, and nothing
below rewrites them. This note records which findings motivated which changes, made in
two commits after the pilot (`2e30762` read surface, `df43d67` effect boundary), with no
change to the frozen `gwr-greenfield-v0.1` baseline.

| pilot finding | disposition |
|---|---|
| **P-1** — receipts exist but are not readable | **Closed** by the canonical attempt dossier: one read model sources `docket show` and `docket show --json`; goal, actor, scope, digests, evidence, and timestamps are all exposed. [`governed-runtime/attempt-dossier.md`](governed-runtime/attempt-dossier.md) |
| **P-2** — `proven_not_committed` displayed without its premise | **Closed**: recovery verdicts render qualified — proof basis, asserted `ExclusiveRefCustody`, observed ref, expected result commit, evidence concordance, and explicit establishes/does-not-establish statements. The custody specimen (run C) now displays its own unsoundness. |
| **P-3** — recovery verbs undiscoverable | **Closed**: the CLI's command listing includes `recover fact` and `recover resolve`. |
| **P-4** — no effect-class boundary | **Closed** by explicit effect-class admission: `GitRefEffect` is the one admitted class; inexpressible proposals refuse with a typed `EffectClassRefusal` before standing, reservation, dispatch, provider execution, or Git. The pilot's notification exercise now refuses at `request create` with nothing spent. [`governed-runtime/effect-classes.md`](governed-runtime/effect-classes.md) |
| **P-5** — candidate was operator-authored | Unchanged — a property of that pilot's method, not of the runtime. |
| **P-6** — governed commits authored by the broker | Unchanged — correct by design; now visible in the dossier (dispatch identity, journal digest) rather than only in `git log`. |
| **P-7** — custody violation undetectable after the fact | Unchanged — this is the declared trust boundary. What changed is presentation: the verdict that depends on it now says so (P-2). |

Also closed along the way, from the post-pilot legibility review:

- Persisted reliance refusals now retain their subject — observation, consumer, claim
  (freeze-audit finding N-5; migration `0002_reliance_subject.sql`, nullable columns;
  pre-migration rows read back as *subject not recorded*).
- Malformed persisted records produce typed read errors (`StoreError::Corrupt`,
  `DossierError::MissingRecord`) instead of panics.
- Timeline timestamps, which were recorded but never shown, are exposed.

Still open from the pilot's perspective: `docket list` carries no repository/ref/time
columns; the actor is exposed as its recorded identity (a digest of the operator-supplied
name), so mapping it to a person is a deployment concern; and `dispatch_refused` for a
*well-formed* Git effect still prints only its mechanical ground with no next-step
guidance.

The pilot itself was run against the pre-change surface. Its captured output is what it
was; none of the above makes the new mechanisms retroactively present during the pilot.
