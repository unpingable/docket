# Vertical 01 — one governed change across three offices

The first change to this repository authorized upstream, executed here, and projected
downstream as testimony — run 2026-07-25. This document was itself the governed change:
it was written, then submitted through the vertical it describes, and the commit that
added it was authored by this runtime's broker, not by hand.

Three offices, three questions, three answers that do not substitute for one another:

| office | decides | for this change |
|---|---|---|
| upstream authorization | may exact proposed work receive authority? | admitted against a root-owned target catalog, under an authenticated issuance |
| Docket (this runtime) | does an authenticated issuance match an exact prepared attempt, and what execution actually occurred? | issuance verified and bound; local single-use standing minted and spent; effect settled `committed` |
| downstream testimony | what may a consumer lawfully infer? | the dossier imported as bounded, projection-marked testimony; no claim minted |

## The sequence

1. Docket prepared an exact attempt — **without standing**. Preparation authorizes
   nothing.
2. Docket exported the canonical authorization request (`gwr:authz-request:v1`): the
   attempt identity and version, effect class, prepared-attempt transcript digest,
   repository, target ref, basis, admitted paths, the actor proposed for ratification,
   and this effect class's own settlement premises — declared for the upstream office's
   information, not adopted by it.
3. The upstream office decided on those exact bytes through its normal path: target,
   actor, and every admitted path checked against its root-owned catalog, with its
   principal chain validated.
4. It burned its own decision authority once. A second issuance for the same decision
   refused.
5. It emitted one authenticated immutable issuance (`ag.docket-issuance:v1`), signed
   Ed25519 over the exact body bytes with a domain-separated statement prefix.
6. Docket verified that issuance against **its own stored attempt** — trusted issuer,
   signature, freshness, admitted decision, and every Docket-owned field compared to
   what Docket holds, never to the record's own echoes.
7. Docket minted **its own** standing: local, bound to the exact prepared digest,
   single-use, expiring no later than the issuance.
8. Ratify → reserve → dispatch through the broker; observe; reconcile.
9. Docket rendered the canonical dossier (`gwr:attempt-dossier:v2`), whose new
   `authorization` block carries the upstream facts as upstream facts.
10. The downstream office imported that dossier through its existing
    external-projection profile, and its registry was consulted through the normal
    claim path.

## What each office established — and did not

**Upstream authorization established** that this exact proposal was admitted under a
named decision context, that its own authority was consumed under its own law, and that
the issuance is authentic. It established **nothing** about whether the effect executed,
whether the repository reached any state, or whether any downstream claim is
admissible. An issuance is an authenticated fact about a decision; it is not authority,
and no authority object crossed the boundary — the upstream office's sealed authority
never left it.

**Docket established** that the authenticated issuance matched the exact prepared
attempt, that local standing was minted once and consumed once, and exactly what
execution and settlement occurred, with its evidence. It established **nothing** about
whether the upstream policy was correct, whether the upstream premises are true, or
whether the resulting commit is safe to merge. Docket did not re-decide the upstream
question; it checked custody, not policy.

**The downstream office established** only what its evidence and registry permit.
Authorization plus settlement did not mint `safe_to_merge`, which remains structurally
non-mintable; no registered claim verified from this testimony alone.

## What is carried, and what is not merged

- **Two premise kinds stay two.** Upstream *authorization* premises (principal
  authentication, target-catalog binding) are recorded, rendered, and translated
  downstream as authorization premises. This effect class's *settlement* premises
  (inspectable endpoint, atomic compare-and-swap, attributable result state, exclusive
  ref custody) remain separate everywhere. Neither becomes the other, and no office
  claims to have verified premises it merely received.
- **Two digest domains stay two.** The upstream office's canonical digest of the
  request and Docket's own byte digest of the same request both travel; neither is
  derived from the other, and neither is interchangeable with Docket's prepared-attempt
  transcript digest.
- **Upstream residual obligations are carried undischarged.** For this run the upstream
  office reported them *unrepresented* — it cannot express residuals yet. That is
  recorded as a producer limitation, not as their absence, and execution and import
  discharge nothing.
- **No notary exists.** The downstream packet is operational testimony marked as a
  projection of Docket-held records; digests are producer self-consistency, not an
  independent chain of custody.

## Negative specimens

Run alongside, each producing no standing, no reservation, no dispatch, no Git mutation,
and no testimony describing an execution: an altered issuance body; an expired issuance;
an issuance naming a different prepared digest; an exact issuance replayed against a
second attempt; and a request the upstream office refused outright (a path outside its
catalog's admitted scope), which produced no issuance at all.

## Provenance

Exact identifiers for this run — request and issuance digests, decision and issuance
identities, standing and dispatch identities, the settled commit, the downstream packet
digest, and the claim results — are recorded in campaign custody alongside the commands
that produced them. This is a bootstrap vertical: it is not a claim of production
provider confinement, and it is not a notarized custody chain.
