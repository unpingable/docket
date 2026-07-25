# Task 14 — frozen greenfield runtime vs. the prior Rust implementation

The deliberately deferred comparison between the frozen greenfield baseline and the
prior Rust governed-transition implementation. Performed 2026-07-25, read-only, after
the freeze and after the greenfield's post-freeze work — against the frozen objects,
not the current heads.

**Comparison objects.**

- Greenfield: this repository at `c93c747` (tag `gwr-greenfield-v0.1`).
- Prior: `transition-kernel` at the commit its tag `stage3b2-first-effect` resolves to
  (`1a688ebf`) — an admissibility office within a multi-office governance
  constellation, whose summit claim is *at-most-once authority consumption and
  replay-legible execution of one idempotent bounded effect through a live
  supervisor*.

**Isolation statement.** No prior-implementation code was read before or during the
greenfield build (the freeze record's isolation claim). This comparison is the first
authorized read, it modified nothing in either repository, and no code moved in either
direction. Detailed file-level citations live in the private campaign record; this
document is the claim-level result.

**Prior-implementation gates at its tag** (run from an archived copy): `cargo test`
exit 0 (24 tests, including the nine-case frozen decision-surface corpus and eleven
hostile consequence-chain tests); `clippy -D warnings` exit 0; `cargo fmt --check`
exit 1 (formatting was not among that repository's documented gates; today's rustfmt
also postdates it). Its cross-language differential harness requires executing a
second live system and was not run.

## Shape of the comparison

The two implementations are **complementary organs, not rival implementations of one
organ**. The prior kernel decides *admissibility*: it composes already-decided peer
authorities (standing, spendability, bounded capacity) into
`Admit | Refuse | Escalate`, mints at most a non-authoritative candidate, and by
declared non-claim executes nothing. The greenfield runtime owns the complementary
span: exact admission, ratification, reservation, dispatch, settlement, recovery,
observation, and reliance for one Git effect class. They overlap on invariant content,
not on role.

## Matrix (claim level)

Classifications: greenfield improvement (GI) · prior mechanism preserved in another
form (PP) · useful prior mechanism omitted by greenfield (PO) · intentionally excluded
(LX) · same mechanism, different terminology (ST) · same defect independently
reproduced (SD) · assumption explicit only in one (AD/AT) · formal requirement absent
from one (FR) · incompatible architecture (IA) · unknown (UK). *Conformance
interaction* states whether the prior behavior is closer to, further from, or
orthogonal to the packet's proved invariants relative to the greenfield.

| dimension | greenfield | prior | evidence | class | consequence | conformance |
|---|---|---|---|---|---|---|
| role | whole governed vertical for one effect | admissibility office over peer offices; executes nothing | both repos' contract docs | IA | integration is a seam, not a merge | orthogonal |
| candidate ≠ authority | typed lifecycle + consumed standing | structural: sealed dual proofs, authority object unconstructable without capability + execution-time revalidation + operation binding | sealed types, single constructors | ST | shared doctrine, independently realized | equal |
| exact-content binding | prepared-attempt digest; standing/ratification bind it | anti-recombination: capability bound to the exact standing reference, scope, target, effect class | binding checks + hostile tests | ST | equivalent invariant | equal |
| linearity / replay | one dispatch identity per attempt, ever; re-entry inspects | derived consumption-event identity makes a replay collide with its own spend | replay-refusal specimen | ST | identity-discipline vs idempotency-key; both linear, not interchangeable | equal |
| recovery yardstick | first audit found self-certifying recovery facts; repaired before freeze | yardstick (expected content hash, event id) durable **before** the effect from the start | committed crash specimen | prior art anticipated a greenfield defect class | the repaired greenfield now matches | equal (after repair) |
| crash after acknowledged effect | first audit found the stranded case; repaired before freeze | crash-reconcile was a canonical specimen from the start | committed specimen bundle | as above | as above | equal (after repair) |
| endpoint-state inference | custody premise found, typed, and required (`ExclusiveRefCustody`) | same inference made from its endpoint (marker absence ⇒ non-effect) with **no custody premise named** | reconciliation rules | AD | the premise-naming discipline is the greenfield's contribution | closer (greenfield) |
| settling authority | recovery verdicts require separately held recovery standing | reconciliation is an unauthenticated classification read | recovery APIs | FR | greenfield-only law (invariants 10–11) | closer (greenfield) |
| execution-time revalidation | no direct analog (reservation expiry + clock premise) | explicit subject-bound re-verification of standing liveness at the execution clock; its own missing-clock gap honestly ledgered | revalidation type + gap specimen | PO | candidate for a future greenfield seam; filed, not owed | closer (prior) in intent |
| escalation | absent — refusals only | typed third verdict carrying the required authority | decision enum | PO | matters for the upstream-authorization seam, not for this runtime's core | orthogonal |
| store-enforced lifecycle | successor relation validated at persistence; journals digest-verified before reading | append-only log without store-side validation or integrity binding | store/tests vs log format | FR | greenfield-only law | closer (greenfield) |
| canonical encodings | versioned digest transcripts, length-prefixed codecs, frozen vectors (post-audit) | canonical-JSON hashing plus an opaque-pointer rule for foreign non-canonical digests | codecs and dependency choices | PP | two principled answers; "never recompute what you didn't canonicalize" is worth keeping as doctrine | equal |
| premise-qualified outcomes | endpoint-custody premise explicit; verdicts qualified | a different premise structural (simulated origin can never mint an operational outcome) | premise fences | ST | each baseline lacks the other's premise | equal |
| effect specificity | one Git effect class; explicitly non-generic | one marker effect class; explicitly non-generic ("no shell, no overwrite") | both claims docs | ST | shared refusal of generic effect execution | equal |
| operator read surface | shallow at the frozen baseline (the pilot later established the dossier) | none; specimens and reconstruction serve tests, not operators | surfaces at both tags | both lacked it | the greenfield's post-freeze dossier work addresses it | equal |
| epistemic memory custody | out of scope | consumer-indexed promotion lattice gating remembered material from reliance | custody module | LX | belongs to the upstream/epistemic offices, not this runtime | orthogonal |
| formal coupling | provenance-tagged invariants; proofs external, cited by name | one-way obligation ledger with build-breaking disposition pins | ledgers + specimens | ST | the executable disposition pin is a technique worth considering | equal |

## Findings

1. **No prior mechanism was found that is more conformant with the packet's proved
   invariants than the frozen greenfield on any proved row.** The two genuine prior
   assets the greenfield lacks — execution-time revalidation and a typed escalation
   verdict — sit on doctrine-level rows or at the constellation boundary.
2. **Two greenfield audit-defect classes were structurally absent from the prior
   implementation** (self-certifying recovery evidence; the stranded
   acknowledged-effect crash). Both were found and repaired before the freeze; the
   prior art confirms the repaired law rather than contradicting it.
3. **One prior soundness hole is the exact class the greenfield later named**:
   non-occurrence inferred from endpoint state without a custody premise. The
   greenfield's `ExclusiveRefCustody` discipline is the general fix; the prior
   implementation carries the hole unnamed.
4. **Nothing should be imported.** The useful prior material is doctrine
   (ordering-before-outcome, post-effect verification, never-success conflict
   terminals, opaque-pointer digests, executable disposition pins), all either already
   greenfield law or filed as candidates — not code.
5. **Isolation held.** The architectures differ where the packet permits difference
   and agree where it proves; no structural ancestry beyond the shared doctrine both
   were built under.

## Verdict

The greenfield result stands as an independent realization of the doctrine with
strictly stronger persistence, recovery-authority, and premise-naming law than the
prior implementation; the prior implementation contributes two named candidate
mechanisms and several confirming precedents, and nothing that weakens the frozen
claims. Task 14's purpose — a comparison uncontaminated by prior code — is achieved
and closed.
