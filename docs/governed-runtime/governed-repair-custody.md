# Governed-repair custody

Docket owns the consequence boundary after it accepts one exact AG issuance.
If mechanics discover that the issued effect scope is insufficient, or that a
fresh normative decision is required, Docket records a terminal, append-only
checkpoint. The checkpoint is evidence of a fail-closed halt. It is not
standing, a repair permit, or authority to continue the consumed occurrence.

The canonical intake is AG signed-issuance v2. Docket requires one canonical
outer envelope spelling, authenticates its exact canonical body bytes,
consumes independently resolved execution standing, persists one attempt
before invoking mechanics, recomputes the embedded RFC 8785 scope identity,
and checks every reported effect against the immutable canonical scope. The
same recomputation is performed before standing resolution, at result seal,
and on durable read. The signed issuance also repeats the proposal's
canonical nonclaim identities and absolute expiry. Nonclaims are opaque bound
identities here; Docket does not interpret their NQ or AG meaning. The expiry
must fit the RFC 8785 safe-integer domain. Docket refuses new custody at or
after that deadline while still permitting exact read-only retrieval of
an already durable custody/result. Ordinary settlements, indeterminate
observations, and governed-repair outcomes all retain exact effect-journal
evidence. Indeterminate observations and a later terminal observation form
one durable, ordered cumulative journal; no terminal result discards an
earlier reported effect. An out-of-scope reported effect refuses before
settlement. A known settlement carries that complete cumulative-journal
identity, and its own identity is derived from the complete canonical
settlement body excluding only the identity field. Schema, issuance, attempt,
executor marker, receipt, outcome, cumulative journal, and settlement time are
therefore non-substitutable on restart or replay.

There are two closed governed-repair outcomes:

* `scope_expansion_required` binds the original scope, an exact strictly
  additive delta containing no already-admitted operation, the first blocked
  operation, and exact reason/dependency identities.
* `readjudication_required` binds an exact normative-question identity,
  complete evidence/diagnostic/alternative/fact censuses, and an exact
  read-only adjudication scope.

The executor output is evidence only. Docket validates it against the exact
issuance, custody, attempt, executor binding, effect journal, optional immutable
work checkpoint, time window, and idempotency identity. A work checkpoint has
an optional exact dirty-diff identity but always has an exact content-manifest
identity. Absent optional identities are omitted on the AG wire; explicit
`null` is noncanonical. Docket then derives
explicit transcript identities for the requirement, checkpoint, and sealed
result and appends all scalar/closed data atomically. Exact replay returns the
same result; changed content collides and refuses. Immutable-table triggers and
full read-time identity reconstruction make restart unable to inherit or mint
authority from stored bytes.

An optional successor-work checkpoint in an AG issuance is likewise evidence,
not authority. A configured verifier must freshly establish its exact
repository/commit/tree/content-manifest correspondence at intake and again on
every re-entry that could invoke the executor, including reconciliation.
Future-dated or expired verification refuses before an executor call or state
advance.

The sealed field `no_unauthorized_effect_reported` has deliberately narrow
semantics: Docket validated the complete effect journal presented by its
mediated executor boundary and found no entry outside issuance scope. It does
not prove physical non-occurrence outside that reporting boundary. Executor
journal completeness and physical containment remain explicit operational and
qualification premises; Docket does not manufacture a stronger receipt.

Likewise, `reported_authorized_effects_occurred` means only that the cumulative
executor-reported journal is nonempty. It is not a claim about unreported or
physically mediated effects. Terminal sealing takes an immediate Store
transaction before reading that cumulative journal; a later indeterminate
observation cannot append after the terminal cut.

The additive R2 settlement migration first completes the cumulative executor
journal backfill, verifies each rejected-R1 terminal receipt/outcome and legacy
settlement identity, retains that legacy identity and its deterministic
canonical wire bytes as historical development evidence, and only then derives
the active complete-body settlement projection. An incomplete or contradictory
historical row rolls the whole migration back. Settled projection columns are
immutable after that cut.

An authenticated, canonical issuance that fails a permanent pre-custody law
does not disappear into an untyped command error. Docket seals an immutable
`docket.governed-loop.issuance-refusal/v1` result for an authenticated but
semantically invalid issuance, an expired issuance, an invalid checkpoint
correspondence, an invalid standing response, or an authority-instrument
substitution. The refusal binds the issuance, campaign, occurrence, closed
refusal class, exact reason/evidence identities, and Docket observation time. A
shared issuance-disposition guard makes custody and refusal mutually exclusive
under concurrency. Exact replay returns the same refusal; altered stored bytes,
a changed signed envelope, or conflicting refusal evidence fail closed.
Refusal creates no attempt, consumes no Docket standing, and invokes no
consequence-bearing executor operation. Authenticated input whose purported
issuance/campaign/occurrence coordinates are not even valid immutable keys is
not recordable and fails as an error rather than acquiring an invented key.
On migration, custody rows that predate this common guard are backfilled with
their already durable attempt identity. This closes the mutual-exclusion
membrane for reopen without reconstructing standing, creating another attempt,
or reinterpreting historical bytes as a refusal.

Authentication failures and transient boundary failures remain errors rather
than false terminal facts. In particular, an untrusted or invalid signature,
an unavailable/misconfigured checkpoint verifier, a standing-resolver spawn or
transport failure, and an unavailable executor configuration do not produce a
sealed semantic refusal. They may be retried only through the caller's normal
AG reconciliation law; Docket itself grants no continuation authority.

AG may consume the sealed result only to enter its governed halt and emit a
human-decision request. A later human disposition opens a new occurrence under
fresh observation, standing, admission, and spend. Neither Docket nor AG may
reinterpret this record as the retired campaign-stage `exact_repair` route.

The Docket CLI exposes custody acceptance, consequence-free issuance
observation (`reconcile-issuance`), and authenticated explicit reconciliation
rounds (`reconcile-attempt`).  Only the latter may cross the executor
reconciliation boundary, and its durable reservation commits first.  Neither
operation exposes constructors for requirements, checkpoints, sealed results,
or repair authority. Legacy campaign-stage repair artifacts remain historical
and cannot be imported into this path.

Custody becomes visible before the retained initial executor response returns,
so initial execution and a first explicit round can legitimately overlap.  If
that initial execution advances the exact claimed source cut, Docket resolves
the round only from the monotone durable attempt result.  A superseded executor
response may not add a journal entry, and replay does not reinvoke the executor.
An unchanged claimed cut remains unresolved after restart.  A terminal result
that lands after a completed indeterminate round is observable through exactly
one predecessor-bound local round; it does not authorize another poll.

## Campaign boundary and nonclaims

This implementation campaign is bootstrapped by explicit external human
development authorization. The new governed loop did not govern its own
creation, and no record produced while building it is AG standing or Docket
repair authority. The checked-in NQ C1 rejection/repair specimens are immutable
conformance fixtures only; they grant no authority and make no runtime claim
about NQ.

Qualification status is `not_assessed`. Passing development tests is not a
qualification claim, independent review, certificate, activation, or
promotion. The Gen4 authority selection remains unchanged and uniquely active;
that is a campaign fixture fact, not authority conferred by Docket.
