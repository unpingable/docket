# Governed reconciliation single-flight R4

## Bootstrap and scope

This correction is constructed under external human development authorization.
It does not govern its own construction and it grants no NQ, deployment,
qualification, certificate, or operational authority.

## Mandatory semantic decision

Docket already promises more than one legitimate read-only reconciliation
observation for an indeterminate attempt.  The R3 regression
`unknown_outcome_reconciles_read_only_and_never_executes_again` exercises an
indeterminate observation, a later distinct indeterminate observation, and a
terminal observation.  The cumulative-journal law likewise retains every
ordered observation.  Consequently, reducing reconciliation to one physical
call per attempt would narrow an accepted R3 contract.

R4 therefore uses explicit, versioned reconciliation rounds:

* AG owns creation and authentication of one exact round request under its
  caller-state compare-and-swap law.
* Docket validates the request, derives its exact durable attempt source cut,
  and commits a unique round reservation before calling the executor.
* Duplicate delivery of one round returns its durable completed or unresolved
  state and never invokes the executor again.
* A later poll is a new round bound to the immediately preceding completed
  indeterminate round.  A claimed round left unknown by a crash blocks rather
  than enabling another poll, and a later round is never inferred from an
  ordinary API retry.
* A first authenticated round may instead observe a settlement or governed
  repair result that the initial attempt already sealed.  Docket binds that
  exact terminal source cut and inserts the reservation and completion in one
  transaction; it makes no executor reconciliation call.
* Initial execution and a first explicit reconciliation round can overlap
  after custody is durable.  The round's claimed source cut remains immutable
  historical evidence.  If initial execution advances that exact cut to an
  indeterminate or terminal result before the round response is sealed, Docket
  completes the claimed round from the independently durable monotone result.
  It neither appends the superseded response nor calls reconciliation again;
  any effect reported by that response must already occur exactly in the
  durable cumulative journal.
* If the explicit round completes indeterminate first and the still-running
  initial execution then seals a terminal result, one exact next request may
  observe that terminal result locally.  It must bind the immediately
  preceding completed-indeterminate round and reconciliation identity.  This
  narrow terminal-observation exception is not another poll and makes no
  external call.  After a completed terminal round, all later rounds refuse.
* A reservation left claimed across a crash is unresolved.  Reopen does not
  reacquire it or silently call the executor when its source cut is unchanged.
  If initial execution independently established one of the exact monotone
  results above, replay may complete the round locally from that durable state.
  Arbitrary source-cut changes refuse.  Physical exactly-once behavior across
  process, host, database-copy, or executor boundaries remains an explicit
  nonclaim.

The round binds issuance, attempt, AG caller state, predecessor round/result,
checkpoint, executor binding, canonical request bytes, and Docket source cut.
Campaign and occurrence are transitively bound through the authenticated exact
issuance; they are intentionally not duplicated as caller-selected round
fields.
Its monotone reservation state is claimed then completed; all identity-bearing
columns are immutable.  Executor responses, cumulative journal append, and
round completion share one transaction.

Docket stores the exact canonical source-cut basis alongside its digest,
including the terminal result kind and identity when a first round observes an
already-sealed result.
Reopen strictly decodes and rehashes those bytes, joins the round signer to
the exact stored issuance signer, reconstructs its custody/checkpoint/executor
coordinates, and checks the immediate completed-indeterminate predecessor
chain.  A claimed round must either reproduce the same complete current source
cut or prove the exact monotone initial-attempt advance described above; a
completed round retains its historical cut and exact predecessor/result
references.

Migration 0012 is admitted only when the complete SQLite schema object set for
the round ledger exactly matches the migration-owned table, automatic indexes,
and trigger definitions.  A complete-looking but weakened table, inert trigger,
rebound trigger, extra object, or partial object set refuses on reopen.

AG and Docket use the existing pinned AG issuer trust boundary with a distinct
round-request schema and signature domain.  A raw CLI-selected identifier is
not round authority.  Docket recovery and AG restart paths observe durable
state only; only the explicit product round operation may cross the external
reconciliation boundary.

The AG-owned mirrored conformance corpus is pinned by manifest SHA-256
`74c429d8d32341fc31fba45e4cdd1a0b6d994bace4c7d4d8ccfccfc9dad8aded`.
Its reconciliation-round member is pinned by SHA-256
`408a2fe3ddf75621c43da441cbdcd33c7fe0845abadd9b02adc72038d01496fc`;
Docket's ordinary gate exercises its actual request, reservation, completion,
response, executor-envelope, identity, strict-decoding, and authentication
types against those exact bytes.
