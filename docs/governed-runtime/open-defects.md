# Open defects and operator classifications

Findings from the Task 12 conformance audit (`conformance-v0.md`, fresh codex session,
2026-07-24) with the operator's ruling on each. Recorded here so the freeze gate has a
single place to check.

## Closed

### Invariant 8 — recovery facts bind the exact attempt and dispatch (`proved`)

**Was:** blocking correctness defect. `validate_fact_binding` compared only attempt,
dispatch, and prepared-attempt digest; `establishes()` compared the observed ref against
the fact's *own* `basis` field. The recovery artifact therefore carried both the
proposition and the comparison baseline, so validation degenerated into "does this
document agree with itself?" A fact naming the correct attempt, dispatch, and digest but a
foreign repository, ref, and basis was accepted and drove a false `ProvenNotCommitted`.

**Fixed 2026-07-24.** `AuthoritativeBinding` now carries the admitted attempt's own fields
plus the persisted dispatch identity; `validate_fact_binding` compares every semantically
binding field against it (new typed refusals `RepositoryMismatch`, `TargetRefMismatch`,
`BasisMismatch`), and `establishes()` takes the authoritative basis rather than the fact's
copy. `RecoveryStandingToResolutionV1` takes `&PreparedAttempt` instead of loose copies,
so checking a fact against anything but the real attempt is structurally impossible.
Regression suite: `crates/gwr-core/tests/recovery_binding.rs` — the audit witness
unchanged in construction (now refused), per-field independence, both positive verdicts,
and the degenerate result-equals-basis case.

## Open — operator-classified, not yet actioned

### Store prior/next validation — architectural exposure defect

`Store::record_*` methods accept a caller-supplied `AttemptState` and validate only the
optimistic version, never the prior/next pair. Lifecycle law is enforced in the service
path over a structurally permissive substrate. Operator ruling: *acceptable only if `Store`
is explicitly an internal trusted port that cannot be implemented or called by untrusted
code; if it is public extension surface, the invariant claims are overstated.* Choose one:
harden (validate the transition inside the store) or narrow the claims and the visibility.

Affects conformance rows 1, 2, 5, 6, 14, 16, 27, 29 ("checked but looser") and 11.

### Invariant 25 / clone-and-extend — expiry revival — **NOW THE FREEZE BLOCKER**

Re-audit of the patched tree (2026-07-24) classified row 25 `unenforced`, below the
`tested-only` minimum its `doctrine-unproved` tag requires, and it is now the sole freeze
blocker. Two revival paths:

1. **Clock rollback.** Expiry is judged by comparing the presented `now` against
   `expires_at`; no irreversible expired state is ever recorded. A backward clock reading
   makes a previously-refused record valid again. (Invariant 26 makes clock readings
   authoritative — an `implementation-choice` — so this is the cost of that choice.)
2. **Clone-and-extend.** `StandingGrant` and `ReservationClaim` have public fields; a
   caller using a bridge directly can clone an expired value, raise `expires_at`, and
   present it as valid. Only the persisted store path prevents that.

Existing tests assert that an expired record *refuses*, never that it does not *revive* —
which is precisely the distinction N7 names. Operator ruling: same authority-leak shape as
the store issue; **likely requires constructor/privacy hardening rather than more bridge
checks.** Minimum to unblock the freeze: a test asserting non-revival. Proper fix: private
fields with validated constructors, and/or a durable expired marker.

### Invariant 8 residual — journal digest and expected result unverified

The re-audit accepts row 8 as `checked` but notes a remaining looseness: neither the
fact's `journal_digest` nor its `expected_result_commit` is checked against a persisted
broker journal, and `Store::record_recovery_fact` accepts caller-constructed facts. A
correctly contextualized but self-authored expected result can therefore still drive a
`CommittedViaRecovery` when the ref happens to hold that commit. Narrower than the closed
defect (all six context fields must now match the real attempt), but the same family:
evidence partly self-authored. Not currently blocking; fix would verify the fact's journal
digest against the stored journal for that dispatch.

### N3 / invariant 30 — missing-bridge refusal is a protocol obligation

`RelianceRefusal::NoBridge` exists and unsupported *versions* are checked by each bridge,
but no runtime API accepts an undeclared crossing and produces the refusal; callers
construct it by convention (conformance row 30, `tested-only`). Operator ruling: **not
enforced; document as a protocol obligation unless you choose to encode it.** Documented
here.

## Independent adversarial review, 2026-07-24 — eight witnessed violations

A fresh reviewer, given the invariant table and the code but no prior audit narrative,
constructed accepted executions violating the claims. All eight carry concrete witnesses.
Priority order is the reviewer's, and it is the right one: V1 and V2 let an accepted
execution assert something false about the world.

**V1 — broker path allowlist bypassed by rename/copy diffs (invariants 1, 14, 15, 16).**
`patch_paths` (`broker/mod.rs`) takes only the `a/` side of `diff --git` and relies on a
`+++ b/` line that rename/copy patches do not carry. A governed run admitted with
`--allow src/lib.rs` committed a tree containing `evil/pwned.rs` and deleted the admitted
file; the journal shows the path check *passing*. Verified independently: `patch_paths` on
a rename patch returns `["src/lib.rs"]` and never examines the destination. Control with
the same path named directly is correctly refused `ForbiddenPath`.

**V2 — false `CommittedViaRecovery` for an effect that never landed (invariants 6, 8, 9).**
Attempt A crashed before `ref_updating` (ref never moved); attempt B then committed
legitimately. Editing one line of the plain-text broker journal makes A's recovery fact
claim B's commit as its expected result, and the bridge mints `CommittedViaRecovery` for A
— while the commitment table records that commit as B's. Two absent checks: the runtime
already stores `last_journal_digest` and never compares it (`AuthoritativeBinding` has no
`journal_digest` field, though `bridge-specifications-v0.md` lists it as a required
binding), and `establishes()` still derives the verdict from the fact's own `observed_ref`
and `expected_result_commit`. The second is exploitable **without touching any file**: a
fact with every checked binding copied faithfully and invented result fields is accepted.
This is the residual recorded above under "Invariant 8 residual" — the judgment that it was
"not currently blocking" was wrong.

**V3 — death inside `Dispatching` strands an acknowledged effect permanently.**
`dispatch()` persists `Dispatching`, then calls the broker. Kill the runtime in that
window with the ref already moved and acknowledged, and every exit is closed on restart:
`dispatch` returns `AlreadyDispatched`, `recover fact` refuses `NotIndeterminate`,
`observe` returns `NotFound`. `state-machine-v0.md` requires that a crash inside
`Dispatching` resolve to what the journal establishes, else `Indeterminate`; nothing
re-inspects the journal. Worse than indeterminacy: a definite, journal-acknowledged
commitment the ledger can never record.

**V4 — a labor provider obtains standing (invariant 24).** `docket.rs` puts the provider
workspace at `<state>/workspace`, one directory below `standing.key` and `state.sqlite`,
and passes it as the provider's `current_dir`. A substituted provider binary (a
substitution the codebase endorses for contract tests) read the HMAC key and the store,
minted a token, and the runtime accepted it. Real codex runs `--sandbox workspace-write`,
which limits writes but not reads. `populate_workspace` also reuses one fixed path, so
workspaces are not per-run disposable.

**V5 — admitted attempt content mutates at persistence (invariants 15, 16).**
`store/codec.rs` joins `allowed_paths`/`argv` on U+001F without escaping and `get_attempt`
re-splits and *recomputes* the digest. A path containing U+001F becomes two paths; the
attempt read back is a different object with a different binding digest, and the digest
printed at admission can never be ratified.

**V6 — the `Store` port persists any `AttemptState` with no successor check (invariant
27).** Demonstrated: `Prepared → Committed` with no dispatch row, then `Committed →
Prepared`, timeline recording the impossible sequence. Not CLI-reachable (services do cross
the bridges) — this is the port-boundary exposure already classified above, now with a
witness. Note `record_dispatch` *does* validate its claim, so the omission is inconsistent
rather than deliberate.

**V7 — `StandingTokenCodec::verify` reconstructs a different grant than `issue` signed.**
`payload()` interpolates `repository` unescaped into a `|`-delimited string; `verify`
splits positionally. A repository containing `|` authenticates with an attacker-chosen
`attempt_digest` and `expires_at`. Not forgery — the HMAC is intact — the parser and
serializer disagree about what was signed. Blast radius is limited today only because
`docket.rs` uses just `verified.id` and re-loads the real grant.

**V8 — `StandingGrant::validate` does not implement the non-revival its doc claims**
(invariant 25). Confirms the freeze blocker above and locates it: the invariant holds in
the persistence layer, not in the value object whose comment asserts it.

Unwitnessed but recorded by the reviewer: broker envelope is unauthenticated and
under-parsed (`attempt` and `prepared_digest` silently dropped, fields default to `""`);
`ObservationFailed` is returned before the claim check, implying an inadmissible claim
would have been admissible had the command passed; the persisted `prepared_digest` column
is never read; `DispatchIdentityConflict` is dead code; `reserve()` can orphan a claim;
`observe()` panics on an empty argv.

Held under attack, with witnesses: invariants 2, 3, 4, 5, 9, 10, 11, 12, 13, 18, 19, 21,
22, 28, 29, 30; digest transcript collision resistance; projection concurrency.

## Repair campaign, 2026-07-24 — status

| Finding | Status |
|---|---|
| V1 broker path allowlist bypass | **fixed** — authorization runs on `git diff-index --raw -z` over the temporary index and covers both endpoints of every transition |
| V2 false `CommittedViaRecovery` | **fixed** — verdict derived from `AuthoritativeBinding`; journal digest verified against the indeterminacy record; commit attribution checked |
| V3 stranded acknowledged effect | **fixed** — re-entry from `Dispatching` re-presents the envelope and settles from the journal |
| V4 provider reads authority material | **partially fixed — see below** |
| V5 persistence mutates admitted content | **fixed** — length-prefixed encoding, round-trip proved over control characters |
| V6 permissive `Store` port | **hardened** — the store validates the successor relation, not just the version |
| V7 token serializer/parser disagreement | **fixed** — one canonical length-prefixed transcript; every accepted parse must re-encode to the signed bytes |
| V8 mutable authority objects | **hardened** — private fields, `issue`/`claim` constructors, non-revival asserted directly |

### V4 remains open, and relocation is not the boundary

The workspace no longer sits inside the state directory: it is per-run, under
`GWR_WORKSPACE_ROOT` or the system temp directory, so `..` from the provider's working
directory no longer reaches `standing.key` or `state.sqlite`. A test drives a probe
provider through the real CLI and asserts from the runtime's own provenance log that
neither is visible.

**This is layout hygiene, and the operator's ruling already named it as such.** The defect
is ambient authority: a provider running as the same UID can still read the state
directory by absolute path. Closing it needs an OS boundary — separate UID, mount
namespace, or container — plus binding the provider executable's identity. That is not
implementable from inside this process and is the one item of the campaign that remains
open. Until it is closed, the honest claim is: *the adapter hands the provider no
authority, and no longer places it adjacent to authority material, but does not confine
it.*

## Second blind review, 2026-07-25 — findings and dispositions

A second blind pass re-ran the full invariant table and every recorded witness against the
patched tree, and reviewed the six changed seams starting from the claimed invariants
rather than the diff. Classification results: [`conformance-v0-second-pass.md`](conformance-v0-second-pass.md).

All eight repair-campaign fixes were confirmed by witness, including V1 end-to-end through
the real CLI (the in-repo regression for V1 is unit-level only and would not catch a
regression in the `diff-index` invocation itself). Concurrency held at every durable
boundary: four racing ratifications spent one grant, four racing dispatches produced one
commitment and one journal.

### Closed before the freeze

**N-1 — `ProvenNotCommitted` proved less than its name said.** Recovery derives the
verdict from a reading of the governed target ref. From "the ref holds the basis" the
runtime concluded non-occurrence — but an external rollback produces two observationally
identical states with different occurrence histories (the effect never landed; the effect
landed and was reverted). Endpoint equivalence laundering history. No retained evidence
separates them: `refs/gwr/*` carries no reflog under Git's default `core.logAllRefUpdates`,
verified empirically.

Fixed by making exclusivity an explicit premise of the verdict rather than unstated
background. `gwr_core::recovery::ExclusiveRefCustody` is a required field of
`AuthoritativeBinding`, so no code path reaches a verdict without naming it, and the
premise now appears in the invariant table, the verdict documentation, the recovery API
contract, [`trust-model.md`](trust-model.md), and this record. Reflog corroboration was
considered and rejected as a *repair*: it improves evidence but does not prove
non-occurrence, since retention, expiry, deletion, configuration, alternate mutation
paths, and repository replacement all remain assumptions. Real ref mediation is a later
deployment boundary, alongside provider confinement. Boundary specimen:
`crates/gwr-local/tests/ref_custody_boundary.rs`, which asserts the *unsound* behaviour
under violated custody — a statement of the boundary, not a check that the runtime
defends it.

**N-2 — standing-token MAC tags were non-canonical.** `u8::from_str_radix(_, 16)` accepts
uppercase, so an uppercase tag passed the constant-time verify and then hit a
`debug_assert_eq!` on the hex string: a panic in debug on operator-supplied input at the
authority seam (`docket ratify`, exit 101), and silent acceptance in release, where one
grant had two valid token texts. Fixed by requiring strictly canonical lowercase hex and
checking that every accepted token re-encodes to exactly the bytes presented — payload
*and* tag — in every build profile. The `debug_assert` is gone; a correctness mechanism
that disagrees between profiles is not one. Regression:
`crates/gwr-local/tests/token_canonicality.rs`, and the suite now runs under `--release`
as well as debug.

**N-3 — an empty observation plan stranded a committed attempt.** `observe()` indexed
`argv[0]` unguarded; `--observe ""` admitted an attempt that committed normally and then
panicked at observation (exit 101). Observation happens after commitment, so the property
that matters is not merely "no panic": a malformed invocation must not consume or strand a
committed attempt. Fixed at both ends — `ObserveError::EmptyObservationPlan` is returned
before anything is run and before any record is written, and the CLI refuses an empty
`--observe` at admission, since the plan is fixed at admission and can never be edited.
Regression: `crates/gwr-local/tests/empty_observation_plan.rs`, which asserts the
commitment, projection, version, and observation ledger are all untouched by the refusal.

### Open — recorded as post-v0.1.0 work, not blockers

These are looseness inside stated scope, not witnessed false claims. The distinction is
the one this campaign established and is worth keeping.

- **N-4** — `ObservationFailed` is returned before the claim check, so presenting an
  inadmissible claim against a failed observation implies it would have been admissible
  had the command passed.
- **N-5** — persisted reliance refusals retain only attempt, kind, detail, and time; the
  observation, consumer, and claim are dropped (row 21's value-level looseness).
- **N-6** — `StandingGrant::from_persisted` and `ReservationClaim::from_persisted` are
  public value-level constructors. No service path reaches them; every service loads
  grants from the store by identity. Encapsulation debt, not a live authority leak.
- **N-7** — `split_list` silently drops trailing bytes after the last well-formed element,
  so decode is not injective over hand-written column values. The digest is recomputed
  from the decoded value so no semantic drift is possible, but the stored
  `prepared_digest` column is still never compared on read.
- **N-8** — the broker envelope remains unauthenticated and under-parsed. Not charged as a
  defect: anything able to run the broker could run `git update-ref` directly, so it is
  not a privilege boundary. See [`trust-model.md`](trust-model.md) §1.

## Freeze gate

**Satisfied 2026-07-25.** The re-audit classifies no `proved`-tagged invariant as
`tested-only` or `unenforced`, and row 25 — the sole remaining blocker — is now
`tested-only`, the minimum its tag requires. N-1, N-2, and N-3 were closed before tagging.
