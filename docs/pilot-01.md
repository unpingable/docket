# Pilot 01 — first governed execution

The first real governed execution of this runtime, run 2026-07-25 against **this
repository**, using the frozen `gwr-greenfield-v0.1` implementation with no behavioural
changes. This document was itself produced by the pilot and submitted through the runtime
as the pilot's final governed change.

The pilot's purpose was not to make the change. It was to determine whether an operator can
understand what happened from the runtime's public records **without reading implementation
code**.

## What was run

| run | purpose | outcome |
|---|---|---|
| A | normal complete execution | `committed` |
| B | crash after the effect lands, before settlement | `indeterminate` → `committed_via_recovery` |
| C | custody-boundary demonstration (**not** a defended scenario) | `proven_not_committed` for an effect that **did** land |
| N | can a non-Git effect be expressed at all? | `dispatch_refused` / `BasisMoved` |

Governed repository: this one. Target ref `refs/gwr/target` (`refs/gwr/custody-demo` for
run C). Admitted paths throughout: `docs/pilot-01.md` and `README.md`. Observation plan:
`cargo fmt --check`, executed in a detached worktree of the exact result commit.

### Run A — normal execution

```
work_request    1c804952ffd38f8ab1ad1ac6841e9e77
candidate       3292633be362854ed6c3a09e5afdc04c   digest 031bc3cf…1a43d
attempt         3651e1764023767cf70a15f5b32f2ce4
prepared digest c5439f5faf224a57bb2a6da6c00bddb2891acc2b2998e6f1df86c8361cfd93a0
grant           620eab999ac2f7e6fcba714dea95f121   (act: ratify, actor: jbeck)
ratification    8d632c125e1a980f2934c71da19f5073
reservation     369bf2e432cedb2fd19b101c741352f4
dispatch        8186b6b1a1b20a913e573fb52f954a1a
basis           72cb3b323fa286cd212378eadae4a42fe4dc093e
result commit   48002eed53e998ed5620d9b9574737cc989c3815
observation     3f8b700671aa335328f349ba6aec05e4   exit_status 0
```

The candidate digest equals the SHA-256 of the patch bytes. The commit touched exactly the
two admitted paths. Relying on the observation for the one admissible claim was admitted;
the same observation presented for `safe-to-merge` was refused `ClaimNotAdmissible`.
Reconciliation retained `HumanReviewBeforeMerge`.

Journal:

```
received / verified / patch_applied / paths_authorized / tree_written
commit_created 48002eed…  / ref_updating / ref_updated 72cb3b32… 48002eed… / acknowledged
```

### Run B — crash after the effect landed

Failure injected with the runtime's own documented hook,
`GWR_BROKER_CRASH_AFTER=ref_updated`, which aborts the broker process immediately after the
ref transition is journalled: the effect lands, the acknowledgement is lost.

```
attempt         2ccdcabaf092c1a1af7bcdf471220113
basis           48002eed53e998ed5620d9b9574737cc989c3815
result commit   7a5a861996f774d5b3aeb29f6e60a2e09bdecc69
recovery fact   77a3fa338b002b9ed75d42a8fd8bf6cb
recovery grant  4e3c93649b83ee5d0930f459b2e587fd   (act: resolve_recovery — separate authority)
```

Dispatch reported `indeterminate` and added: *"only recovery evidence plus recovery standing
resolves this."* The journal ended at `ref_updated` with no `acknowledged`. `recover fact`
read the world and reported `observed_ref` equal to `expected_result_commit`.
`recover resolve`, under a **separately granted** recovery standing, settled the attempt
`CommittedViaRecovery`.

**The ref moved exactly once.** One `ref_updated` line, one commit, and re-entry inspected
the journal rather than repeating the effect.

### Run C — custody boundary

**This run demonstrates a known-unsound case. It is not a successful recovery test and not a
defended property.**

After the effect landed at `a35d82b70f0907c3f4b93664f69fc1a7d89328a1`, a writer other than
the governed broker reverted `refs/gwr/custody-demo` to its basis — violating
`ExclusiveRefCustody`. Recovery then settled the attempt:

```
attempt  4aa7e08db7697b885bd98e2d134f8149   →  proven_not_committed
ground truth: commit a35d82b70f0907c3f4b93664f69fc1a7d89328a1 exists and holds the effect
```

The runtime recorded non-occurrence for an effect that occurred. This is the boundary
documented in [`trust-model.md`](governed-runtime/trust-model.md) §2 and asserted as an
executable specimen in `crates/gwr-local/tests/ref_custody_boundary.rs`. Both the ref and
the ledger record were preserved rather than reconciled: `refs/gwr/custody-demo` now points
at the landed commit while the ledger says `proven_not_committed`, and that disagreement is
the evidence.

### Run N — expressing a non-Git effect

An attempt to describe *"send a notification that the pilot finished"*:

```
target_ref 'mailto:ops@example.com'   accepted as a ref name
empty patch                           accepted as a candidate (digest e3b0c442… = SHA-256 of "")
attempt e21028af6efa837a2e20470ddee9830a   ratified, reserved, dispatched
outcome: dispatch_refused   ground: BasisMoved
```

Nothing external happened, and no authority leaked — but the runtime never said *"this
effect class has no admitted description."* It carried a nonsense effect through admission,
**spent real standing and a real exclusive reservation on it**, and refused it many steps
later with a mechanical Git refusal that explains nothing about why.

## Operator-legibility review

Conducted from CLI output, receipts, and published documentation only.

**Caveat that limits this review:** it was performed by the same agent that audited the
implementation, so genuine first-encounter legibility was not testable here. The findings
below are visible from the public surface, but the *absence* of a finding is weak evidence.
A fresh reader would be a better instrument.

| question | answerable? | from what |
|---|---|---|
| What was proposed? | **no** | the goal is captured at `request create` and never displayed again |
| Who authorized it? | **no** | the actor is bound into standing and the ratification receipt; no command prints it |
| What paths and repository state were admitted? | **no** | `--allow` paths, basis, repository, and target ref are not shown after admission |
| Did the effect execute? | yes | terminal state |
| Normally or via recovery? | yes | `committed` vs `committed_via_recovery` are distinct terminal states |
| What evidence supports the verdict? | **partly** | result commit and journal digest are printed once at dispatch time and never again |
| Which conclusions depend on premises? | **no** | nothing in CLI output mentions custody, and `proven_not_committed` carries no qualifier |
| What to do after a refusal or uncertainty? | **partly** | `indeterminate` prints a helpful note; `dispatch_refused` prints only a ground |

### Findings

Classified as *missing mechanism*, *false/overstated claim*, *missing receipt data*, *poor
presentation*, *documentation gap*, or *expected consequence of the declared trust model*.
None was fixed during the pilot.

**P-1 — the receipts exist but are not readable. (poor presentation)**
`docket show --json` returns state, version, timeline, an obligation *count*, and
observations. It does not return the goal, actor, repository, target ref, basis, admitted
paths, result commit, or journal digest. All of that is recorded in the store and in the
typed ledger; none of it has a read path. An operator reconstructing what happened must
either scroll back through dispatch-time stdout or open `state.sqlite` directly. This is the
largest gap between what the runtime *knows* and what it will *tell you*, and it is
presentation, not mechanism — the data is already there.

**P-2 — `proven_not_committed` is displayed without its premise. (poor presentation,
bordering on overstated claim)**
The custody premise is encoded in the type system and stated in the invariant table, the
verdict documentation, the API contract, the trust model, and the freeze record — and
appears nowhere an operator will actually look. `docket show` prints
`state proven_not_committed`, unqualified. The word "proven" does the opposite of the work
the premise does.

The discriminating evidence *was* visible, one command earlier: `recover fact` printed
`observed_ref` and `expected_result_commit` as **different values**. That disagreement is
exactly the signal that custody was violated, and it is discarded from every subsequent
surface — the resolution prints only the verdict, and `show` prints only the state. A
warning at that point would cost little.

**P-3 — the recovery verbs are undiscoverable. (documentation gap)**
The CLI's own error text lists thirteen commands and omits `recover fact` and
`recover resolve`. An operator told by `dispatch` that "only recovery evidence plus recovery
standing resolves this" cannot find the commands that do it from the CLI.

**P-4 — no effect-class boundary. (missing mechanism)**
Run N. The runtime has one effect vocabulary — a Git ref transition backed by a patch — and
no way to say so. A caller proposing something outside it is not refused as inexpressible;
it is admitted, ratified, reserved, and refused at the broker on Git's terms. Authority is
spent before the category error is detected. Fail-safe, not fail-legible.

**P-5 — the candidate was operator-authored. (limitation of this pilot, not a defect)**
Runs used the scripted provider via `--fake-patch`, so the pilot exercised the governance
path but not the labor path. The real `codex exec` adapter exists and was exercised
separately ([`codex-smoke-run.md`](governed-runtime/codex-smoke-run.md)); it was not used
here because the pilot needed a specific, predetermined change.

**P-6 — governed commits are authored by the broker. (expected consequence)**
Commits carry `gwr-broker <broker@gwr.local>` and a fixed 2000-01-01 date, which is what
makes the result commit a deterministic function of the admitted attempt. Reviewers reading
`git log` will see neither the proposing agent nor the ratifying actor. Correct by design;
worth knowing before it surprises someone.

**P-7 — custody violation is undetectable after the fact. (expected consequence)**
Confirmed empirically: `refs/gwr/*` gets no reflog under Git's default
`core.logAllRefUpdates`, so nothing retained distinguishes "never landed" from "landed and
was reverted." Already recorded in the trust model; the pilot confirms it in practice.

## Verdict

**Usable reference implementation; not yet operator-ready.**

The governance machinery did its job. Authority was bound to exact content and consumed
once. A crash that landed an effect and lost its acknowledgement was recovered to the
correct terminal state under separately-held standing, with the ref moving exactly once. A
broader claim on a real observation was refused. The residual obligation survived
completion. Nothing leaked, nothing was lost, nothing was fabricated.

What is missing is not mechanism but **read access**. An operator cannot presently answer
"what was proposed, by whom, over which paths, and on what evidence" from the CLI, and the
one verdict that depends on an environmental premise is displayed without it. Those are P-1
and P-2, and they are the difference between this and an operator-ready tool. Neither
requires new governance; both are surfacing work over records that already exist.

P-4 is the finding with consequences beyond presentation. It says the membrane is
**agent-neutral but not effect-neutral**, and that the boundary of the effect vocabulary is
currently invisible from outside. Any adapter that widens what agents may propose will meet
this first.

---

*Record produced by the pilot it describes and submitted through the runtime as its own
final governed change. Command transcripts, journals, and full identifiers for all four
runs are held in campaign custody outside this repository.*
