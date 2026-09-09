# Operator-beta AG systemd composition contract

**Recorded:** 2026-09-07
**Status:** `RUN_002_ACCEPTED__CLOSEOUT_READY_FOR_INDEPENDENT_AUDIT`

**Docket owner base:** `c49ad8d0f26fb2a13b9dbafdde84d7abfe1f867b`
**AG/Docket successor reconciliation result:**
`44271684f6fb647620d8cade291814dadd08be18`
**AG store-audit owner:** `837de287497942c79966aa05c083acee9c312261`
**AG store-audit package qualification:**
`db4bad1fba2b5ab512cc58356314228167b2f48e`
**AG M1A accepted result:** `92d274c299478a65121f2d8e1b93a2d00383a828`
**NQ-ng acquisition contract:** `e45c7b4bfb18ea740576a65f692b29f4390fbaff`
**NQ-ng M1B result branch:** `9f1b081b7fc5b2d99fb92ee6b0ac4107c7e7dfe4`
**NQ-ng qualification closeout:** `5ea0a4be9f7aed0fb7f31db730b2db834957129b`
**NQ-ng harness subject:** `dc5d602484a4556c465df6947e98d81dba0d314a`
**Release-basis acceptance:**
`d968db4a1b9cda702e2e6167df605b16822f0b43`

This contract defines the narrow M1 composition between AG's already-qualified
systemd executor and Docket's already-qualified generic local executor
transport. It does not qualify that composition, authorize another effect,
deploy either component, or establish the target's current postcondition.

## Exact topology and ownership

The operator-beta effect path is:

```text
AG historical decision and one-use authorization consumption
  -> signed exact issuance
  -> Docket authentication and current execution-standing decision
  -> one Docket attempt, marker, executor binding, and dispatch
  -> target-local AG systemd executor V2
  -> executor-owned systemd evidence and terminal receipt
  -> Docket settlement or outcome-unknown reconciliation
  -> fresh NQ-ng observation (separate M1B owner)
```

AG owns the decision cut, authorization consumption, signed issuance, exact
subject/scope/work, and the systemd executor's plan, mechanics, evidence, and
receipt. Docket owns authentication of the issuance, its fresh execution
standing decision, canonical attempt and marker, exact executor binding,
dispatch custody, settlement, and reconciliation. The executor owns whether
its retained evidence supports `success`, `failure`, or `indeterminate`.
NQ-ng owns fresh postcondition observation. No component silently assumes
another component's authority.

The canonical Docket product is this repository. The sibling campaign/evidence
repository is not a product-code owner. This composition uses Docket's generic
`docket.governed-executor-transport/v1`; it does not add a systemd effect class
to Docket or import Docket's separate native Git-standing history by analogy.

## Admitted subjects and placement

The Docket side begins at accepted C2
`c49ad8d0f26fb2a13b9dbafdde84d7abfe1f867b`, whose implementation subject is
`f7a0018a9bf6ad95f6e3eb567e31e5a6f04c5428`. C2 retains the C1 transport bytes,
schema corpus, SQLite migration, and external behavior while placing the
transport-neutral law in `gwr-runtime` and local process/SQLite adapters in
`gwr-local`.

The admitted AG/Docket adoption pair is accepted and published successor result
`44271684f6fb647620d8cade291814dadd08be18`, whose exact AG owner parent is
`837de287497942c79966aa05c083acee9c312261`, with exact Docket C2
`c49ad8d0f26fb2a13b9dbafdde84d7abfe1f867b`. The AG owner descends accepted original
integration result `a05f7410cee0cca262d95ea198099f811091cc0f`, tested merge
`651d7178ef4a8950b9d9ac25c7d3fe496ed55f96`, and separately qualified M1A systemd owner
result `92d274c299478a65121f2d8e1b93a2d00383a828`. The fresh successor witness requalified
the managed-file adoption path only. It does not qualify this systemd composition or
reclassify any earlier result.

The current qualified target-local AG package was built from exact owner
`837de287497942c79966aa05c083acee9c312261` and is closed by package-qualification result
`db4bad1fba2b5ab512cc58356314228167b2f48e`. Its archive SHA-256 is
`98a4f31f0b6c13653ae95ce55586dbac6d0826b649cd7612882f3716b80e2279`.
The package installs the feature-enabled process adapter only at
`/usr/libexec/agent-governor-ng/ag-effectd`, with executable SHA-256
`668bdd26646ef6a5ba5502b64984844b84c1f70024a76eb5236af2b17702d068`.
The older M1A package and receipt remain predecessor evidence at their original subjects.

Docket state, Docket's local process, the AG governed-loop process that invokes
it, the AG executor process, executor plan, and executor attempt store reside
on the target VM. This is required by the accepted local-process transport and
by the executor's direct use of the local system bus. A controller may courier
exact admitted artifacts, retain receipts, and observe the target only through
separately qualified boundaries; it does not remotely impersonate AG's local
command port, proxy the system bus, or become effect authority.

Package presence alone grants no standing. Docket admits mechanics only after
authenticating one exact AG issuance, freshly resolving Docket-owned execution
standing, retaining custody, and verifying the pinned executor identity and
plan identity.

## Existing interfaces reused without semantic change

AG's `CommandDocketCustodyPortV1` invokes exactly:

```text
docket governed-loop accept
docket governed-loop reconcile-issuance
docket governed-loop reconcile-attempt
```

It binds the Docket executable, state directory, trust file, standing resolver,
executor executable, executor configuration, issuer principal, key identity,
and signing key through the accepted AG runtime profile. It signs the already
created issuance; a Docket resubmission never creates or consumes another AG
authorization occurrence.

Docket's accepted process boundary invokes exactly:

```text
ag-effectd plan-id CONFIG
ag-effectd execute CONFIG
ag-effectd reconcile CONFIG
```

For the beta, `CONFIG` is one canonical
`ag-effectd.docket-executor-systemd-plan/v2` document. Its work identity uses
`ag-effectd.docket-executor-systemd-work/v2`. Docket treats the plan contents
and the executor's typed receipt as opaque while retaining and checking the
exact executable digest, plan identity, attempt, marker, subject, scope, and
terminal outcome binding.

The existing `governed-loop inspect` operation remains the query-only Docket
read surface. It opens the existing database read-only, invokes neither the
standing resolver nor executor, and reports exact retained issuance,
authentication, custody, executor binding, status, settlement, or
indeterminate evidence. No composition-specific Docket state table or event
stream is authorized by this contract.

The operator selected NQ-ng for M1B after the original release-basis record
named classic NQ. The classic worktree and its exact results remain preserved,
but that lane is `SUPERSEDED_FOR_OPERATOR_BETA`. No classic-NQ implementation,
acceptance, or evidence transfers to NQ-ng. NQ-ng must establish its own exact
contract, implementation, package, fixture, and terminal qualification under
its owner gates. The eventual main-loop integration artifact may join only a
terminally accepted NQ-ng artifact whose applicability to the exact composed
occurrence has been mechanically verified. Docket neither consumes nor
reinterprets NQ-ng evidence.

## Bounded beta occurrence

The composition fixture admits one non-production action:

- machine: a retained Debian 12 fixture machine identity;
- unit: `constellation-beta-http-fixture.service`;
- action: `start`;
- expected prestate: `inactive` and `disabled`;
- executor lock timeout: 5,000 ms;
- executor job timeout: 30,000 ms; and
- one exact V2 plan, subject, scope, issuance, attempt, and marker.

The M1A run-004 owner result is predecessor evidence, not the composed
occurrence. Its known vector (`work` `976d8ebe...`, attempt `6099f35b...`, marker
`0457cbd8...`) demonstrates the executor-owned law but must not be replayed as
the beta composition. The composed qualification creates a fresh exact AG
decision/consumption and a fresh Docket occurrence against a reset local VM.

## Occurrence and provenance law

The composed record must permit an exact walk, without matching prose,
timestamps, filenames, or target names:

```text
AG decision cut
  -> AG authorization-consumed transition
  -> signed issuance identity and exact body
  -> Docket authentication and standing resolution
  -> Docket custody, attempt, marker, and executor binding
  -> exact six-field executor dispatch
  -> executor evidence and receipt
  -> exact four-field executor outcome
  -> Docket settlement or indeterminate record
```

The qualification retains the exact AG policy/evidence references actually
used at the decision cut where the authoritative AG history exposes them.
Original decision, independently reopenable historical warrant, and current
support remain separate. Missing historical material is `NOT_RECORDED`; an
unresolved or disagreeing authoritative source is `INDETERMINATE`. Current
policy, current evidence, or a newly reconstructed record cannot replace the
historical basis.

Docket and the executor do not copy or reinterpret AG policy evaluation.
Docket's settlement proves only its own custody and the executor outcome it
accepted. The executor receipt is enactment testimony, not proof of a current
postcondition. Only a subsequent fresh NQ-ng observation may support the
postcondition, and M1B remains independently qualified.
The accepted NQ-ng acquisition contract is
`e45c7b4bfb18ea740576a65f692b29f4390fbaff`.
The accepted/published NQ-ng mechanism result is retained by branch
`9f1b081b7fc5b2d99fb92ee6b0ac4107c7e7dfe4`, closeout
`5ea0a4be9f7aed0fb7f31db730b2db834957129b`, and harness
`dc5d602484a4556c465df6947e98d81dba0d314a`. Run-012 qualifies the bounded package,
two-VM observation, direct AG-owner effect, restart/reopen, store-cut, and teardown
mechanism cases with declared limitations. It explicitly leaves Docket database occurrence
and AG authorization consumption `NOT_RUN`, so it cannot serve as the composed occurrence.

## Failure cuts and reconciliation

Qualification must preserve these distinct results:

1. AG refusal before authorization consumption: no issuance, Docket attempt,
   dispatch, or mechanics.
2. AG decision accepted but consumption not committed: no signed issuance or
   Docket custody.
3. Consumption committed and Docket authoritatively reports `NotAccepted`: AG
   may resubmit the same signed issuance; it must not spend again.
4. Docket authentication or standing refusal before custody: no attempt or
   mechanics; retain the exact refusal evidence available at that boundary.
5. Docket custody committed but executor binding or process invocation fails:
   preserve the one attempt as outcome unknown/indeterminate.
6. Executor receives a new exact attempt but proves no systemd transmission:
   return its exact known-no-effect/failure receipt.
7. Systemd transmission may have occurred but complete effect evidence is not
   retained: return the executor's exact indeterminate receipt.
8. Executor atomically retains complete success evidence and terminal receipt
   but acknowledgement is lost: Docket reconciliation presents the same
   dispatch to `reconcile`; the executor reopens evidence and performs no
   mechanics.
9. Docket has already settled: repeat AG submission or Docket reconciliation
   returns the retained custody/settlement and performs no mechanics.
10. Docket outcome attempt/marker disagreement, executor program/plan change,
    missing owner evidence, or retained-row disagreement refuses fail closed;
    none may be repaired from current target state.

`reconcile` is query-only with respect to mechanics. It may complete Docket's
own settlement from the exact executor outcome for the already-custodied
attempt. It never creates an AG authorization, a fresh Docket attempt, or a
second systemd call.

## Strongest permitted composition claim

The maximum claim remains **one-spend / one-attempt bounded effect custody**:

- one AG authorization consumption in one authoritative AG history;
- at most one Docket standing/custody/attempt/marker for that issuance;
- one exact dispatch for that attempt;
- effectively-once executor enactment custody for that exact attempt; and
- same-attempt outcome-unknown reconciliation without another spend or
  mechanics occurrence.

These are separate local invariants connected by exact issuance, work,
subject, scope, attempt, marker, executor, evidence, and receipt identities.
They are not a distributed atomic commit, literal exactly-once physical
execution, guaranteed effect, global replay prevention, effect causation, or
proof of the current postcondition. Absence of an observed duplicate is not
sufficient evidence for any stronger claim.

## Qualification gate

The smallest qualifying implementation should prefer a campaign-owned fixture
and existing CLIs over Docket runtime changes. It must exercise and retain:

1. exact accepted Docket C2, AG owner/result, NQ-ng harness/closeout ancestry,
   executable/package digests, and target-local placement;
2. one real AG decision and one-use consumption producing the exact signed
   issuance consumed by Docket;
3. fresh Docket standing resolution, one custody row, one attempt, one marker,
   exact executor program/plan binding, and one exact dispatch;
4. one successful reset-VM effect with executor evidence/receipt reopen and
   Docket terminal settlement;
5. identical AG resubmission, Docket reconcile, executor replay, and process
   restart with byte-identical terminal results and no repeated mechanics;
6. concurrent same-issuance submissions converging on the one retained
   Docket occurrence;
7. refusal before custody, known-no-effect after executor admission, and
   post-transmission indeterminate cases kept distinct;
8. acknowledgement loss after executor commit but before Docket settlement,
   followed by same-attempt reconciliation;
9. issuer, issuance, decision/consumption, subject, scope, work, standing,
   attempt, marker, executor binary, plan, receipt, and evidence substitutions;
10. restart with missing or changed executor plan/evidence refusing rather
    than consulting current target state;
11. query-only `governed-loop inspect` reconstructing exact Docket state
    without resolver/executor invocation or mutation;
12. reset and teardown of all campaign-owned target state, stores, keys,
    packages, fixtures, forwarded listeners, and local VM processes while
    retaining bounded controller evidence.

The fixture must verify the actual method-call count, Docket row cardinality,
AG consumption cardinality, and exact stored bytes; process exit alone is not
evidence. Any dimension requiring unavailable live authority stops only that
dimension and is recorded `NOT_RUN`.

The Docket owner result may close on those twelve cases without claiming a
fresh postcondition. The complete M1 vertical later joins the accepted Docket
result to independently accepted M1B evidence and must additionally prove:

- fresh NQ-ng postcondition evidence is joined only through recorded
  exact subject, scope, and target identities; an unrecorded edge remains
  absent; and
- original decision, historical warrant, and current support remain separate
  when later observation or policy differs.

Those are composition acceptance conditions, not authority for Docket to
implement, reinterpret, or qualify NQ-ng.

## Current gate and non-goals

The original contract and current-pin correction are accepted and published at
`85ff185347e46ff2bf6168a6f300bbe4f94a5dbc`. The qualification-only fixture now
exists without a Docket runtime change. Its local tests, exact owner suites,
reproducible Bookworm package, and known-no-effect composed occurrence are green.
Accepted/published fixture checkpoint `ea9d394831ae5f640e8ea7bd5871b978bcce5e7f`
authorized fresh run `operator-beta-composed-m1b-run-001`. That run retained one
AG authorization spend, one Docket attempt/settlement, one successful owner effect,
fresh post/restart NQ evidence, and then refused at query-only AG store audit because
the fixture retained the canonical outcome without the owner CLI's terminal newline.
Run-001 is terminal and must not be resumed or relabeled. The framing correction must
receive independent acceptance before any distinct fresh occurrence. Full owner
store-cut acceptance, teardown, and a terminal composed result remain unestablished.

Not authorized here:

- a new Docket systemd effect family or transport version;
- a new AG authorization, standing, evidence, or receipt model;
- a distributed transaction coordinator;
- a second orchestration or persistence layer;
- production deployment, default-branch merge, or service activation;
- classic-NQ implementation, result transfer, or cutover;
- NQ-ng package, VM, provider, or production activation outside its accepted
  owner lane;
- worker/provider/model execution;
- UI controls or aggregate `authorized`, `executed`, `healthy`, or
  `exactly_once` status; or
- inference of missing provenance from matching content or timestamps.

The qualification-only fixture is implemented and does not change Docket product
runtime or transfer the separately accepted NQ run-012 result. Run-001 records a
Docket database occurrence, AG authorization consumption through Docket, and an AG
owner effect, but no terminal composed qualification. Full owner store-cut acceptance,
teardown, another occurrence, provider contact, deployment, and production remain
`NOT_RUN` pending correction qualification and independent acceptance.
