# Operator-beta AG systemd composition contract

**Recorded:** 2026-09-07
**Status:** `M1_DOCKET_COMPOSITION_CONTRACT__NQ_NG_RECONCILIATION_REVIEW_REQUIRED`

**Docket owner base:** `c49ad8d0f26fb2a13b9dbafdde84d7abfe1f867b`
**AG/Docket adoption integration result:**
`a05f7410cee0cca262d95ea198099f811091cc0f`
**AG M1A accepted result:** `92d274c299478a65121f2d8e1b93a2d00383a828`
**NQ-ng acquisition contract:** `e45c7b4bfb18ea740576a65f692b29f4390fbaff`
**NQ-ng helper accepted result (publication pending):**
`9d8624a2d13cb1562b55a81de6f6cea07fb65dcc`
**Release-basis acceptance:**
`2e9a7657c414bd6307efd09fa0104fc6fb92938c`

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

The admitted AG/Docket adoption pair is the accepted and published AG result
`a05f7410cee0cca262d95ea198099f811091cc0f` with exact Docket C2
`c49ad8d0f26fb2a13b9dbafdde84d7abfe1f867b`. That result contains the tested
AG integration merge `651d7178ef4a8950b9d9ac25c7d3fe496ed55f96` and preserves the separately
qualified M1A systemd owner result
`92d274c299478a65121f2d8e1b93a2d00383a828` as an ancestor. The adoption
integration witness does not reclassify either owner's earlier result; this
composition requires new evidence against the integrated pair.

The M1A result's qualified target-local package is
`agent-governor-ng-systemd-executor` version `0.1.0-1+m1a3`, archive SHA-256
`2852dc8a516980c4a1936d64a3a3f472d95fccf5eb3935f01a1be277f6b24f26`.
The package installs the feature-enabled process adapter only at
`/usr/libexec/agent-governor-ng/ag-effectd`, with executable SHA-256
`d2c021892d470d227548bf94ceb943d6b9457592176f289bd9864b40a3aeb460`.

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
The NQ-ng helper qualification result
`9d8624a2d13cb1562b55a81de6f6cea07fb65dcc` independently returned
`ACCEPTED / PROCEED` for implementation
`386358190e974c532d5237d36231fe7e806d100e`. It remains unpublished at this
checkpoint and establishes only the bounded helper, not an admitted M1B
package/VM result.

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

1. exact accepted Docket and AG result ancestry, executable/package digests,
   and target-local placement;
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

This contract requires independent review before a fixture or runtime edit.
The next lawful transition after acceptance is the smallest qualification
harness that composes the existing AG and Docket CLIs in an isolated resettable
environment. A Docket runtime change is allowed only if that exercise exposes
a concrete owner defect that existing interfaces cannot close.

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

This checkpoint is documentation only. Implementation and qualification are
`NOT_STARTED` until an independent audit accepts the exact contract subject.
