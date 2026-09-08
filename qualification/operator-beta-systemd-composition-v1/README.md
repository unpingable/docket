# Operator-beta AG → Docket → systemd composition fixture

**Recorded:** 2026-09-08
**State:** `LOCAL_QUALIFICATION_GREEN__LIVE_COMPOSED_OCCURRENCE_NOT_RUN__INDEPENDENT_AUDIT_REQUIRED`

This directory is a qualification-only adapter around existing owners. It adds no
Docket runtime state, transport, effect family, daemon, retry controller, or product
package.

## Topology and exact inputs

- AG-ng exact owner `837de287497942c79966aa05c083acee9c312261`
  creates the decision, spends one authorization, signs the issuance, and owns the
  systemd plan/evidence/receipt.
- Docket exact C2 `c49ad8d0f26fb2a13b9dbafdde84d7abfe1f867b`
  authenticates the issuance, resolves fresh execution standing, and owns custody,
  attempt, marker, dispatch, settlement, reconciliation, and query-only inspection.
- NQ-ng exact published result branch
  `9f1b081b7fc5b2d99fb92ee6b0ac4107c7e7dfe4` supplies the VM lifecycle and fresh
  pre/post/restart observation. Its producer bytes are required to equal accepted
  run-012 harness `dc5d602484a4556c465df6947e98d81dba0d314a`.
- AG systemd package result `db4bad1fba2b5ab512cc58356314228167b2f48e`
  supplies exact `ag-effectd` SHA-256
  `668bdd26646ef6a5ba5502b64984844b84c1f70024a76eb5236af2b17702d068`.
- The governing Docket contract and current pins are accepted/published at
  `85ff185347e46ff2bf6168a6f300bbe4f94a5dbc`.

The target-only qualification package is:

```text
constellation-operator-beta-composition-fixture_0.1.0-1_amd64.deb
SHA-256 990dc8709862ffa5be429cde9ae16cb5c8d11dfcdce93567dc4af1b51987f8cb
```

Its canonical build receipt is SHA-256
`f07f2bb12f5a3f55888375cae5f384dd22b031c6fd70a624cc6fff3d676e0670`.
The package data archive is a closed root-owned 0755 layout containing only:

```text
/usr/libexec/constellation-operator-beta/docket
/usr/libexec/constellation-operator-beta/composition-driver
```

It installs no service, configuration, authority, state directory, or maintainer
script. `build_bookworm_fixture.py` binds exact AG and Docket heads/trees and lock
files, complete path/mode/content identities for both vendor trees, immutable
Bookworm builder image identity, network-disabled/offline commands and environment,
two independent clean builds, binary ABI/digests, package/control inventory, logs,
and the exact driver/builder sources. `verify` reopens those inputs and refuses
additional output files.

## Execution path

`run_composed_two_vm.py` loads the exact NQ-ng producer and overrides only the
composition-owned seams:

```text
NQ pre-observation
  -> composition-driver
  -> AG CampaignEngineV1 decision + one-use spend + signed issuance
  -> real `docket governed-loop accept`
  -> real `ag-effectd execute`
  -> Docket settlement / exact duplicate replay
  -> AG restart + Docket inspect + ag-effectd reconcile
  -> NQ post-observation
  -> NQ package lifecycle + guest restart + fresh observation
  -> AG owner store-cut audit + Docket query-only reopen
  -> package/fixture/VM teardown
  -> closed manifest and bounded disposition
```

The driver retains the exact AG authorization state/history/replay, issuance,
Docket custody/settlement/inspection, executor dispatch/outcome/evidence, and all
identity joins. It rejects a worker-level `SETTLED` marker unless the AG owner outcome
is `success`. The query-only checker independently reopens both archived occurrence
cuts, the AG attempt-store cut with accepted `audit-store`, the Docket state with the
retained exact Docket executable, all six NQ artifacts, boot changes, NQ backups,
current-support separation, and teardown evidence.

The maximum terminal claim is:

```text
ONE_SPEND_ONE_ATTEMPT_BOUNDED_EFFECT_CUSTODY_WITH_DECLARED_LIMITATIONS
```

It explicitly keeps `aggregate_postcondition=NOT_RECORDED`,
`literal_distributed_exactly_once=NOT_CLAIMED`, signed upstream checksum
`NOT_QUALIFIED`, and deployment/production `NOT_RUN`.

## Current qualification evidence

The local gate currently establishes:

- 10 direct builder/adapter cases, including closed receipt/inventory, path/mode/
  content substitutions, exact target invocation, worker/owner outcome disagreement,
  closed artifact inventory, and non-collapsed terminal dimensions;
- all 17 exact Docket governed-loop owner cases, including concurrent same-issuance
  convergence, standing/authentication/custody refusal, acknowledgement-loss/
  indeterminate reconciliation, substitution, restart, replay, and query-only inspect;
- Docket's four repository gates under Rust 1.94.0: formatting and warnings-denied
  all-target Clippy passed, and the complete debug and release suites passed when run
  serially. One parallel debug run observed a pre-existing local fixture
  `Text file busy` state-transition race; its exact case and the serialized suite passed;
- AG governed-loop 42 passed / 1 intentional fixture emitter ignored, and all 19
  issuance tests passed;
- two byte-identical offline Bookworm fixture builds and exact receipt reopening;
- one exact packaged, local known-no-effect occurrence: one AG spend, one Docket
  attempt, one settlement, exact replay/restart/reconcile, and an AG owner `failure`
  with only `get_machine_id_reply`, no job path/result, because the deliberately wrong
  machine identity refused before `StartUnit`; and
- a deterministic package-identity substitution control that refuses.

The accepted AG/Docket managed-file cross-process test is also invoked explicitly
with the exact retained Docket and AG binaries; it is no longer left at its normal
ignored default in this gate.

These results cover the non-live owner laws in the twelve-case contract matrix. They
do not establish the reset-VM success, composed archive, live method count,
restart/store-cut, or teardown. Those dimensions remain `NOT_RUN` until a clean
implementation checkpoint receives independent acceptance and a new run identity is
used. Earlier NQ runs 001–012 are never resumed, relabeled, or treated as the composed
occurrence.

## Local gate

The retained campaign paths are defaults; each may be overridden by the corresponding
environment variable in `check_local.sh`.

```bash
bash qualification/operator-beta-systemd-composition-v1/check_local.sh
COMPOSITION_INJECT_BOUNDARY_FAILURE=1 \
  bash qualification/operator-beta-systemd-composition-v1/check_local.sh
```

The first command must print `COMPOSITION_LOCAL_QUALIFICATION_PASSED`. The second
must return nonzero at the exact package-identity boundary after the direct tests and
owner suites pass.

## Next gate

1. Freeze a clean non-rewriting implementation checkpoint.
2. Independently audit exact source, package/receipt reproduction, local gate,
   deterministic negative control, and the claim boundary.
3. Only after acceptance, use a fresh run identity under the existing isolated
   user-systemd producer custody.
4. Independently reopen the terminal archive. A refusal or indeterminate result is a
   legitimate terminal outcome and must not be relabeled as success.

No publication, default-branch merge, deployment, target activation outside the
fixture, or productization follows from this checkpoint.
