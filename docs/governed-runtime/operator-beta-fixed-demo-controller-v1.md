# Operator-beta fixed demo controller V1

**Status:** implementation checkpoint; live two-VM qualification `NOT_RUN`

This contract supplies the one missing launch/status seam for the operator-beta
M2 demonstration. It wraps the accepted composition qualification runner. It is
not a Docket product command, general scheduler, retry controller, campaign
authoring interface, or authority source.

## Owners

- Docket owns the fixed launch intent, launch-acceptance custody, and the
  query-only composition success/refusal reopeners.
- user systemd and the OS own live unit/process testimony.
- the NQ-ng harness owns `RECOVERY.json`, observations, VM lifecycle, and its
  refusal record.
- AG-ng owns authorization/spend and systemd effect evidence.
- the future AG-hosted M2 screen may render this projection but may not derive
  or replace any of these facts.

## One closed launch

The controller consumes one canonical newline-framed
`constellation.operator_beta.fixed_demo_launch_spec.v1` from its fixed installed
path `/var/tmp/constellation-operator-beta-m2-controller-run-002/fixed-demo-spec.v1.json`.
The CLI accepts only `start` or `status`; callers cannot select a spec, digest,
runner, occurrence, or input cohort. Docket code closes every semantic field
against `ADMITTED_COHORT`. The local installer supplies only physical directory
and lock identities, which are revalidated on every use. The mode-0400 installed
spec must belong to the invoking account. AG configuration independently pins
the controller code; it is not Docket's admission authority.
The spec closes the scenario/run/root/unit,
three ports, 7,200-second bound, controller and owner subjects/trees, physical
controller-state directory and lock identities, runner/builder/harness identities, and all six
input paths/lengths/digests. The controller derives the complete runner argv.
The fresh M2 run root is fixed at
`/data/git/.campaign-artifacts/constellation-operator-beta-composed-m2-run-002`.
This uses the filesystem with room for the accepted NQ-ng 24 GiB preflight;
earlier authoritative `/var/tmp` run archives remain in place.

The controller opens the pre-existing mode-0700 state directory by exact
device/inode/owner/mode and holds a no-follow regular-file `flock` while
starting. Before any user-systemd call it create-exclusively writes, fdatasyncs,
and directory-fsyncs the deterministic `launch-intent.v1.json`. Any existing
intent pathname, including a partial or invalid interrupted record, forbids a
second manager call. There is no retry/reset/delete operation.
The lock must already exist at its admitted device/inode; acquisition uses
nonblocking attempts with an explicit five-second monotonic deadline. Its
pathname and controller directory are revalidated before intent and manager
operations. Timeout is a controller refusal and creates no launch intent.

## Execution bytes and environment assumptions

The producer remains the accepted `8ac6ea5` composition runner, with its exact
adjacent builder and NQ-ng `9f1b081` harness. The newer M2 controller/checker has
a separate byte identity recorded in intent and status. Original owner records
retain the producer subject; no validator revision is substituted into them.

Before launch, the controller opens each of those three source files no-follow,
requires its exact length/SHA-256 and stable file metadata, and captures its
bytes. It compresses the canonical three-file map into a bounded ASCII argument
for `/usr/bin/python3 -I -B -c` under user systemd. The final encoded argument is
at most 100,000 bytes and decoded content at most 1 MiB. The exact argv vector,
capsule digest and bootstrap digest are bound into intent and compared to the
actual process command-line vector before acceptance.

The bootstrap verifies the capsule digest and framing, then supplies the three
modules through an in-memory loader mediating the runner's explicit
`spec_from_file_location` calls. It preserves original filenames and refuses
other dynamic campaign-module paths; it has no source-file fallback. Source
pathname replacement after capture cannot change executed campaign code.
Later Git checks may still refuse a changed checkout. Qualification executes a
real child after replacing all three source paths and requires captured output,
plus a digest-substitution refusal.

This bounded local environment trusts the host kernel, user-systemd manager,
Python interpreter/standard library, installed OS tools, and invoking account.
It does not claim confinement from another process that can modify that
account's process memory or the trusted platform. Repository files may change
concurrently; the capsule closes their validation-to-process-open interval.
Package/image inputs retain the accepted runner's existing hash and copy
validation. No new process-control or authority service is introduced.
The producer unit also sets `RuntimeMaxSec=7200` and `TimeoutStopSec=30`.
This encloses the accepted NQ cooperative runtime checks. Expiry does not
establish a terminal owner result: retained refusal must reopen, otherwise
controller status remains uncertain and forbids another launch.

After a successful manager reply, the controller requires an active exact
unit/InvocationID/MainPID, reads PID start ticks, argv, cwd, and the one admitted
spec-digest environment binding from `/proc`, and compares the resulting
execution record with the spec-derived record. Only then may it
create-exclusively synchronize `launch-accepted.v1.json`. The runner's NQ owner
record must later agree on run, unit, invocation, PID, and start ticks.

At every supervisor-loss cut, existing intent prevents a second launch.
Missing manager acknowledgement, an active matching unit without acceptance,
acceptance without runner custody, inactive nonterminal state, mismatched
records, and unavailable OS testimony remain distinct. `status` is query-only
and never repairs a record.

## Terminal reopening

The terminal projection distinguishes the producer of an authority record from
the checker that reopens it: a validated NQ-ng refusal has `owner: NQ-ng` and
`validator: Docket`; a validated composition success has `owner: Docket` and
`validator: Docket`. An indeterminate Docket checking diagnostic is not a
validated refusal record.

Successful terminal state is admitted only by existing `check-run`.
`check-refusal` reopens the exact physical run directory through the accepted
NQ owner loader, requires a closed canonical refusal, requires exact agreement
with the recovery record and admitted composition identities, and requires the
success result/manifest to be absent. It establishes refusal custody only: it
does not establish complete inventory, teardown, no effect, or success.

The source-labeled projection keeps durable state, live process testimony,
runner identity, disagreements, and release limitations separate. Phase never
implies liveness; process exit never implies terminality; an AG success receipt
never implies the current NQ postcondition.
`controller_custody` and `runner_durable` are separate. Missing/invalid intent
or acceptance remains a disagreement even when valid runner recovery or
terminal evidence exists. `live_sources` preserves manager and OS observations
independently, including inactive-manager/active-process disagreement. A
timeout, inaccessible query or invalid manager encoding is `NOT_OBSERVABLE`.
Retained acceptance fields are fully validated before any live binding,
including scenario, invocation format, positive PID/start ticks and exact
intent/execution digest, even after the process exits.

Evidence entries name their owner and retained path. Existing bytes are only
`RECORDED_UNVERIFIED` until terminal owner reopening establishes the chain;
missing or unobservable evidence is explicit. No narrative log parsing creates
domain state. Refusal reopening admits only the three actual composition effect
testimony states and their custody relation, with the frozen producer/input
cohort required. It does not claim teardown or no-effect qualification.

## Qualification boundary

Direct local cases must cover one-call concurrency, duplicate query-only
reopen, pre/post-intent interruption, acknowledgement loss, acceptance before
runner custody, process-identity disagreement, state/spec/intent/acceptance
pathname or content substitution, independent live/durable axes, exact refusal
reopening, and success-terminal disagreement. The existing composition and
Docket regression gates remain required.

No live VM, effect, deployment, production action, handoff, model/provider,
generic observability protocol, or UI implementation is qualified by this
checkpoint.

## Independently retained installation and execution identity

The reviewed controller contains literal `ADMITTED_SPEC_BYTES` and
`ADMITTED_SPEC_SHA256` values taken from the integration owner's enrollment
record. They bind the full canonical physical installation spec, including
state-root and lock device/inode/owner/mode. The CLI checks those independent
literals before constructing its controller. It never derives expected admission
from the bytes currently found at the installed spec path. Coherent replacement
of spec, state root and lock therefore cannot enroll another launch occurrence.
Absent enrollment is a refusal; replacement requires a separately reviewed
campaign decision and does not happen through `start` or `status`.

Execution testimony uses `__executed_source_sha256__`, computed from the bytes
the capture bootstrap actually compiles and executes. The AG adapter supplies
that marker from its retained, independently pinned controller bytes. Direct CLI
invocation captures and executes bounded no-follow source bytes and supplies the
same marker. `__file__` is a path hint, never a later executing-byte measurement.
An imported controller without this marker refuses to issue execution identity.

The installed/reviewed controller entrypoint, Python platform and invoking
account are trusted premises. Direct CLI capture identifies executing bytes;
it does not independently authorize arbitrary replacement code. AG's digest pin
establishes adapter delegation custody, not application authority. Docket owns
the fixed spec admission and one-intent law. Another same-UID process able to
replace the trusted entrypoint itself or modify process memory is outside the
declared premise; ordinary campaign source pathname changes remain covered by
the existing capsule controls.

Manager observation requires exactly the five requested properties, without
duplicates or malformed lines. Every property has a closed type/value check;
unknown future service state vocabulary is `NOT_OBSERVABLE`, never guessed as
process exit. PID/InvocationID are checked before process observation. Invalid
UTF-8 in manager output or relevant `/proc` execution fields also withdraws the
observation. A positive PID in a valid transitional service state still requires
the same `/proc` occurrence and execution checks before being shown as active.
