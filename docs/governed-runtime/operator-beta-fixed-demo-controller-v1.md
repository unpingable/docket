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
`constellation.operator_beta.fixed_demo_launch_spec.v1` at a caller-admitted
path, byte length, and SHA-256. The AG demo configuration must pin those three
values; the browser supplies none. The spec closes the scenario/run/root/unit,
three ports, 7,200-second bound, controller and owner subjects/trees, physical
controller-state directory identity, runner/harness identities, and all six
input paths/lengths/digests. The controller derives the complete runner argv.

The controller opens the pre-existing mode-0700 state directory by exact
device/inode/owner/mode and holds a no-follow regular-file `flock` while
starting. Before any user-systemd call it create-exclusively writes, fdatasyncs,
and directory-fsyncs the deterministic `launch-intent.v1.json`. Any existing
intent pathname, including a partial or invalid interrupted record, forbids a
second manager call. There is no retry/reset/delete operation.

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
