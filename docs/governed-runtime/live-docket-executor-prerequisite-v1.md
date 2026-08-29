# RIVER-CLERK local Docket executor process host

## Campaign boundary

RIVER-CLERK starts from the remote-verified canonical Docket source
`c49ad8d0f26fb2a13b9dbafdde84d7abfe1f867b` on
`campaign/c2-governed-loop-layering`. It preserves the frozen
`docket.governed-executor-transport/v1` dispatch and outcome objects and adds
one reusable local process host:

```text
docket-governed-executor plan-id CONFIG
docket-governed-executor execute CONFIG
docket-governed-executor reconcile CONFIG
```

This is the Docket half of BEDROCK's executor prerequisite. It does not include
the separately owned NQ/Bedrock adapter, create an AG issuance, consume
execution standing, create a Pod, or activate a route.

## Configuration and plan identity

`CONFIG` is a strict JSON object with schema
`docket.local-governed-executor-config/v1` and these required fields:

| field | meaning |
| --- | --- |
| `state_database` | absolute path of the host's durable SQLite attempt journal |
| `work_schema` | exact adapter work schema |
| `subject` / `scope` | exact governed digest bindings |
| `adapter_program` | absolute executable, regular and not a symlink |
| `adapter_config` | absolute adapter-owned configuration, regular and not a symlink |

The returned plan is the existing Docket domain-separated SHA-256 construction
over canonical JSON containing every configuration field plus content digests
of the adapter executable and adapter configuration. The mutable state
database's path is bound; its changing contents are not. `plan-id` reads and
measures only and does not create the state database.

Docket already binds its selected executor executable bytes and returned plan
identity. It calls `plan-id` before standing consumption and again after
custody is durable but before executor delivery. The host independently
recomputes its plan for every execute and reconcile operation. A changed
configuration or adapter therefore no longer matches the dispatch `work`.

## Adapter interface

The host accepts only a native ELF adapter. It stages the exact measured bytes
under a digest name in a `0700` campaign-owned directory, opens and verifies
that object once, and executes that retained object through `/proc/self/fd/N`.
A later staged-path replacement cannot change the executable object already
selected for invocation.

The internal Docket-to-adapter call is:

```text
ADAPTER execute
ADAPTER reconcile
```

Adapter stdin is exactly an eight-byte big-endian configuration length, the
already measured adapter-configuration bytes, then Docket's canonical closed
V1 dispatch JSON. No mutable configuration pathname is passed after plan
resolution. The adapter must return Docket's unchanged closed V1 outcome on
stdout. Documents remain bounded to 1 MiB. This internal framing adds no AG,
Codex, Bedrock, or NQ wire.

`execute` is the sole adapter operation permitted to invoke mechanics.
`reconcile` may read retained evidence and may not invoke mechanics. The host
cannot prove the adapter's application semantics, so every concrete adapter
and its permission set requires independent qualification.

## Ordering, replay, and settlement

The composed ordering is:

```text
authenticate exact AG issuance
-> resolve executor plan
-> consume Docket execution standing
-> persist exact Docket custody
-> remeasure executor plan and program
-> host durably reserves exact dispatch
-> adapter execute
-> host durably records exact outcome
-> Docket durably records settlement or indeterminate evidence
```

The host's SQLite transaction commits `dispatched` before adapter entry. The
reservation also binds the device and inode of a private per-attempt operation
fence. A process-local immediate SQLite transaction prevents a second host
operation while the first host remains live. The exact framed input file is
exclusively locked and inherited as adapter stdin, so the child retains that
lock if its host dies. Reconciliation refuses before adapter entry until the
child exits. A replaced fence pathname resolves to a different durable identity
and refuses; a hard link to the same object retains the same lock. A
second `execute` for a dispatched attempt refuses with reconciliation
required and cannot call mechanics. A terminal replay returns the identical
stored outcome. Any changed plan, marker, work schema, work, subject, or scope
refuses before adapter access.

An adapter transport refusal, malformed or oversized response, changed outcome
binding, or terminated process leaves the durable dispatch reservation without
a claimed result. Docket therefore retains its existing indeterminate posture.
A later `reconcile` uses only the adapter's reconciliation operation and may
settle from qualified evidence. A known outcome cannot be replaced; a retained
indeterminate result may be upgraded to a known result.

The host does not infer success from an adapter exit code. Success, failure,
and indeterminate exist only in a valid, exactly bound V1 outcome document
whose receipt is a canonical digest.

## NQ/Bedrock consumer requirements

The independent NQ integration owner must provide and qualify an adapter that:

1. accepts only NQ's exact prepared-occurrence work schema and verifies
   dispatch `work`, `subject`, and `scope` against the sealed plan;
2. verifies Docket `attempt` and `marker` against NQ's exact authorization
   and durable claim/fence bindings before mechanics;
3. on `execute`, loads an already-durable claimed occurrence, invokes
   `ExecuteMechanicsV1::execute` at most once, and persists the resulting NQ
   state and evidence before returning;
4. maps proved success to `success`, proved non-occurrence or a definite
   terminal failure to `failure`, and every unresolved result to
   `indeterminate`;
5. on `reconcile`, loads retained state and calls only the
   `ReconcileEvidenceV1` path—never claim, release, Pod creation, or execute;
6. makes the returned receipt digest identify retained terminal or uncertainty
   evidence and preserves exact attempt/marker binding;
7. passes substitution, replay, terminated-process, outcome-unknown, and
   reconciliation cases with no live route.

The adapter depends on the independently qualified durable NQ claim/fence
interface. Until both exist and are qualified together, RIVER-CLERK is not a
complete BEDROCK prerequisite.


## Permission and activation boundary

The state database, staged executable directory, and operation-fence directory
must be beneath a nonsymlink directory with no group or other access. State is
opened with `O_NOFOLLOW`; the retained descriptor's device/inode is compared to
the named object before and after SQLite initialization. This is an explicit
same-UID private-directory permission-boundary assumption, not a claim of
absolute confinement from every same-UID writer after those checks.

Executable selection is stronger: the exact opened ELF descriptor is carried
through `exec`, so later source or staged pathname replacement cannot select
new bytes. The child-held operation fence is stronger across host death: its
durable device/inode binding makes substituted fence pathnames fail closed,
and its inherited open-file lock prevents reconciliation overlap with live
mechanics.

No service unit, listener, default route, production configuration, or
automatic activation is added. The binary runs only by explicit invocation.
