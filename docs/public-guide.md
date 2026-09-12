# Docket newcomer guide

Docket is a local-first runtime for keeping an exact Git-ref effect attempt
legible after authorization: it prepares the admitted work, dispatches through
its broker, and retains the result and recovery record. It does not decide
policy or grant permission. Those responsibilities stay outside Docket.

The public repository is `constellation-docket`; crate, binary, and protocol
identities retain their existing `gwr-*`, `docket`, and `gwr-git-broker` names.

## What this public main branch supports

The admitted effect class is the atomic Git target-ref transition. Docket is
agent-neutral but Git-effect-specific; proposals outside that class are
refused before standing, reservation, dispatch identity, or provider work.
The frozen `gwr-greenfield-v0.1` baseline and later `main` work are documented
in the [greenfield result](governed-runtime/greenfield-result.md),
[current conformance pass](governed-runtime/conformance-v0-second-pass.md),
and [effect-class boundary](governed-runtime/effect-classes.md). This is a
working runtime, not an operator-ready or production-hardened service.

## Build and inspect from source

From a clean checkout, build both required executables and inspect the local
command surface:

```sh
cargo build --locked --workspace
./target/debug/docket --help
test -x ./target/debug/gwr-git-broker
```

The `docket` and `gwr-git-broker` executables remain siblings unless
`GWR_BROKER_BIN` explicitly names the broker. There is no package-registry or
archive installation promise. Prerequisites, local state setup, and supported
source installation are in the [source installation guide](governed-runtime/source-install-and-bootstrap.md).

Read-only inspection begins with the checked-out command's `--help`. Existing
attempts can be examined with `docket show` and `docket journal`; the
[operator runbook](governed-runtime/operator-runbook.md) defines the result
states and their permitted next steps.

## Trust and recovery limits

Recovery can establish only what its evidence and premises support. A process
ending or an incomplete journal does not itself establish whether the target
ref changed. Inspect and reconcile the same attempt before considering a
successor. A `proven_not_committed` verdict remains conditional on the
deployment's asserted exclusive broker custody of the target ref. Same-UID
provider/broker trust and monotone clock readings are also deployment
premises, not guarantees supplied by this process. See the complete
[trust model](governed-runtime/trust-model.md).

The documents cite a private normative packet as provenance; it is not a
public installation prerequisite or part of this repository.
