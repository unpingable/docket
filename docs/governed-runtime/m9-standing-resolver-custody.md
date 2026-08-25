# M9 external standing-resolver custody

M9 adds an opt-in FreeBSD-only exact-content launch mode for the external
execution-standing authority. It does not change either standing schema and it
does not move currentness or standing policy into Docket.

The existing `--standing-resolver PATH` mode remains unchanged. Exact mode is
selected only when both of these adjacent runtime options are present:

```text
--standing-resolver-content sha256:<64 lowercase hex>
--standing-resolver-journal /absolute/create-new/path.jsonl
```

The expected content is deployment/runtime custody configuration. It is opaque
to AG and is not evidence that the resolver is approved, authentic, or built
from particular source. In the qualified M8 composition, the outer bootstrap's
exact argv binding mechanically retains this value without acquiring standing
semantics.

On FreeBSD, exact mode performs this sequence before standing is admitted:

1. serialize the unchanged
   `docket.governed-loop.execution-standing-request/v1` request exactly once;
2. acquire at most 16 MiB from one absolute, regular, executable,
   non-group/world-writable resolver candidate without following the final
   symlink;
3. create a private unlinked execution representation with creator
   `docket_standing_resolver`;
4. close the sole writer, reduce the retained reader rights, and verify the
   qualified M7 write/reacquisition refusals;
5. measure that exact finalized representation and compare it with the runtime
   expected content;
6. refuse a mismatch before descriptor invocation;
7. pass the exact serialized request to `fexecve(2)` on that same retained
   representation;
8. capture exact stdout/stderr content hashes before decoding the unchanged
   standing response; and
9. append an `accepted` record binding the response to the exact Docket attempt
   only after the transactional custody insertion commits.

Sequential exact replay returns existing custody before resolver selection,
journal creation, or invocation. A launch or response failure never produces an
`accepted` journal record. Frozen Docket one-use and attempt semantics are not
changed.

## Journal contract

The create-new, mode-0600 journal is canonical JCS JSON Lines. Every entry uses
`civil.docket.standing-resolver-launch-record/v1` and binds:

- deterministic launch and issuance identities;
- exact request content and expected resolver content;
- source and private-representation content identities;
- representation device/inode/link count and M7 authority-closure record;
- invocation method and kernel descriptor-acceptance standing;
- exact stdout/stderr content identities and process status; and
- for the terminal `accepted` entry only, the exact standing resolution,
  currentness witness, execution standing, Docket attempt, and executor marker.

Stages are `prepared`, `refused`, `entered`, `completed`, and `accepted` as
applicable. Each record carries the SHA-256 content identity of the preceding
canonical record. The journal is bounded to eight entries of at most 128 KiB
each.

The fault-injection feature recognizes the paired absolute fixture paths
`GWR_M9_STANDING_RESOLVER_READY` and `GWR_M9_STANDING_RESOLVER_RESUME`. Production
builds omit this pause. It exists solely to qualify source/path replacement
after finalized representation measurement and before descriptor invocation.

## Explicit boundaries

M9 custody proves the selected executable-content and invocation relationship;
it does not prove resolver policy, provenance, authenticity, host truth, or
effect causation. Static linkage is a separate native qualification obligation:
the retained resolver artifact must have neither an ELF interpreter nor an
ordinary `DT_NEEDED` dependency. Offline evidence verifies retained identities
and journal structure; it cannot replay historical kernel enforcement.

## Qualification closeout

M9 closed **QUALIFIED WITH EXPLICIT DEPLOYMENT LIMITATION**. On stock FreeBSD
15.1-RELEASE-p2, the qualified static resolver content was
`sha256:d5c29db25899c9a130581ad8c667154e3e4fbefc4be96027ea2c676903ba28ab`.
The matching occurrence finalized, measured, and descriptor-invoked that exact
private representation. A valid static alternative
`sha256:a5e1d95c3d20db934842c91b58dc18380204f7b0dd458c73a2fb32200511af6c`
was measured and refused before application entry. Post-custody pathname
replacement and source-content change did not redirect execution; a distinct
object with byte-identical content was accepted.

One preliminary occurrence established an important receipt-loss boundary:
`waitpid(2)` was interrupted after the native effect completed, and the outer
bootstrap therefore retained no completion record. The consumed occurrence was
not reused. Commit `7371b637b0b39d4a80a7b7c07b981edf78c01964` makes the shared
descriptor-child wait retry `EINTR`; all fresh qualified occurrences and exact
replay controls used that correction. The later
`bbd7829109efdd46c16a39566d28e0da5bf6c908` change is test-only warning cleanup.

The retained verifier binds one exact query, resolver program, launch journal,
response, and Docket attempt. It deliberately does not establish the truth of
the standing response or that executable and stdin content are its sole inputs:
the frozen custody-directory and TTL environment inputs remain runtime inputs.
The bootstrap's initial invocation remains the declared root TCB.
