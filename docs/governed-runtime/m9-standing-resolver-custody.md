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
