# M6 measurement-to-execution content continuity

Status: qualified with an explicit deployment limitation on
`campaign/measurement-execution-continuity`.

For a governed executor-plan/v3 occurrence, Docket's FreeBSD launch path no
longer executes the mutable source candidate directly. It reads the bounded
candidate bytes, creates an attempt-private regular vnode in Docket's state
directory, unlinks that vnode before population, writes and synchronizes the
candidate bytes, opens the same vnode read-only through `O_EMPTY_PATH`, verifies
the writer/reader device and inode identity and zero link count, closes the
writable descriptor, measures the read-only representation, and compares that
measurement with the opaque governed expectation. Only an equal representation
is retained and passed to `fexecve(2)`.

The qualified boundary is therefore:

```text
source candidate C
  -> private unlinked representation R
  -> measure H(R) == governed expected E
  -> close representation writer
  -> retain read/execute descriptor for R
  -> fexecve(R)
```

Changing the source pathname or overwriting the source inode after R has been
established does not change R. A fresh FreeBSD qualification occurrence changed
the source from A to B after the representation-ready witness; Docket retained
and launched A, the second-stage governed chain settled successfully, and B's
application-entry witness remained absent. A candidate that was B before
acquisition produced a B representation, mismatched the governed A expectation,
and was retained as an indeterminate attempt with no first-stage invocation,
second-stage launch, writer execution, or target change.

This is source-decoupled content continuity, not immutable storage. A controlled
fixture retained the private representation's writable descriptor, changed R
from A to B after measurement, closed the writer, and observed B execute. Keeping
the writer open made `fexecve` fail with `ETXTBSY`. The production path therefore
depends on the explicit custody invariant that no writable handle to R escapes
after finalization. It delegates only a rights-limited read/execute descriptor.
The result does not claim protection against process, kernel, or raw-device
compromise by an unrelated privileged actor.

FreeBSD sealed `memfd_create(2)` objects rejected writes as expected but were not
executable through `fexecve(2)` in the qualified 15.1 environment (`EBADF`). The
private unlinked regular vnode is the narrow stock mechanism actually qualified.
No FreeBSD source or kernel change was required.

Docket remains domain-neutral. The governed content is opaque exact work, not
provenance, authenticity, approval, or trust. Docket's own dynamically linked
bootstrap remains outside this custody boundary. Retained M6 evidence verifies
the exact expected/representation/attempt/dispatch/launch/effect relationships;
it does not replay historical kernel enforcement or establish later-state
causation.
