# M7 execution-representation write-authority closure

Status: qualified with an explicit deployment limitation on
`campaign/execution-representation-authority-closure`.

M7 closes the governed writable-authority assumption left by M6. The FreeBSD
launch path creates exactly one writable descriptor for each private unlinked
execution representation. It populates and synchronizes that representation,
opens the exact device/inode read-only, verifies zero link count, then closes
the sole writer before content measurement. Only after that finalization does
it reduce the reader to `CAP_READ`, `CAP_SEEK`, `CAP_FSTAT`, and
`CAP_FEXECVE`, probe direct writing and `O_EMPTY_PATH|O_RDWR` reacquisition,
measure the representation, and invoke it with `fexecve(2)`.

The qualified ordering is:

```text
create/populate one private representation writer
  -> reopen exact vnode read-only
  -> close the sole writer
  -> reduce reader rights and probe non-writing authority
  -> measure finalized representation
  -> fork with only the read-only reader inherited
  -> fexecve the same reader
```

The authority receipt is
`civil.managed-file.execution-representation-authority-closure/v1`. It records
one created writer, zero writer duplicates, one pre-measurement close, zero
surviving or inherited writers, zero links, the surviving rights profile,
write/reacquisition probe results, and ordered finalization, measurement, and
invocation sequences. It is bound into Docket executor-binding/v4 and
executor-launch/v3 identities. Legacy M6 records remain exact binding-v3/
launch-v2 records; unresolved M6 custody is refused rather than silently
rebound as M7.

Native controls exercised the finalized reader, a `dup(2)` copy, and a
fork-inherited copy. None could write or regain `O_RDWR`; retained bytes were
unchanged. The qualified VM provided no writable `/dev/fd` alias and no
`/proc/curproc/fd` facility. M6's contrary control remains retained: a live
writer produces `ETXTBSY`, while changing A to B through that writer and then
closing it makes B execute. The M7 success therefore comes from closing all
writable authority created or retained by the governed mechanism, not from
treating the vnode as universally immutable.

Docket remains domain-neutral and dynamically linked before this custody
boundary. The receipt is an aggregate statement by the implementation, not a
kernel enumeration of unrelated processes. Native tests and traces qualify the
live mechanism; retained verification checks exact identities, counts, rights,
ordering, attempt/dispatch binding, and both launch stages. M7 does not claim
global immutability, unrelated-root resistance, provenance, authenticity, host
truth, causation, CAS, convergence, or production policy.
