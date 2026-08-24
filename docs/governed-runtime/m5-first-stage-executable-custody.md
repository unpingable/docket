# M5 first-stage executable custody

Status: qualified on `campaign/first-stage-executable-custody`.

For one governed execution occurrence, Docket now treats the expected
first-stage executable content as part of the opaque exact work plan. Docket
does not decide whether those bytes are trustworthy. It preserves the plan,
opens the configured candidate, measures the already-open object, requires the
measured SHA-256 to equal the plan expectation, and on FreeBSD invokes that
same descriptor with `fexecve(2)`.

The lifecycle is:

```text
exact opaque work / plan-v3 expectation
  -> open candidate without following a final symlink
  -> hash retained descriptor
  -> compare expected and measured content
  -> persist attempt custody
  -> revalidate the retained descriptor
  -> fexecve the retained descriptor on equality
```

A mismatch is an effect attempt with an indeterminate outcome, not a completed
effect and not reusable authorization. Docket retains the attempt and the
expected/measured identities; it creates no launch record for a pre-execution
mismatch. Exact replay returns the existing attempt custody and does not launch
again.

`civil.managed-file.executor-plan/v3` is the domain artifact that supplies the
generic `governed_executor.expected_content` value. That value participates in
the exact opaque work digest. AG therefore continues to authorize exact opaque
work without learning executable-policy semantics. Docket checks structural
custody and equality only; the ManagedFileV1 adapter owns interpretation of the
domain plan.

Native FreeBSD qualification used a static first-stage executable. The selected
object has no ELF interpreter or shared-library dependency, so those dynamic
dependencies are absent from the first-stage object boundary. Docket itself is
dynamically linked and remains pre-custody runtime TCB.

## Qualified and limited properties

- A distinct valid executable whose content differs from the exact governed
  expectation is opened and measured, then refused before application entry.
- Replacing the pathname after Docket opens the candidate does not redirect
  descriptor invocation; the retained object is invoked.
- A different filesystem object with the same bytes is accepted because the
  qualified identity is byte-content identity, not inode identity or
  provenance.
- Missing, symlink, non-regular, and nonmatching malformed candidates refuse
  without downstream execution or target mutation.
- Docket revalidates content immediately before invocation, but stock process
  scheduling still leaves a final check-to-exec interval. A controlled
  privileged in-place overwrite in that interval caused the alternate bytes to
  begin executing from the same descriptor. This is not compare-and-swap and
  does not constrain unrelated privileged processes.

The last result is a deployment limitation, not a stronger identity claim.
The qualified relationship requires stable executable-object custody during
the operation. Content equality establishes neither origin, build provenance,
approval, authenticity, nor trust. Docket's attempt record is dispatch custody;
it is not independently observed application entry, writer success, target
state, or later civild observation.
