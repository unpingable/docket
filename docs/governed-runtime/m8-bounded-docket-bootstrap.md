# M8 bounded Docket bootstrap

M8 introduces `gwr-docket-bootstrap`, a deliberately small native FreeBSD
bootstrap around the existing Docket application. It is deployment-custody
plumbing, not a Docket domain service and not an authorization authority.

The bootstrap consumes `civil.docket.bootstrap-selection/v1`. That exact
selection binds a deployment-supplied expected Docket content identity and the
content identities of the governed input artifacts, plus canonical Docket argv
and stdin identities. Expected Docket content is deliberately not added to the
same occurrence's AG work: doing so would make Docket's own identity an input to
the application that admits the occurrence.

On FreeBSD the bootstrap reads a bounded no-follow regular candidate, creates
the M6/M7 private unlinked regular-vnode execution representation, closes all
writer descriptors, restricts the surviving reader, and only then measures the
exact representation. It refuses a mismatch before calling `fexecve(2)`. A
match is invoked from that descriptor; the candidate pathname is not resolved
again.

The JSONL journal schema is `civil.docket.bootstrap-launch-record/v1`:

- `prepared` binds selection, expected/source/private content, argv/stdin/env
  identities, representation identity, and the M7 authority-closure receipt;
- `entered` records that the kernel accepted descriptor invocation;
- `completed` binds captured child stdout/stderr identities and exit standing;
- `refused` identifies a pre-entry refusal.

Records are JCS bytes and form a chain: `prior_record_sha256` is `null` on the
first record and otherwise identifies the exact preceding JCS record. The
qualification harness retains the forwarded child stdout and stderr as
separate raw artifacts; the completed record binds their exact hashes (empty
streams are valid artifacts).

Raw child stdout and stderr are forwarded byte-for-byte after child completion.
The exact bounded stdin file is supplied to the child. `argv_sha256` is SHA-256
over an unsigned 64-bit big-endian argument count followed by each raw argument
as an unsigned 64-bit big-endian length and its bytes. `environment_sha256` uses
the same framing over lexically sorted raw `name=value` entries.

The bootstrap must be built and natively verified as static. Its initial code,
configuration, candidate open, input opens, private-representation creation,
and evidence-output setup remain a declared privileged initial TCB. Static
linkage does not make that code self-authenticating or self-custodied. The
dynamic Docket payload's runtime loader and shared libraries execute only after
the payload object has been selected and descriptor-invoked, and remain an
explicit post-custody runtime TCB. Host truth, provenance, causation, and
protection from unrelated privileged host activity are not established.

The `fault-injection` feature exposes one bounded native qualification point
after private-representation finalization and measurement and immediately
before descriptor invocation. Both
`GWR_DOCKET_BOOTSTRAP_CUSTODY_READY` and
`GWR_DOCKET_BOOTSTRAP_CUSTODY_RESUME` must name absolute fixture paths. The
bootstrap creates the ready marker exclusively and accepts only an exact
launch-identity resume marker within 60 seconds. Production builds omit this
feature and ignore these variables.

Build the production profile natively with
`scripts/build-freebsd-static-docket-bootstrap.sh`. Set
`GWR_BOOTSTRAP_FAULT_INJECTION=1` only for the controlled native custody
matrix. The script refuses non-FreeBSD and non-amd64 environments and retains
native `file(1)`, `ldd(1)`, and `sha256(1)` witnesses.

Non-FreeBSD execution refuses explicitly. The existing Docket domain, attempt,
transaction, and replay semantics are unchanged.
