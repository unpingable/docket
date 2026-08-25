# M8 bounded Docket bootstrap

M8 introduces `gwr-docket-bootstrap`, a deliberately bounded native FreeBSD
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
qualified Docket payload is also static: the retained native profile has no ELF
program interpreter or ordinary `DT_NEEDED` shared-library startup dependency.
This removes that startup dependency class; it does not make executable bytes
the sole determinant of later process behavior.

Docket later pathname-executes the frozen standing-resolver fixture. That
interpreter/runtime transition is governance-support plumbing, not a native
effect-executor transition, and M8 does not claim content custody for it. The
qualification harness also uses outer SSH, `su`, Python, `truss`, and `env`
instrumentation before bootstrap application entry. Those processes do not
become part of the qualified effect-executable chain: the M8 result is
conditional on the retained static bootstrap profile having entered at the
declared outer launch boundary. It is not a claim that every executable in the
qualification process tree is descriptor-custodied. Host truth, provenance,
causation, and protection from unrelated privileged host activity are not
established.

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

## Qualification closeout

M8 closed **QUALIFIED WITH EXPLICIT DEPLOYMENT LIMITATION**. On FreeBSD
15.1-RELEASE-p2 the retained static bootstrap was
`sha256:1b23782ad784d551e32dab01284e2a2786d87035d6e004c567f340309d7177ca`
and the expected, measured, and descriptor-invoked static Docket payload was
`sha256:c7ae8a0c367ab4620e8a4bd5f37ed60e94af9259ea4acd3439b02648661b7d2d`.
A valid static alternative at
`sha256:a5e1d95c3d20db934842c91b58dc18380204f7b0dd458c73a2fb32200511af6c`
was refused before Docket application entry. Path and source-content changes
after custody continued to execute the retained Docket representation.

The qualified statement begins at static-bootstrap application entry. It does
not custody that bootstrap's initial invocation, Docket's later dynamic
standing-resolver transition, or qualification-only process ancestry. Expected
Docket content is deployment custody input, not AG authorization. The complete
retained evidence and offline verifier are owned by absd
`qualification/m8/`; controller closeout is owned by civild
`research/bounded-docket-bootstrap/`.
