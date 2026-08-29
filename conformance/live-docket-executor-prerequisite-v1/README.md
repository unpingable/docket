# RIVER-CLERK — live Docket executor prerequisite v1

## Custody

- Campaign: `live-docket-executor-prerequisite-v1` (`RIVER-CLERK`).
- Source repository: `git@github-unpingable:unpingable/docket.git`.
- Remote-verified predecessor branch: `campaign/c2-governed-loop-layering`.
- Exact predecessor commit: `c49ad8d0f26fb2a13b9dbafdde84d7abfe1f867b`.
- Campaign branch: `campaign/live-docket-executor-prerequisite-v1`.
- The predecessor's frozen governed-executor dispatch/outcome wire is unchanged.

Frozen evidence SHA-256:

- `conformance/executor-transport-v1/corpus.json`: `3e58081f7cc36ecfad44ee9860c77ec5784b34c91e7c707d126f00ef778cf687`
- `conformance/executor-transport-v1/dispatch.schema.json`: `704c474e93e7bce83ea51fda38b8446ed1be95cd658db14c5bd5cb5c4a28fadd`
- `conformance/executor-transport-v1/outcome.schema.json`: `3851b2b43097936a3494ac6a43e26a2b5cb040e55847c867f05b62516ec0ca3f`
- `docs/governed-runtime/executor-transport-v1.md`: `b54f8db4d89c7e422733757f7a69b7fcc7420ce225f782f493c703c8e39e41a1`
- `docs/governed-runtime/executor-transport-c1-adjudication.md`: `1aca787c6cfe2704803082b0d16dee51795400194d7432f017d2c7ca326d27cf`
- `crates/gwr-local/migrations/0006_governed_loop_custody.sql`: `eefe9b084d1515086d3de3621c8b52a95a1603622f23482d2e700242bb7caeeb`

## Product

The campaign adds a Docket-owned explicit-invocation process host for the
existing governed-executor transport. It durably reserves an exact dispatch
before effect, separates `execute` from `reconcile`, binds plan identity to
adapter executable/configuration bytes, executes the retained native ELF file
descriptor, and keeps a durable inode-bound child-held operation fence across
host death. It adds no listener, service, default route, production activation,
AG/Codex wire, or NQ mechanics implementation.

The local native conformance adapter is a test fixture only. It verifies
reservation visibility and supplies deterministic refusal, cancellation,
outcome-unknown, replay, duplicate-key, content-mutation, pathname-replacement,
concurrency, and parent-process-death cases.

## Qualification disposition

The Docket-owned process host is locally qualified. RIVER-CLERK as a BEDROCK
prerequisite remains **INCOMPLETE** until the independently owned NQ/Bedrock
adapter and durable NQ claim/fence interface are implemented and the composed
boundary is independently qualified. No authority exists from this result.

Authority and actuation counts for this campaign are all zero:

- AG authorization issuance/acceptance/consumption: `0 / 0 / 0`.
- Docket production governed attempts/standing consumption: `0 / 0`.
- NQ claims/fences/live occurrences: `0 / 0 / 0`.
- Pods, production route changes, and approval responses: `0 / 0 / 0`.

The implementation qualification gates are recorded in `result.json`. The
exact committed campaign head and remote equality are custody facts reported
after the content commit and cannot be embedded in that commit without a
self-reference.
