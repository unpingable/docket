# Contributing

## The four gates

Every change must pass all four. Pass/fail is decided by **exit codes**, never by reading
the tail of the output.

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test --workspace --release
```

The release run is not redundant: a defect was shipped once whose behaviour differed
between profiles. If you filter output, preserve the real status (`set -o pipefail`, then
read `${PIPESTATUS[0]}`) — a pipeline ending in `tail` or `grep` returns the last
command's exit code, not the test runner's.

Never claim tests pass without running them.

## What a change to an invariant costs

The thirty invariants in `docs/governed-runtime/invariants-v0.md` carry provenance tags:

- **`proved`** — a theorem or exhaustive enumeration exists externally and is cited by
  name. Must be enforced type-level or checked. A contradiction exposed during
  implementation is **reported, not resolved**.
- **`doctrine-unproved`** — binding; at minimum tested-only.
- **`implementation-choice`** — revisable with a recorded rationale.

If your change alters what an invariant enforces, update the invariant table and
`conformance-v0-second-pass.md` in the same commit. Do not rewrite historical
classifications in `conformance-v0.md`, which is marked superseded-in-part and retained
deliberately.

## Premises are not guarantees

Some claims rest on explicitly stated environment premises — most importantly
`ExclusiveRefCustody`, which underlies any verdict asserting non-occurrence. These are
asserted, not verified.

Do not quietly upgrade a premise to a guarantee. If you add real enforcement, update
`trust-model.md`, the invariant-table custody note, `RecoveryVerdict`'s documentation, and
`crates/gwr-local/tests/ref_custody_boundary.rs` together. That last file deliberately
asserts unsound behaviour under a violated premise; it is a boundary statement, not a
failing test awaiting repair.

## Reporting a defect against a claim

The most useful report is an **executable witness**: a test that constructs an accepted
execution violating a stated invariant. Prose findings are welcome, but a witness is what
gets acted on, and every finding in this repository's audit history was reproduced with one
before it was repaired.

Witnesses that turn on a documented scope boundary (same-UID trust, external ref mutation,
clock rollback) are still valuable — file them as documentation issues if any claim
overstates what the runtime enforces.

## Style

- Small, reviewable commits. Do not bundle refactors or renames into a repair commit; a
  diff that mixes them cannot be reviewed against the invariant it claims to fix.
- Separate documentation and publication commits from implementation commits.
- Domain types return typed refusals and do not panic on caller input. A panic reachable
  from operator input is a defect even when it fails closed.
- No `serde` or JSON in persistence: encodings are explicit, length-prefixed, and part of
  the store's schema. Digests are computed over explicit versioned transcripts; changing a
  field, label, order, or domain tag is a version bump, not an edit.

## Commits and history

Commit messages explain **why**, and state what was verified. Do not rewrite published
history. Do not move the `gwr-greenfield-v0.1` tag — it identifies the audited frozen
object, and later documentation commits are expected to sit after it.

## Security

Do not file vulnerabilities as public issues. See [SECURITY.md](SECURITY.md).

## Licensing

By contributing you agree that your contributions are licensed under the Apache License
2.0, as in [LICENSE](LICENSE).
