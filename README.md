# Governed Work Runtime (gwr)

A local-first governed work runtime for exact AI-mediated repository effects.

The trusted runtime establishes mechanical facts only; domain modules own semantic
judgments; labor providers produce candidate artifacts and untrusted provenance. The
normative specification lives in `docs/governed-runtime/`.

Docket is **agent-neutral but currently Git-effect-specific**: exactly one effect class
is admitted — the atomic Git target-ref transition, `GitRefEffect` — and a proposal
outside it is refused with a typed refusal *before* any standing is issued, any
reservation is created, any dispatch identity is minted, or any provider runs
([`effect-classes.md`](docs/governed-runtime/effect-classes.md)). Recovery guarantees
are properties of that class and its stated premises, not universal Docket guarantees.

## Status

The audited baseline is frozen as [`gwr-greenfield-v0.1`](CHANGELOG.md) — a greenfield
comparison result, built without adapting any prior implementation. It is a working
runtime with a full audit record, not a production-hardened product. Work after the tag
(the first pilot, the canonical read surface, the explicit effect-class boundary) is on
`main` and recorded in the changelog; the tag has not moved.

**Read the trust model before relying on anything here.**
[`docs/governed-runtime/trust-model.md`](docs/governed-runtime/trust-model.md) states what
is enforced and what is assumed. Three assumptions are load-bearing and are premises rather
than guarantees: exclusive broker custody of the governed target ref, same-UID trust of the
labor provider and broker binary, and monotone clock readings. Several claims a reader
might expect to be enforced are deliberately written down there as premises instead.

## Where to start

| | |
|---|---|
| What it is and what it claims | [`greenfield-result.md`](docs/governed-runtime/greenfield-result.md) |
| The thirty invariants and their provenance | [`invariants-v0.md`](docs/governed-runtime/invariants-v0.md) |
| What is enforced vs. assumed | [`trust-model.md`](docs/governed-runtime/trust-model.md) |
| Current conformance classification | [`conformance-v0-second-pass.md`](docs/governed-runtime/conformance-v0-second-pass.md) |
| What it does not do | [`greenfield-known-gaps.md`](docs/governed-runtime/greenfield-known-gaps.md) · [`non-goals.md`](docs/governed-runtime/non-goals.md) |
| Test coverage | [`greenfield-test-matrix.md`](docs/governed-runtime/greenfield-test-matrix.md) |
| First governed execution (pilot) | [`pilot-01.md`](docs/pilot-01.md) · [`pilot-01-followup.md`](docs/pilot-01-followup.md) |
| The supported evidence/read surface | [`attempt-dossier.md`](docs/governed-runtime/attempt-dossier.md) |
| What effects are admissible | [`effect-classes.md`](docs/governed-runtime/effect-classes.md) |
| What each outcome means and what to do next | [`operator-runbook.md`](docs/governed-runtime/operator-runbook.md) |
| First upstream-authorized governed change | [`vertical-01.md`](docs/vertical-01.md) |
| How upstream authorization becomes local standing | [`upstream-authorization.md`](docs/governed-runtime/upstream-authorization.md) |

Documents cite an external "normative packet" as their requirements source. That packet is
held privately and is not part of this repository; the citations are to an external source,
not to missing files.

## Workspace

- `crates/gwr-core` — pure deterministic types and transition rules. No I/O.
- `crates/gwr-runtime` — use-case coordination and neutral ports.
- `crates/gwr-local` — SQLite, filesystem artifacts, provider adapters, Git broker,
  observations, CLI, clocks, identity generation.

## Verification

Four gates, all required:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test --workspace --release
```

Pass/fail is decided by exit codes, never by reading the tail of the output.

The release run is not redundant: a defect was shipped once whose behaviour differed
between build profiles — a `debug_assert!` panicked in debug on operator-supplied input
while release silently accepted it. Both suites must be green.

At the freeze this was 125 tests, identical in both profiles.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Vulnerability
reports should not be filed as public issues.

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
Attribution and authorship: [PROVENANCE.md](PROVENANCE.md).
