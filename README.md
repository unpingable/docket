# Governed Work Runtime (gwr)

A local-first governed work runtime for exact AI-mediated repository effects.

The trusted runtime establishes mechanical facts only; domain modules own semantic
judgments; labor providers produce candidate artifacts and untrusted provenance. The
normative specification lives in `docs/governed-runtime/`.

## Workspace

- `crates/gwr-core` — pure deterministic types and transition rules. No I/O.
- `crates/gwr-runtime` — use-case coordination and neutral ports.
- `crates/gwr-local` — SQLite, filesystem artifacts, provider adapters, Git broker,
  observations, CLI, clocks, identity generation.

## Verification

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

Pass/fail is decided by exit codes.
