# Greenfield test matrix

State at freeze: **125 tests, 0 failures**, identical under `cargo test --workspace` and
`cargo test --workspace --release`. `cargo fmt --check` and
`cargo clippy --workspace --all-targets -- -D warnings` both exit 0.

Pass/fail is taken from the bare exit code of each command, never from reading its tail.

## By target

| target | tests | covers |
|---|---:|---|
| `gwr-core` unit | 17 | digest transcript order/label/version sensitivity and frozen vectors; attempt-identity binding; standing scope, expiry, consumption, **non-revival**; reservation exclusivity and consumption; lifecycle transitions |
| `bridges` | 10 | all four bridges: admitted crossings, refused crossings, unsupported versions, and the absent-crossing refusal value |
| `recovery_binding` | 8 | per-field binding of recovery facts; both positive verdicts; the degenerate result-equals-basis case; the original audit witness, now refused |
| `observation_cannot_rewrite_outcome` | 1 | a failing observation does not disturb a commitment |
| `gwr-local` unit | 2 | length-prefixed list encoding: round trip over control characters, and injectivity |
| `broker_path_authorization` | 8 | rename, copy, addition, deletion, in-place modification, multi-record patches, paths with spaces/quotes/newlines, empty transition sets |
| `git_broker` | 8 | envelope digest mismatch, basis moved, invalid patch, forbidden path, atomic compare-and-swap, journal inspection |
| `failure_injection` | 19 | nineteen named failure cases including real process death at every journal phase, provider death, late candidates, standing replay, wrong-basis ratification |
| `persistence` | 10 | immutable rebinding, optimistic versioning, typed ledger separation, projection reconstruction, schema boundary scans |
| `ratification` | 11 | digest binding, basis binding, scope mismatch, expiry, replay, token integrity |
| `reservation` | 4 | exclusivity, conflict refusal, expiry, one-use consumption |
| `provider_contract` | 8 | neutral port conformance for both fakes; provider substitution changes no core type |
| `provider_contract_codex` | 7 | the real `codex exec` adapter behind the unchanged contract |
| `vertical_slice` | 4 | the full governed slice end to end, including a real `cargo test` observation |
| `token_canonicality` | 4 | **N-2 regression** — non-canonical MAC tag spellings refused; canonical tokens round-trip for awkward repositories; tampered tokens refused; profile-independent by construction |
| `empty_observation_plan` | 2 | **N-3 regression** — typed refusal before anything runs; commitment, projection, version, and observation ledger untouched |
| `ref_custody_boundary` | 2 | **N-1 boundary specimen** — correct recovery under held custody; the *unsound* verdict under violated custody, asserted deliberately |

## Coverage of the eight adversarial findings

Every finding from the independent review carries a regression, and each was re-run
against the patched tree during the second blind pass.

| finding | regression | second-pass result |
|---|---|---|
| V1 broker path allowlist bypass | `broker_path_authorization` | refused `ForbiddenPath`; also re-run **end-to-end through the real CLI**, ref unmoved |
| V2 false `CommittedViaRecovery` | `recovery_binding` | invented result fields, edited journal, deleted journal, cross-attempt attribution — all refused with distinct typed refusals |
| V3 stranded acknowledged effect | `failure_injection` | re-verified with a true `SIGABRT` mid-`Dispatching`: re-entry settles to `Committed`, ref moved exactly once |
| V4 provider reads authority material | `provider_contract*` | workspace relocation confirmed; confinement explicitly not claimed |
| V5 persistence mutates admitted content | `gwr-local` unit | byte-for-byte round trip through real SQLite over control characters, CJK, empty |
| V6 permissive `Store` port | `persistence` | three illegal transitions refused `IllegalTransition`, projection and version untouched |
| V7 token serializer/parser disagreement | `token_canonicality` | awkward repositories round-trip; N-2 closed the remaining tag non-canonicality |
| V8 mutable authority objects | `gwr-core` unit | clone-and-widen does not typecheck; non-revival asserted directly |

## Properties exercised beyond per-finding regressions

- **Concurrency at durable boundaries.** Four threads racing one standing grant → exactly
  one spend. Four racing `reserve()` calls on a held ref → zero extra reservations. Four
  racing `dispatch()` calls → one commitment, one journal, three `AlreadyConsumed`.
- **Crash recovery around durable boundaries.** Real process death at each journal phase,
  and a real runtime death between persisting `Dispatching` and recording the outcome.
- **Malformed and non-canonical input.** Token payload and tag spellings, length-prefix
  lies, trailing bytes, truncated tags, non-hex tags, wrong keys; attempt content
  containing the former delimiter, colons, newlines, and multi-byte UTF-8.
- **Replay and substitution.** Standing use, reservation use, recovery resolution;
  recovery facts substituted across attempt, dispatch, repository, ref, basis, digest,
  journal, and observed ref.
- **Cross-attempt attribution.** A commit owned by another attempt cannot settle this one.

## Not covered by tests

Recorded rather than implied:

- The exclusive-ref-custody premise is **asserted, not verified**; its specimen documents
  the unsound case rather than defending against it.
- Same-UID confinement of providers is not claimed and not tested.
- Clock rollback is not prevented; no test asserts monotonicity.
- Invariant 30's missing-bridge refusal is constructed by tests, not produced by any
  runtime API.
