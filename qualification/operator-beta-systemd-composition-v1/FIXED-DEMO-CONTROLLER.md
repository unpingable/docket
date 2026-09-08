# Fixed demo controller implementation checkpoint

**Status:** `READY_FOR_INDEPENDENT_AUDIT`
**Accepted base:** `8ac6ea566c2b530f03ee307f0149d2e860fd2583`
**Live two-VM exercise:** `NOT_RUN`
**AG-hosted screen:** `NOT_STARTED`

This checkpoint adds only the Docket-owned one-shot launch/status adapter and
the missing terminal-refusal reopener defined by
`docs/governed-runtime/operator-beta-fixed-demo-controller-v1.md`.

Observed local evidence:

- focused controller/refusal gate: 21/21 cases passed;
- deterministic boundary substitution: refused with exit 1 after the same
  focused cases;
- composition qualification gate: 32 Python cases, Docket 17, AG governed
  loop 42 passed/1 intentional ignore, AG issuance 19, explicit packaged
  cross-process case, known-no-effect case, and retained owner identities
  passed;
- Docket workspace debug and release suites passed; the exact ordinary
  parallel release command was rerun to a clean pass after two earlier
  accepted-parent test-fixture races (`DispatchOutcome` timing and transient
  executable `ETXTBSY`) each passed on isolated rerun; a serial release run
  also passed;
- `cargo fmt --check` passed; and
- warnings-denied Clippy under Rust 1.98 remains `NOT_GREEN` on accepted-parent
  `question_mark` and `chunks_exact_to_as_chunks` lints outside this Python/docs
  delta. No lint suppression or unrelated Rust change is included.

No user-systemd unit, producer, VM, package installation, effect, provider,
publication, deployment, or production action was performed. The tests use a
local manager fixture and campaign-owned temporary files only. This checkpoint
does not qualify the future AG screen or the required fresh M2 end-to-end run.
