# Fixed demo controller implementation checkpoint

**Status:** `CORRECTION_READY_FOR_INDEPENDENT_REAUDIT`
**Accepted base:** `8ac6ea566c2b530f03ee307f0149d2e860fd2583`
**Live two-VM exercise:** `NOT_RUN`
**AG-hosted screen:** `NOT_STARTED`

This checkpoint adds only the Docket-owned one-shot launch/status adapter and
the missing terminal-refusal reopener defined by
`docs/governed-runtime/operator-beta-fixed-demo-controller-v1.md`.

## Current correction custody — 2026-09-08

Independent review rejected `864c353cea7399153edc9d7fea4f24a420025a86`.
Corrections address fixed Docket admission, separate controller and
runner custody, retained acceptance validation, independent manager/OS
testimony, closed refusal outcomes/cohort, and bounded lock acquisition with
pathname revalidation. The focused gate currently passes 35 cases; its injected
control exits 1 after those cases. This is local evidence, not acceptance.

The implementation now selects the exact accepted `8ac6ea5` producer separately
from the current query-only checker. Production CLI arguments cannot select a
spec or its trust root. The physical installation spec and launch lock have not
been created. Execution now captures the exact admitted runner, builder and
NQ-ng module bytes into a bounded capsule held in the systemd execution argv.
The bootstrap mediates explicit dynamic imports from captured bytes and has no
campaign-source pathname fallback. Direct child-process qualification proves
replacement of all three paths after capture does not replace executed code;
capsule digest substitution refuses. A real frozen-cohort help invocation also
passes. Retained producer and checker identities remain separate.

Qualification was retained under user-systemd in campaign-owned
`/data/git/.campaign-artifacts/m2-controller-gates-001`, `-002`, and `-003`.
Each record binds the producer, script, before/after source diff and actual
exit codes; all source comparisons passed. Those executions are terminal.
Observed results: focused 34/34 and deterministic control exit 1; composition
45 Python cases plus owner regressions and packaged witness PASS, with its
control exit 1; debug workspace and fmt PASS; ordinary Phosphor 33/33 PASS.
The initial focused service run had an incomplete PATH and exited 127 after
tests; the corrected explicit-PATH run passed and preserves the earlier record.

The ordinary parallel release suite is **NOT_GREEN**: two runs failed inherited
Git fixture assertions in different tests. The first failing case passed alone;
the full serial release suite passed. Warnings-denied Clippy is also
**NOT_GREEN** on inherited Rust 1.98 `question_mark` lint debt. No Rust, Cargo,
or dependency file differs from accepted 8ac6ea5. These actual failures are
limitations, not silent passes. Independent review must assess the bounded
Python controller correction with those results visible.

After the full gate runs, the final narrow envelope change fixes the fresh run
root on `/data/git` to satisfy NQ-ng's 24 GiB free-space prerequisite and adds
the exact systemd 7200-second runtime/30-second stop limits. Focused cases cover
the final envelope. Final exact-subject re-audit remains required. Do not launch
a VM or present this checkpoint as accepted before that disposition.

The validator dependency is separately pinned by exact length/SHA-256 before
its captured bytes may be imported. A direct substitution case refuses before
import. This closes the corresponding query-side pathname substitution while
retaining the accepted producer identity. Full candidate 0e1fefc gates are
retained in `m2-controller-gates-004`; this subsequent narrow validator-pin
child requires its own independent disposition.

## Evidence at rejected checkpoint 864c353

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
