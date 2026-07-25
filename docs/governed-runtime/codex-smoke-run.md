# Task 11 — live codex smoke run record

Date: 2026-07-24. One bounded live run, separately authorized by the operator. Automated
contract tests use a fake executable; this record is the only live testimony.

## Setup

- Provider: `codex exec`, codex-cli 0.145.0, invoked non-interactively
  (`-c approval_policy="never" --sandbox workspace-write --skip-git-repo-check --cd
  <workspace>`, stdin closed), bounded at 300 000 ms.
- Fixture: disposable Git repository containing a Rust crate whose test
  `canonicalizes_whitespace` fails at basis `ac209f7bdf7456ce19800de26f5a91e542143b7c`;
  dedicated target ref `refs/gwr/target`.
- Workspace: disposable detached clone at the exact basis, origin remote removed. The
  adapter received only the bounded assignment — no target credentials, no standing
  tokens, no reservation handles, no dispatch permits, no recovery authority.

## Transcript facts (mechanical)

| Step | Record |
|---|---|
| work request | `4181398554e9af45074300f8ac4514db` |
| preparation run | `076de36b6edaba01c3356b267c6b7891` — live codex, exit 0 |
| candidate | `1a760d5a3e0f6675a8296c46bb1e3b72`, digest `deb75ba392276cdc6abec9c40305667376810d23b20392f46fcce1f29cad5fe0` (computed by the runtime from `git diff` of the workspace; codex's own account of its work is provenance only) |
| attempt | `65abdba2fff569d3bcf8ad1f9abf8867`, prepared-attempt digest `cf69bfe7…d718e87` |
| ratification | `e45191d41753e7df6497bd48e46e50e2` (HMAC token verified, standing consumed once) |
| reservation | `0bbbff014bf22a35f308a8976577f449` |
| dispatch | committed; result commit `df067dd19197153923f1a2cca39607ffed3fa41c`, parent = basis; ref moved only through the broker |
| observation | `c3908d40100fc067ff1854281c028ecb` — `cargo test --locked canonicalizes_whitespace` against the exact result commit, exit 0 |
| reliance | `effect-and-command` admitted; `safe-to-merge` refused (`ClaimNotAdmissible`) |
| reconciliation | `HumanReviewBeforeMerge` retained |

Final state: `committed`, version 4, timeline
`admitted → ratified → reserved → dispatching → committed`.

## The candidate patch (exact bytes, ingested content-addressed)

```diff
diff --git a/src/lib.rs b/src/lib.rs
index d25556e..a220a4f 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,5 +1,5 @@
 pub fn canonicalize(s: &str) -> String {
-    s.to_string()
+    s.split_whitespace().collect::<Vec<_>>().join(" ")
 }
```

## Result

The real provider completed the existing vertical slice **without any change to
`gwr-core` types, core lifecycle, core schemas, receipt bodies, ratification,
reservation, broker, recovery, or reliance**. Codex's claim that its verification test
passed was recorded as provenance and not believed; the runtime's own observation
established the exit status independently.
