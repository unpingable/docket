# Canonical governed-repair custody development ledger

Status: development scope record; not standing, qualification, or authority.

This Docket custody seam was built under external human development
authorization. It did not govern its own construction. NQ records used in tests
are immutable hostile fixtures, not reconstructed Docket custody or execution
authority.

The initial design confined Docket to exact AG issuance intake, one execution
custody/attempt, in-scope effect journaling, immutable checkpoint binding,
sealed scope-expansion or readjudication results, typed pre-custody refusal,
and replay/reconciliation. Approval and NQ diagnostic meaning remain outside
Docket.

## Final Docket path census

- `crates/gwr-core/src/governed_repair.rs`: pure exact-scope and governed-result
  contract.
- `crates/gwr-local/src/governed_loop.rs`: canonical intake, custody, attempt,
  execution, typed refusal, sealing, replay, reconciliation, and hostile tests.
- `crates/gwr-local/src/store/mod.rs`: migration registration.
- `crates/gwr-local/migrations/0009_governed_loop_refusal.sql`: append-only
  refusal plus custody/refusal exclusivity and pre-existing-custody backfill.
- `crates/gwr-local/tests/campaign_burn_concurrency.rs`: typed bounded lock
  failure instead of a test-thread panic at Store open.
- `docs/governed-runtime/governed-repair-custody.md`: canonical custody contract
  and operational nonclaims.
- This ledger records the bounded design and exact source census.

No legacy campaign-stage repair path was restored. No NQ, AG, Gen4, trust-root,
remote, deployment, or external authority state was modified from this
repository.
