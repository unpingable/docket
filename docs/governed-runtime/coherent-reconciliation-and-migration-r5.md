# Docket R5 coherent reads and serialized migration

## Bootstrap and scope

This correction is constructed under external human development authorization.
It does not govern its own construction and grants no NQ, deployment,
qualification, certificate, or operational authority. AG R5 and the actual-wire
corpus remain unchanged.

## Coherent reconciliation observations

Every set of durable fields used to classify a reconciliation observation is
read through one deferred SQLite transaction. The transaction contains the
attempt projection, explicit round, source cut, executor-result history,
cumulative journal, sealed result, checkpoint correspondence, and completion
receipt used by that classification. A caller may discard that snapshot and
take a fresh one, but it never combines values from both.

Deferred read transactions end before any checkpoint verifier or executor
process is invoked. Consequence-bearing claim and completion paths retain their
immediate write transactions and re-read the current durable cut there. A
duplicate caller therefore returns a completed replay, an unresolved claimed
round, or a typed stale outcome. Genuine contradictions observed within one
snapshot continue to fail closed.

## Serialized first-open migration

One outer `BEGIN IMMEDIATE` transaction covers the complete migration decision
and application: every schema census, conditional DDL statement, backfill,
legacy validation, exact reconciliation-schema census, and commit. The R2
backfill and R4 reconciliation migration join that transaction rather than
opening nested transactions. A concurrent opener waits under Docket's bounded
busy policy and then performs a fresh census against the committed schema.

Migration failure rolls back the entire cut. Partial legacy column groups are
corruption, not an invitation to infer or complete ambiguous state. Migration
serialization changes no persistent schema and therefore introduces no new
schema version.

The indeterminate executor-result path also claims its immediate writer
transaction before reading the prior journal. This prevents a concurrent
opener's completed migration census from invalidating a deferred WAL snapshot
between journal classification and the first result write. Journal append and
attempt-state update remain one atomic cut; bounded contention is still
reported rather than converted into success.

## Campaign discovery disposition

AG's product boundary remains endpoint/database scoped. Deployment-wide
discovery of configured AG service roots is a later deployment-catalog concern,
not Docket custody authority and not part of this correction. No global
campaign catalog is added.
