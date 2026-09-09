# M4 day-two operator procedure — candidate, not yet qualified

This bounded extension uses the existing two-VM composition lifecycle and
component-owned commands. It is not a daemon, orchestrator, or deployment
authority. Run only in fresh campaign-owned Debian guests. Never run
`day_two_guest.py` on an operator host. Root/integration owns exact package
pins and coordinates guest ports/disks before a new producer starts.

## Evidence reuse and missing gates

Accepted retirement VM001 retains installation, exact remove/reinstall,
guest reboot/reopen, fresh observations, AG/Docket reconciliation, online NQ
backup, evidence export and scoped teardown. Its original result is unchanged.
Remove/reinstall is not a version upgrade; backup integrity is not restore.

`day_two_restore.py` operates only on copies of retained stores. Restore002
demonstrated both roles' complete typed-row/schema preservation, refused
existing-destination and corrupt-source restores, unchanged config on invalid
apply, and equal durable status. Read-time `generated_at` remains separate.
Raw private evidence is under the campaign's `m4/restore-002-*` directories.
Its SQLite immutable read mode is valid only for these quiescent standalone
snapshots, never for a running store with uncollected WAL state.

The new VM candidate adds actual packaged `nqd.service` start, Unix API
inspection, restart, stop, online backup, absent-destination restore,
owner reopening of the restored store, explicit already-current upgrade,
invalid-config/start refusal, repair and restart, journal retention and
cleanup. Zero scheduled watchers is deliberate: restoring historical
evidence must not silently restart collection or authorize an effect.

## Operator sequence and recovery disposition

1. Verify exact package/checksum and fresh guest enrollment; installation
   never enables a service, admits helpers or initializes arbitrary state.
2. Stop the owner service and require `inactive` before maintenance. Inspect
   exact package, config, admission, database and current process separately.
3. Validate configuration with `nq config check`. Start only after successful
   checks; service start is not socket readiness or a diagnostic conclusion.
4. Use `nq backup NEW_PATH`, not a live WAL file copy. Retain digest and
   source identity. Verify restore into an absent destination, exact typed
   rows/schema and owner read surfaces before using that copy.
5. Keep pre-maintenance state and matching WAL sidecars quarantined. Never
   substitute an older AG/Docket ledger into live execution: previously spent
   authority and post-backup writes require separate reconciliation.
6. Invalid config, failed restore/start or interrupted maintenance leaves
   `nqd` stopped, both copies retained, and the procedure incomplete. Inspect
   the original occurrence; do not automatically replay it. A failed stop
   leaves service state unresolved and prohibits mutation. Supervisor loss
   does not authorize a replacement producer.
7. Export only explicitly selected evidence. Private archives include stores
   and logs and are **not a secret-free public export**. Public presentation
   must use a bounded reviewed allowlist; filenames alone do not sanitize it.
8. Remove only the enrolled disposable fixture paths after evidence custody.
   Package uninstall and destructive data cleanup remain distinct actions.

## Remaining work (must not disappear into a passing fixture)

True binary/schema upgrade and rollback require a named supported predecessor
and new owner evidence; `already_current` does not qualify those transitions.
M3 application data/ingestion/rollback and real-provider state recovery remain
with their companion owners. Restoring AG/Docket authorizing state is not
qualified by NQ evidence restoration. Secret-free export needs its own bounded
allowlist checks. No human trial, production operation, fleet install or
deployment is established by this scripted qualification.
