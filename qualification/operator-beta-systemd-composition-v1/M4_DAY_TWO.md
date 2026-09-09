# M4 day-two operator procedure — evidence and remaining qualification

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

VM002 (producer `810bfd1`, checker `fc3d686`) demonstrated packaged `nqd.service` start, Unix API
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

The exact modern v4-to-v5 empty schema specimen passed a separate owner upgrade
exercise (`m4/upgrade-001`). This is not populated historical binary migration.
The original M2 binary's factual profiles are incompatible with the current
cohort despite both displaying version 0.1.0. See [M4_COLD_COHORT.md](M4_COLD_COHORT.md)
for the separate old-archive/fresh-store procedure and pending VM transition.
Its final service readiness uses `watchers=[]`; fresh admission and diagnostic
execution are explicit one-shot steps, not scheduled-monitor qualification.
M3 application data/ingestion/rollback and real-provider state recovery remain
with their companion owners. Restoring AG/Docket authorizing state is not
qualified by NQ evidence restoration. The support-lane public-export allowlist
and three controls passed against both VM002 records; raw private archives
remain private and must not be posted as public summaries. No human trial, production operation, fleet install or
deployment is established by this scripted qualification.

## Practical operator commands and boundaries

Use only the release's admitted package digests and config/owner enrollment;
these examples describe the demonstrated NQ lifecycle, not permission to
operate production or restore authorizing ledgers:

```sh
sudo -u nq nq --config /etc/nq/nq.toml config check
sudo systemctl start nqd.service
curl --fail --unix-socket /run/nq/nqd.sock http://localhost/v3/status
sudo systemctl restart nqd.service
curl --fail --unix-socket /run/nq/nqd.sock http://localhost/v3/status
sudo systemctl stop nqd.service
systemctl show nqd.service --property=ActiveState --value
sudo -u nq nq --config /etc/nq/nq.toml backup /ABSENT/BACKUP.sqlite
sudo -u nq nq restore /ABSENT/BACKUP.sqlite /ABSENT/RESTORED.sqlite
```

Require a fresh successful status response after each start/restart, not merely
an existing socket or `active` label. Before changing failed configuration,
retain `systemctl show` result/ExecMainStatus and `journalctl -u nqd.service`.
Explicitly stop restart scheduling before repair. Restore into an absent
destination; then compare full typed rows/schema and reopen with the exact owner
binary before changing configured state. Invalid restore destinations and
invalid configuration must preserve existing data/configuration.

## Screen reconnect and credential boundary audit

The unchanged AG M2 screen reconstructs state through Docket `status` on refresh
or a new browser connection; lost launch replies do not retry RUN. Docket's
retained intent prevents a second launch even across acknowledgement loss.
The screen's server process may be restarted with the same admitted controller;
this reconstructs a view, not a campaign or provider execution. Current fields
become `NOT_OBSERVABLE` when their source fails; do not display a stale spinner.

Concrete existing controls: AG `test_refresh_and_reconnect_reopen_status`,
`test_unavailability_never_becomes_completion`, `test_transport_exit_is_not_success`;
Docket `test_durable_intent_cut_forbids_a_second_launch` and
`test_acknowledgement_loss_exposes_activity_without_second_launch`. Twenty
unchanged AG screen tests passed at `5194005` under authorized loopback test
execution; an initial sandbox-only attempt had ten socket-permission errors,
not ten product failures. Historical real M2 browser evidence stays on its
original exact subjects. A new live browser/restarted-server exercise against
the beta provider surface is not inferred from these fixtures.

M4's local NQ path has no provider credential flow. Missing/revoked credentials,
provider model/configuration refusal, pre-admission timeout and post-admission
unknown outcome belong to the separate Switchyard/Codex/Nightshift owner path.
No new auth system or credential probe belongs in this runbook. That path needs
its own exact no-generation refusal controls and admitted live/reconnect evidence;
M3 application backup/ingestion recovery likewise retains its own qualification.
