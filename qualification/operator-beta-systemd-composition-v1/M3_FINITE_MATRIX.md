# M3 finite guest matrix — source candidate, not runtime qualification

The application owns `qualification/m3-admission/cases.json` and the exact
enrollment/capture semantics. Docket owns only this bounded qualification route.
Current capture interface is Labelwatch `2b5a03467e2cd4b86b90ce819dc2934c19043596`,
with corrected entry diagnosis descendant `17a2dedb2528025ec0c05b173d9be9b4b8b4ba53`.
Each stage retains the actual entry diagnosis and exact policy digest: observed
freelist pages must meet the explicitly configured fixture threshold. Filesystem
pressure is separately reported; a roomy fixture is not described as pressured.
The diagnosis is application-owned evidence, not NQ qualification or authority.
Both route and checker call that exact enrolled application's `require_entry`:
freelist/threshold/pressure classifications, OS/SQLite/file/sidecar consistency,
and original identity are checked; favorable labels alone are insufficient.
New cleanup-v2 NQ and the companion Rust driver still require real compilation,
package construction, independent review and actual local VM execution. No case
is credited from Python inventory tests or an exit-code expectation alone.

## Coverage and commands

The guest has the exact reviewed application at `/opt/constellation-m3/labelwatch`,
the reviewed modern NQ executable, and the existing AG/Docket executor package.
Install the separately built `m3-composition-driver` alongside the existing
composition tools. Root integration owns the final source and package hashes.

From this qualification directory, choose one closed case:

```
python3 m3_stage_cases.py --case normal-stage --revision <exact-Labelwatch-commit>
python3 m3_later_cases.py --case normal --revision <exact-Labelwatch-commit> --nq <native-path> --nq-sha256 <native-SHA256>
```

`m3_stage_cases.CASES` supplies twelve independent stage occurrences: ordinary
stage, case 2 temporary space, case 3 changed source, case 4 actual restored-content
substitution, case 6 exclusive staging failure, and seven stage interruption cuts.

`m3_later_cases.cases()` supplies the remaining named cases 1, 5, 8–15 and the
later-action case-7 cuts. Ordinary rollback and cleanup reconciliation are each
separately admitted; reconciliation binds the interrupted cleanup STARTED record.
Case 14 includes the original driver's exact duplicate-custody check and a
separate actual held operation-lock refusal, not concurrent untracked effects.
Case 15 includes missing/stale/substituted cleanup input and actual postcondition
margin refutation. Failed writer startup uses the real CLI's invalid numeric
argument and Restart=no; it is not a fabricated readiness record.

Before each cleanup admission the app capture CLI independently produces the
actual native prerequisite. Capture exit 0 means completed capture only. The AG
resolver requires the exact ESTABLISHED receipt and current applicability.
The pre-release and post-release receipts are distinct. The source acquisition
budget is 20 seconds, outer capture timeout 45 seconds, step timeout 25 seconds,
and route timeout 90 seconds. These are small disposable-fixture parameters,
not qualified production workload limits.

Each case gets its own 4MiB target tmpfs, separate 8MiB backup tmpfs, source,
operation, digest-named unit, journal, Docket state and evidence directory.
The space case fills only its bounded mount, never the guest root filesystem.
These tmpfs witnesses do not establish power-loss backup durability.

After the producer returns, invoke the separately frozen checker source, not a
modified producer tree:

```
python3 m3_case_check.py <exact-case-directory> --nq <native-path> --nq-sha256 <native-SHA256>
```

Retain its stdout as `INDEPENDENT-CHECK.json` only on successful exit. The checker
joins exact step/fragment/admission identity, one AG spend/Docket attempt and
settlement where actually established (otherwise explicit NOT_SETTLED owner
state), systemd outcome and no-restart count, actual cut markers, helper
journals, retained files/content and recovery disposition. It reexecutes the
retained native source/request on a SHA-pinned sealed executable; runtime loader
and libraries remain the enrolled VM premise. Helper completion alone never
establishes resource relief. Native final success/refutation is checked separately.

Then explicitly run `m3_case_teardown.py <exact-case-directory>`: stop only its
recorded units, archive both stopped filesystems, and unmount only those mounts.
The archive preserves bytes, not authority-bearing inode continuity. No automatic
retry, cleanup authorization or recovery follows a failed case/checker. Preserve
its mounts, logs and records for bounded diagnosis instead. Run cases sequentially
so the fixture memory budget is bounded; the supervising durable producer must
checkpoint each selected case and expected evidence before waiting.

## Controller loss is not a helper cut

The abrupt helper cases establish their exact helper interruption boundary only.
They do not establish that the controller survived or recovered.

The governing Docket module is byte-identical to accepted runtime `6c57926`:
`crates/gwr-local/src/governed_loop.rs`, Git blob
`ed5b9e10fc6cc658c002fa57a5cc9e50aa136bd7`. Existing owner tests specifically cover:

- `restart_before_custody_reservation_is_not_accepted_and_invokes_nothing`;
- `transport_refusal_after_custody_reconciles_without_a_second_execute`;
- `unknown_outcome_reconciles_read_only_and_never_executes_again`;
- `concurrent_duplicate_custody_creates_one_attempt_and_one_delivery`.

Their accepted historical evidence remains on its original revisions. The reuse
claim is only unchanged custody/reconciliation semantics: no modifications to
Docket's implementation are made by this companion harness. Re-run these owner
tests on the integrated release as an affected witness. The M3 route additionally
refuses an existing output directory before launching anything; timeout records
OUTCOME_UNKNOWN and does not issue a new action. If its supervisor disappears,
inspect the already reserved Docket/AG/systemd occurrence. Do not rerun this
creation-only driver as a recovery mechanism. Actual kill/restart of the new
companion supervisor is **NOT_RUN**, not implied by helper cuts or old M2 evidence.

## Remaining qualification prerequisites

- Exact merged NQ cleanup-v2, application capture and Rust resolver compilation.
- Exact dependency lock/vendor and two Bookworm-compatible package builds.
- Independent source review of this full matrix/checker and exact A/B freeze.
- Storage/ports/root launch approval, then each real case/checker/teardown.
- Four applicable Docket gates and affected composition/runtime witnesses.
- Human/operator trial and production-scale timing, containment and backup
  durability remain separate NOT_RUN dimensions.

## Application day-two procedure — candidate, not production authorization

This procedure consumes Labelwatch `17a2dedb`, NQ `920dc762`, and the candidate
companion export/recovery contract `c167cfdbcd293c37030c92071141352366949ef4`.
Exact packaged integration and full matrix/controller-loss acceptance remain
required. Normal-stage has actual VM evidence, but VM001/002/003 failures remain
retained; no aggregate application qualification or dogfood result follows.

1. Enroll one exact disposable target, operation, source identity, held writer
   cut, immutable step files/units and separate backup filesystem. Retain the
   entry diagnosis and threshold policy before deciding maintenance is needed.
   Missing/unknown/not-needed diagnosis is not permission to compact.
2. Admit `stage`: independently create backup, restore that backup, compare
   schema and typed row contents under the closed application manifest, then
   build and verify staging. Counts alone do not prove row preservation.
   Exclusive paths and original identity must remain bound; an integrity-only
   check does not prove recoverability. Fixture tmpfs is not durable backup.
3. Admit `replace`, then `verify-installed`: retain original rollback object;
   compare the installed replacement against the declared manifest and identity.
   Keep the write hold. This is replacement/data acceptance, not resource relief.
4. Start only enrolled writer units and admit `verify-service` after actual
   readiness bound to operation/hold/cut and exact PID/start. Process existence
   or paused processes are not useful ingestion. Failed start or uncertain
   readiness keeps the hold and does not authorize cleanup.
5. Acquire/replay the exact current native cleanup prerequisite, joined to this
   operation's source/original/backup/restore/cut and step. Admit `cleanup` only
   while its original applicability remains current. Never extend freshness
   through a new standing timestamp. Retaining the original occupies space;
   replacement acceptance therefore precedes cleanup authorization, and neither
   asserts final filesystem relief.
6. Admit `release` only after cleanup's required durable completion. Observe
   actual resumed generation and independently qualify post-release filesystem
   margin/data/service conditions. Missing generation or insufficient margin
   remains indeterminate/refuted as returned by the actual factual owner.

### Interrupted or refused steps

Never rerun a STARTED-without-completion step. Before STARTED, inspect original
owner custody anyway: controller absence is not evidence no dispatch occurred.
After STARTED or a backup/restore/staging fsync, retain all copies and the hold;
unfinished stage is not an installed replacement. Between the two replacement
renames, classify actual source/original/staging identities and keep writers
stopped. After replacement, `rollback-pre-ingest` is a separately admitted action
only while the exact pre-ingestion conditions still hold. Once new writes exist,
old rollback would discard them: preserve both objects and use forward recovery,
not overwrite with the old file.

At cleanup authorization/before unlink, retain the hold and exact objects. After
unlink without cleanup completion, separately admitted `reconcile-cleanup`
binds the interrupted STARTED record and verifies the actual absent original;
it completes required synchronization, not another deletion. Release-record
cuts still require observed resumed generation; a record alone cannot establish
data-plane resumption. Before/after terminal cuts retain both helper disposition
and owner state. Exit77/78 proves only its exact fixture marker and checked
filesystem boundary, never controller recovery.

Temporary-space, changed-source, restored-content mismatch, exclusive staging,
lock contention, readiness failure and failed systemd start are intentional
negative cases. Preserve their specific helper reason and artifact state.
Missing/stale/substituted/foreign cleanup evidence is pre-admission refusal with
zero spend/attempt, not a failed helper. A helper report
REFUSED_OR_OUTCOME_UNKNOWN may coexist with Docket NOT_SETTLED/indeterminate:
do not manufacture a settlement receipt or label all owner uncertainty refused.

### Existing-owner inspection and candidate recovery

These commands refer only to the existing occurrence and exact enrolled binaries;
placeholders must come from its retained checkpoint, not a new run ID. Native
candidate `c167cfdb` exposes:

```sh
<m3-driver> --inspect-existing <docket> <ag-effectd> <existing-custody-directory> <exact-issuance>
<docket> governed-loop inspect --state <existing-custody-directory>/occurrence/docket-state --issuance <exact-issuance>
<m3-driver> --recover-existing <docket> <ag-effectd> <existing-custody-directory> <exact-issuance>
```

Inspect first. Recovery is an explicit candidate operation, not automatic retry:
it may append AG/Docket reconciliation history but its port has no issuance
signer and refuses accept_issuance. It does not mint authority, execute a new
step, repair data or make stale facts current. Retain output separately and
check unchanged issuance/spend plus exact owner disposition. Missing identity,
NOT_OBSERVABLE or unresolved custody stops advancement. Existing controller-loss
fixture wrappers are qualification tools, not operator recovery executables.

Actual production target inventory/privileged inspection and any production
maintenance action remain separately permission-gated. Neither fixture enrollment
nor this document authorizes them. The product claim is preparation for testing
the recurring chore, not an observed removal of that chore or a human trial.
