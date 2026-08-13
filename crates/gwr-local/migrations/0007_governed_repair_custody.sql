-- Append-only terminal governed-repair facts for one already-custodied AG
-- issuance.  These records grant no standing and share no authority surface
-- with the retired campaign-stage exact_repair office.

CREATE TABLE IF NOT EXISTS governed_repair_checkpoint (
    checkpoint TEXT PRIMARY KEY,
    sealed_result TEXT NOT NULL UNIQUE,
    issuance TEXT NOT NULL UNIQUE,
    custody TEXT NOT NULL,
    attempt TEXT NOT NULL UNIQUE,
    executor_binding TEXT NOT NULL,
    executor_result TEXT NOT NULL,
    executor_receipt TEXT NOT NULL,
    requirement_kind TEXT NOT NULL CHECK (
      requirement_kind IN ('scope_expansion_required','readjudication_required')
    ),
    requirement_identity TEXT NOT NULL UNIQUE,
    campaign TEXT NOT NULL,
    occurrence TEXT NOT NULL,
    proposal TEXT NOT NULL,
    observation TEXT NOT NULL,
    standing_resolution TEXT NOT NULL,
    admission_decision TEXT NOT NULL,
    spend TEXT NOT NULL,
    original_scope_digest TEXT NOT NULL,
    effect_journal_digest TEXT NOT NULL,
    effect_journal_entries TEXT NOT NULL,
    work_repository_identity TEXT,
    work_commit TEXT,
    work_tree TEXT,
    work_diff_identity TEXT,
    work_content_manifest_identity TEXT,
    authorized_effects_occurred INTEGER NOT NULL CHECK (
      authorized_effects_occurred IN (0,1)
    ),
    unauthorized_effect_not_performed INTEGER NOT NULL CHECK (
      unauthorized_effect_not_performed = 1
    ),
    idempotency TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
    CHECK (
      (work_repository_identity IS NULL AND work_commit IS NULL AND work_tree IS NULL
       AND work_diff_identity IS NULL AND work_content_manifest_identity IS NULL)
      OR
      (work_repository_identity IS NOT NULL AND work_commit IS NOT NULL AND work_tree IS NOT NULL)
    ),
    FOREIGN KEY (issuance) REFERENCES governed_loop_attempt(issuance)
) STRICT;

-- Exact executor evidence for ordinary known/indeterminate outcomes.  The
-- append is committed atomically with the corresponding attempt transition;
-- no settlement can discard or substitute its authorized-effect journal.
CREATE TABLE IF NOT EXISTS governed_executor_result (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    result_identity TEXT NOT NULL UNIQUE,
    issuance TEXT NOT NULL,
    attempt TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('success','failure','indeterminate')),
    receipt TEXT NOT NULL,
    effect_journal_digest TEXT NOT NULL,
    effect_journal_entries TEXT NOT NULL,
    recorded_at INTEGER NOT NULL,
    FOREIGN KEY (issuance) REFERENCES governed_loop_attempt(issuance)
) STRICT;
CREATE UNIQUE INDEX IF NOT EXISTS governed_executor_result_exact_observation
ON governed_executor_result(issuance,receipt);

CREATE TABLE IF NOT EXISTS governed_repair_scope_expansion (
    checkpoint TEXT PRIMARY KEY,
    requested_delta_digest TEXT NOT NULL,
    requested_effect_class TEXT NOT NULL,
    requested_delta_resources TEXT NOT NULL,
    blocked_effect_class TEXT NOT NULL,
    blocked_resource TEXT NOT NULL,
    blocked_path TEXT NOT NULL,
    blocked_operation TEXT NOT NULL CHECK (
      blocked_operation IN ('read','create','modify','delete','execute')
    ),
    reason TEXT NOT NULL,
    dependency_evidence TEXT NOT NULL,
    limitations TEXT NOT NULL,
    FOREIGN KEY (checkpoint) REFERENCES governed_repair_checkpoint(checkpoint)
) STRICT;

CREATE TABLE IF NOT EXISTS governed_repair_readjudication (
    checkpoint TEXT PRIMARY KEY,
    question TEXT NOT NULL,
    evidence_census TEXT NOT NULL,
    diagnostic_census TEXT NOT NULL,
    bounded_alternatives TEXT NOT NULL,
    unresolved_facts TEXT NOT NULL,
    adjudication_scope TEXT NOT NULL,
    limitations TEXT NOT NULL,
    FOREIGN KEY (checkpoint) REFERENCES governed_repair_checkpoint(checkpoint)
) STRICT;

CREATE TRIGGER IF NOT EXISTS governed_repair_checkpoint_immutable_update
BEFORE UPDATE ON governed_repair_checkpoint BEGIN
  SELECT RAISE(ABORT, 'governed repair checkpoint is immutable');
END;
CREATE TRIGGER IF NOT EXISTS governed_executor_result_immutable_update
BEFORE UPDATE ON governed_executor_result BEGIN
  SELECT RAISE(ABORT, 'governed executor result is immutable');
END;
CREATE TRIGGER IF NOT EXISTS governed_executor_result_immutable_delete
BEFORE DELETE ON governed_executor_result BEGIN
  SELECT RAISE(ABORT, 'governed executor result is immutable');
END;
CREATE TRIGGER IF NOT EXISTS governed_repair_checkpoint_immutable_delete
BEFORE DELETE ON governed_repair_checkpoint BEGIN
  SELECT RAISE(ABORT, 'governed repair checkpoint is immutable');
END;
CREATE TRIGGER IF NOT EXISTS governed_repair_scope_immutable_update
BEFORE UPDATE ON governed_repair_scope_expansion BEGIN
  SELECT RAISE(ABORT, 'governed scope result is immutable');
END;
CREATE TRIGGER IF NOT EXISTS governed_repair_scope_immutable_delete
BEFORE DELETE ON governed_repair_scope_expansion BEGIN
  SELECT RAISE(ABORT, 'governed scope result is immutable');
END;
CREATE TRIGGER IF NOT EXISTS governed_repair_readjudication_immutable_update
BEFORE UPDATE ON governed_repair_readjudication BEGIN
  SELECT RAISE(ABORT, 'governed readjudication result is immutable');
END;
CREATE TRIGGER IF NOT EXISTS governed_repair_readjudication_immutable_delete
BEFORE DELETE ON governed_repair_readjudication BEGIN
  SELECT RAISE(ABORT, 'governed readjudication result is immutable');
END;
