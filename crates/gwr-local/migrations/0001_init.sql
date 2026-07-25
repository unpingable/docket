-- Immutable typed ledger records plus current-state projections.
-- Ledger tables are insert-only; projections carry optimistic versions.

CREATE TABLE IF NOT EXISTS work_request (
    id TEXT PRIMARY KEY,
    repository TEXT NOT NULL,
    target_ref TEXT NOT NULL,
    goal TEXT NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS preparation_run (
    id TEXT PRIMARY KEY,
    work_request TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    deadline INTEGER NOT NULL
) STRICT;

-- The immutable end record for a run; its absence means the run is running.
CREATE TABLE IF NOT EXISTS preparation_run_end (
    run_id TEXT PRIMARY KEY,
    end_kind TEXT NOT NULL,
    at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS candidate_artifact (
    id TEXT PRIMARY KEY,
    preparation_run TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    content_len INTEGER NOT NULL,
    ingested_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS attempt (
    id TEXT PRIMARY KEY,
    work_request TEXT NOT NULL,
    candidate TEXT NOT NULL,
    repository TEXT NOT NULL,
    basis TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    target_ref TEXT NOT NULL,
    expected_basis TEXT NOT NULL,
    patch_digest TEXT NOT NULL,
    allowed_paths TEXT NOT NULL,
    argv TEXT NOT NULL,
    environment TEXT NOT NULL,
    admitted_at INTEGER NOT NULL,
    prepared_digest TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS standing_grant (
    id TEXT PRIMARY KEY,
    actor TEXT NOT NULL,
    act TEXT NOT NULL,
    repository TEXT NOT NULL,
    attempt_digest TEXT NOT NULL,
    expires_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS standing_use (
    id TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL,
    used_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS standing_projection (
    grant_id TEXT PRIMARY KEY,
    consumed_by TEXT,
    version INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS reservation (
    id TEXT PRIMARY KEY,
    repository TEXT NOT NULL,
    target_ref TEXT NOT NULL,
    basis TEXT NOT NULL,
    attempt TEXT NOT NULL,
    expires_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS reservation_use (
    id TEXT PRIMARY KEY,
    reservation_id TEXT NOT NULL,
    used_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS reservation_projection (
    reservation_id TEXT PRIMARY KEY,
    consumed_by TEXT,
    version INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS ratification (
    id TEXT PRIMARY KEY,
    attempt TEXT NOT NULL,
    prepared_digest TEXT NOT NULL,
    actor TEXT NOT NULL,
    standing_use TEXT NOT NULL,
    at INTEGER NOT NULL
) STRICT;

-- UNIQUE(attempt): one persisted DispatchId per attempt, enforced by schema.
CREATE TABLE IF NOT EXISTS dispatch (
    id TEXT PRIMARY KEY,
    attempt TEXT NOT NULL UNIQUE,
    prepared_digest TEXT NOT NULL,
    reservation_use TEXT NOT NULL,
    repository TEXT NOT NULL,
    target_ref TEXT NOT NULL,
    expected_basis TEXT NOT NULL,
    patch_digest TEXT NOT NULL,
    allowed_paths TEXT NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS commitment (
    attempt TEXT PRIMARY KEY,
    dispatch TEXT NOT NULL,
    target_ref TEXT NOT NULL,
    previous_value TEXT NOT NULL,
    result_commit TEXT NOT NULL,
    journal_digest TEXT NOT NULL,
    at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS dispatch_refusal (
    attempt TEXT PRIMARY KEY,
    dispatch TEXT NOT NULL,
    ground TEXT NOT NULL,
    journal_digest TEXT NOT NULL,
    at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS indeterminate_outcome (
    attempt TEXT PRIMARY KEY,
    dispatch TEXT NOT NULL,
    last_journal_digest TEXT,
    at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS recovery_fact (
    id TEXT PRIMARY KEY,
    attempt TEXT NOT NULL,
    dispatch TEXT NOT NULL,
    prepared_digest TEXT NOT NULL,
    repository TEXT NOT NULL,
    target_ref TEXT NOT NULL,
    basis TEXT NOT NULL,
    observed_ref TEXT NOT NULL,
    expected_result TEXT,
    journal_digest TEXT NOT NULL,
    source_kind TEXT NOT NULL,
    source_detail TEXT,
    recorded_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS recovery_resolution (
    id TEXT PRIMARY KEY,
    attempt TEXT NOT NULL,
    dispatch TEXT NOT NULL,
    fact TEXT NOT NULL,
    verdict TEXT NOT NULL,
    standing_use TEXT NOT NULL,
    at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS observation (
    id TEXT PRIMARY KEY,
    attempt TEXT NOT NULL,
    argv TEXT NOT NULL,
    workdir TEXT NOT NULL,
    result_commit TEXT NOT NULL,
    environment TEXT NOT NULL,
    exit_status INTEGER NOT NULL,
    stdout_digest TEXT NOT NULL,
    stderr_digest TEXT NOT NULL,
    at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS reliance_admission (
    attempt TEXT NOT NULL,
    observation TEXT NOT NULL,
    result_commit TEXT NOT NULL,
    at INTEGER NOT NULL,
    PRIMARY KEY (attempt, observation)
) STRICT;

CREATE TABLE IF NOT EXISTS reliance_refusal (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attempt TEXT NOT NULL,
    kind TEXT NOT NULL,
    detail TEXT,
    at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS residual_obligation (
    id TEXT PRIMARY KEY,
    attempt TEXT NOT NULL,
    kind TEXT NOT NULL,
    at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS reconciliation (
    attempt TEXT PRIMARY KEY,
    retained TEXT NOT NULL,
    at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS attempt_projection (
    attempt TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    version INTEGER NOT NULL,
    rat_id TEXT,
    rat_standing_use TEXT,
    rsv_id TEXT,
    rsv_use TEXT,
    dispatch_id TEXT,
    refusal_ground TEXT,
    resolution_id TEXT
) STRICT;

CREATE TABLE IF NOT EXISTS timeline (
    attempt TEXT NOT NULL,
    seq INTEGER NOT NULL,
    kind TEXT NOT NULL,
    at INTEGER NOT NULL,
    PRIMARY KEY (attempt, seq)
) STRICT;
