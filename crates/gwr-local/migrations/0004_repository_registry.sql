-- Docket-owned logical repository identities.
--
-- `repository.id` is opaque and minted/registered explicitly. Locator rows are
-- operational aliases only. A relocation appends the new path and marks it
-- current while retaining the former path as history/alias.
--
-- The migration runner separately adds nullable
-- `work_request.repository_id`. Existing rows deliberately remain NULL:
-- registration does not infer a binding from their stored path.
CREATE TABLE IF NOT EXISTS repository (
    id TEXT PRIMARY KEY,
    registered_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS repository_locator (
    repository_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('path', 'remote')),
    locator TEXT NOT NULL,
    registered_at INTEGER NOT NULL,
    current INTEGER NOT NULL CHECK (current IN (0, 1)),
    PRIMARY KEY (repository_id, kind, locator),
    UNIQUE (kind, locator)
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS repository_one_current_path
    ON repository_locator (repository_id)
    WHERE kind = 'path' AND current = 1;
