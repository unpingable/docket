-- Upstream authorization issuances and the standing they justify.
--
-- An issuance is an authenticated immutable fact produced by an upstream
-- authorization office about an admitted decision. It is not authority: it
-- never becomes a standing token, and nothing here is presented to the broker.
-- Docket verifies an issuance against its own stored prepared attempt and then
-- mints its own local, exact-attempt-bound, single-use standing.
--
-- The exact signed body bytes are retained (base64url) so a later reader can
-- re-verify the signature over precisely what was accepted, rather than over a
-- re-serialization.
CREATE TABLE IF NOT EXISTS authz_issuance (
    issuance_id TEXT PRIMARY KEY,
    attempt TEXT NOT NULL,
    decision_id TEXT NOT NULL,
    issuer_principal TEXT NOT NULL,
    issuer_key_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    -- Both canonical domains, kept distinct and never derived from each other.
    request_raw_sha256 TEXT NOT NULL,
    request_upstream_digest TEXT NOT NULL,
    -- Docket's own transcript digest as echoed by the issuance; compared
    -- against the stored attempt at intake, never trusted as a yardstick.
    prepared_digest TEXT NOT NULL,
    requested_actor TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    -- Upstream authorization premises, length-prefixed pairs. Deliberately
    -- separate from the effect class's settlement premises.
    premise_kinds TEXT NOT NULL,
    premise_statements TEXT NOT NULL,
    -- Upstream residual obligations: status distinguishes "none recorded" from
    -- "the upstream office cannot express residuals", and items are carried
    -- verbatim without coercion into Docket's own obligation vocabulary.
    residual_status TEXT NOT NULL,
    residual_items TEXT NOT NULL,
    consumption_ledger TEXT NOT NULL,
    consumption_use_digest TEXT NOT NULL,
    body_b64 TEXT NOT NULL,
    accepted_at INTEGER NOT NULL
) STRICT;

-- Where a grant's authorization came from. NULL on rows written before this
-- migration: those read as "unrecorded", never as either source.
ALTER TABLE standing_grant ADD COLUMN source TEXT;

-- The issuance that justified an upstream-authorized grant. At most one grant
-- per issuance: an issuance cannot mint standing twice.
ALTER TABLE standing_grant ADD COLUMN issuance_id TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS standing_grant_issuance_unique
    ON standing_grant (issuance_id) WHERE issuance_id IS NOT NULL;
