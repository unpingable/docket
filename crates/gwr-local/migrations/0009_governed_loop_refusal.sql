-- Durable, non-authorizing refusal of one authenticated canonical AG issuance
-- before execution custody is minted. A refusal has no attempt and consumes no
-- Docket standing. Its exact signed envelope and sealed identity make replay
-- read-only and changed-content reuse fail closed.

CREATE TABLE IF NOT EXISTS governed_loop_issuance_disposition (
    issuance TEXT PRIMARY KEY,
    disposition TEXT NOT NULL CHECK (disposition IN ('custody','refused')),
    artifact TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS governed_loop_issuance_refusal (
    issuance TEXT PRIMARY KEY,
    refusal TEXT NOT NULL UNIQUE,
    signed_body_b64 TEXT NOT NULL,
    issuer_principal TEXT NOT NULL,
    signer_key_id TEXT NOT NULL,
    signer_public_key TEXT NOT NULL,
    signature TEXT NOT NULL,
    campaign TEXT NOT NULL,
    occurrence TEXT NOT NULL,
    refusal_class TEXT NOT NULL CHECK (
      refusal_class IN ('issuance_invalid','issuance_expired','checkpoint_invalid',
                        'standing_invalid','instrument_substitution')
    ),
    reason_code TEXT NOT NULL,
    evidence TEXT NOT NULL,
    refused_at INTEGER NOT NULL
) STRICT;

-- Existing v6-v8 custody rows predate the common disposition guard. Their
-- attempt identity is the exact durable custody artifact used by the current
-- insert path, so migration can close the race membrane without reconstructing
-- authority or changing attempt bytes.
INSERT OR IGNORE INTO governed_loop_issuance_disposition
    (issuance, disposition, artifact)
SELECT issuance, 'custody', attempt
FROM governed_loop_attempt;

CREATE TRIGGER IF NOT EXISTS governed_loop_issuance_refusal_no_update
BEFORE UPDATE ON governed_loop_issuance_refusal
BEGIN
  SELECT RAISE(ABORT, 'governed-loop issuance refusals are immutable');
END;

CREATE TRIGGER IF NOT EXISTS governed_loop_issuance_refusal_no_delete
BEFORE DELETE ON governed_loop_issuance_refusal
BEGIN
  SELECT RAISE(ABORT, 'governed-loop issuance refusals are immutable');
END;

CREATE TRIGGER IF NOT EXISTS governed_loop_issuance_disposition_no_update
BEFORE UPDATE ON governed_loop_issuance_disposition
BEGIN
  SELECT RAISE(ABORT, 'governed-loop issuance dispositions are immutable');
END;

CREATE TRIGGER IF NOT EXISTS governed_loop_issuance_disposition_no_delete
BEFORE DELETE ON governed_loop_issuance_disposition
BEGIN
  SELECT RAISE(ABORT, 'governed-loop issuance dispositions are immutable');
END;
