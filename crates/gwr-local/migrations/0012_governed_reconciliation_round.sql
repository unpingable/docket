-- R4 durable reconciliation-round single flight.
--
-- A round is authenticated by AG and claimed by Docket before any external
-- reconciliation invocation.  The claim is never reacquired: a process loss
-- before completion remains an explicit unresolved round.  A later poll is a
-- distinct round bound to the immediately preceding completed indeterminate
-- observation; an ordinary retry cannot create it.

CREATE TABLE governed_reconciliation_round (
    request TEXT PRIMARY KEY,
    round TEXT NOT NULL UNIQUE,
    issuance TEXT NOT NULL,
    attempt TEXT NOT NULL,
    caller_state_digest TEXT NOT NULL,
    idempotency TEXT NOT NULL UNIQUE,
    predecessor_round TEXT UNIQUE,
    predecessor_reconciliation TEXT,
    source_cut TEXT NOT NULL,
    source_cut_jcs BLOB NOT NULL,
    checkpoint_identity TEXT,
    executor_binding TEXT NOT NULL,
    reservation TEXT NOT NULL UNIQUE,
    signed_body_b64 TEXT NOT NULL,
    issuer_principal TEXT NOT NULL,
    signer_key_id TEXT NOT NULL,
    signer_public_key TEXT NOT NULL,
    signature TEXT NOT NULL,
    claimed_at INTEGER NOT NULL CHECK (
      claimed_at BETWEEN 0 AND 9007199254740991
    ),
    state TEXT NOT NULL CHECK (state IN ('claimed','completed')),
    completion TEXT UNIQUE,
    result_kind TEXT CHECK (
      result_kind IS NULL OR result_kind IN (
        'settled','indeterminate','governed_repair'
      )
    ),
    result_identity TEXT,
    result_reconciliation TEXT,
    result_evidence TEXT,
    completed_at INTEGER CHECK (
      completed_at IS NULL OR completed_at BETWEEN 0 AND 9007199254740991
    ),
    CHECK (
      (predecessor_round IS NULL AND predecessor_reconciliation IS NULL)
      OR
      (predecessor_round IS NOT NULL AND predecessor_reconciliation IS NOT NULL)
    ),
    CHECK (
      (state='claimed' AND completion IS NULL AND result_kind IS NULL
                       AND result_identity IS NULL AND result_reconciliation IS NULL
                       AND result_evidence IS NULL AND completed_at IS NULL)
      OR
      (state='completed' AND completion IS NOT NULL AND result_kind IS NOT NULL
                         AND result_identity IS NOT NULL AND completed_at IS NOT NULL
                         AND (
                           (result_kind='indeterminate'
                            AND result_reconciliation IS NOT NULL
                            AND result_evidence IS NOT NULL)
                           OR
                           (result_kind!='indeterminate'
                            AND result_reconciliation IS NULL
                            AND result_evidence IS NULL)
                         ))
    ),
    UNIQUE (issuance, attempt, source_cut),
    FOREIGN KEY (issuance) REFERENCES governed_loop_attempt(issuance),
    FOREIGN KEY (predecessor_round) REFERENCES governed_reconciliation_round(round)
) STRICT;

CREATE TRIGGER governed_reconciliation_round_identity_immutable
BEFORE UPDATE OF request,round,issuance,attempt,caller_state_digest,idempotency,
                 predecessor_round,predecessor_reconciliation,source_cut,
                 source_cut_jcs,checkpoint_identity,executor_binding,reservation,signed_body_b64,
                 issuer_principal,signer_key_id,signer_public_key,signature,claimed_at
ON governed_reconciliation_round
BEGIN
  SELECT RAISE(ABORT, 'governed reconciliation round identity is immutable');
END;

CREATE TRIGGER governed_reconciliation_round_monotone
BEFORE UPDATE OF state,completion,result_kind,result_identity,
                 result_reconciliation,result_evidence,completed_at
ON governed_reconciliation_round
WHEN NOT (
  OLD.state='claimed' AND NEW.state='completed'
  AND OLD.completion IS NULL AND NEW.completion IS NOT NULL
  AND OLD.result_kind IS NULL AND NEW.result_kind IS NOT NULL
  AND OLD.result_identity IS NULL AND NEW.result_identity IS NOT NULL
  AND OLD.result_reconciliation IS NULL
  AND OLD.result_evidence IS NULL
  AND OLD.completed_at IS NULL AND NEW.completed_at IS NOT NULL
)
BEGIN
  SELECT RAISE(ABORT, 'governed reconciliation round transition is not monotone');
END;

CREATE TRIGGER governed_reconciliation_round_no_delete
BEFORE DELETE ON governed_reconciliation_round
BEGIN
  SELECT RAISE(ABORT, 'governed reconciliation rounds are append-only');
END;
