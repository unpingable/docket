-- R2 settlement identity closure. A known terminal settlement now carries the
-- exact cumulative executor-effect journal identity at its durable cut. The
-- Rust migrator fills this column and recomputes each rejected-R1 development
-- settlement identity before these shape triggers become active.

ALTER TABLE governed_loop_attempt
ADD COLUMN settlement_cumulative_effect_journal_identity TEXT;

-- Rejected-R1 settlement identities remain exact historical development
-- evidence after the active settlement identity is recomputed under R2.
ALTER TABLE governed_loop_attempt
ADD COLUMN legacy_r1_settlement_identity TEXT;

ALTER TABLE governed_loop_attempt
ADD COLUMN legacy_r1_settlement_jcs TEXT;

CREATE TRIGGER governed_loop_settlement_journal_required_insert
BEFORE INSERT ON governed_loop_attempt
WHEN (NEW.status = 'settled') !=
     (NEW.settlement_cumulative_effect_journal_identity IS NOT NULL)
BEGIN
  SELECT RAISE(ABORT, 'settlement cumulative journal shape is required');
END;

CREATE TRIGGER governed_loop_settlement_journal_required_update
BEFORE UPDATE OF status, settlement_cumulative_effect_journal_identity
ON governed_loop_attempt
WHEN (NEW.status = 'settled') !=
     (NEW.settlement_cumulative_effect_journal_identity IS NOT NULL)
BEGIN
  SELECT RAISE(ABORT, 'settlement cumulative journal shape is required');
END;
