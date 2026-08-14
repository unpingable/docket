-- R2 closes two durable custody contracts without reconstructing authority:
-- the old physical-nonoccurrence wording is narrowed to an executor-report
-- observation, and each executor result binds the cumulative ordered journal
-- known at that cut. The Rust migrator backfills the cumulative columns before
-- restoring the immutable-update trigger.

DROP TRIGGER IF EXISTS governed_executor_result_immutable_update;

ALTER TABLE governed_repair_checkpoint
RENAME COLUMN unauthorized_effect_not_performed TO no_unauthorized_effect_reported;

ALTER TABLE governed_repair_checkpoint
RENAME COLUMN authorized_effects_occurred TO reported_authorized_effects_occurred;

ALTER TABLE governed_executor_result
ADD COLUMN cumulative_effect_journal_digest TEXT;

ALTER TABLE governed_executor_result
ADD COLUMN cumulative_effect_journal_entries TEXT;

CREATE TRIGGER governed_executor_result_cumulative_required_insert
BEFORE INSERT ON governed_executor_result
WHEN NEW.cumulative_effect_journal_digest IS NULL
  OR NEW.cumulative_effect_journal_entries IS NULL
BEGIN
  SELECT RAISE(ABORT, 'cumulative governed executor journal is required');
END;
