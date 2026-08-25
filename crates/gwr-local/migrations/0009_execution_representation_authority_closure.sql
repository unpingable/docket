-- Optional canonical authority-closure inventory for M7. NULL preserves the
-- frozen v1-v3 governed inspection and executor-binding semantics.

ALTER TABLE governed_loop_attempt ADD COLUMN executor_representation_authority TEXT;
