-- Optional measurement-to-execution representation custody. NULL preserves
-- the frozen v1/v2 inspection semantics and never implies content continuity.

ALTER TABLE governed_loop_attempt ADD COLUMN executor_representation_content TEXT;
ALTER TABLE governed_loop_attempt ADD COLUMN executor_representation_method TEXT;
