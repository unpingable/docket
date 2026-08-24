-- Optional descriptor-bound first-stage custody added after the frozen v1
-- governed-loop tables. NULL means the legacy pathname-invocation contract;
-- it never means descriptor custody.

ALTER TABLE governed_loop_attempt ADD COLUMN executor_program_content TEXT;
ALTER TABLE governed_loop_attempt ADD COLUMN executor_expected_content TEXT;
ALTER TABLE governed_loop_attempt ADD COLUMN executor_invocation_method TEXT;
ALTER TABLE governed_loop_attempt ADD COLUMN executor_launch TEXT;
ALTER TABLE governed_loop_attempt ADD COLUMN executor_dispatch_content TEXT;
