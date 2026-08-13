-- Bind the exact executor-configuration bytes independently of the executor's
-- reported plan identity. Historical custody rows cannot be backfilled from a
-- mutable path; their NULL value therefore fails closed on read.

ALTER TABLE governed_loop_attempt ADD COLUMN executor_config_digest TEXT;
