-- Reliance-refusal subject preservation (finding N-5): a stored refusal must
-- be able to say what was refused, for whom, about which observation.
-- Nullable: rows written before this migration genuinely lack a subject, and
-- that absence is exposed as absence, never defaulted.
ALTER TABLE reliance_refusal ADD COLUMN observation TEXT;
ALTER TABLE reliance_refusal ADD COLUMN consumer TEXT;
ALTER TABLE reliance_refusal ADD COLUMN claim TEXT;
