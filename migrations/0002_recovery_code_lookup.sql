-- Clear-text prefix of each recovery code (its first symbols, normalized), so
-- a recovery attempt verifies one Argon2id hash instead of every unused code.
-- Rows written before this column existed stay NULL and are still checked.
ALTER TABLE recovery_codes ADD COLUMN lookup TEXT;

CREATE INDEX idx_recovery_codes_user_lookup
    ON recovery_codes (user_id, lookup)
    WHERE used_at IS NULL;
