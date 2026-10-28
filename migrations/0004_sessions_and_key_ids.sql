-- Session revocation: tokens carry the account's token_version; bumping it
-- invalidates every session issued before (POST /api/v1/logout).
ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0;

-- Fingerprint of the encryption key that sealed secret_enc, so the key can be
-- rotated: rows sealed under a retired key are re-sealed on next use or by
-- `totp-server rekey`. NULL marks rows sealed before key ids existed; those
-- are tried against every configured key.
ALTER TABLE users ADD COLUMN secret_key_id TEXT;
