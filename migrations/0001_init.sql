CREATE TABLE users (
    id               TEXT    PRIMARY KEY,
    -- Emails are normalized to lowercase by the application before any write
    -- or lookup, so a plain UNIQUE constraint gives case-insensitive accounts
    -- (the SQLite build relied on `COLLATE NOCASE` for the same effect).
    email            TEXT    NOT NULL UNIQUE,
    -- XChaCha20-Poly1305 sealed TOTP secret: 24-byte nonce || ciphertext||tag,
    -- AAD-bound to the (immutable) email column.
    secret_enc       BYTEA   NOT NULL,
    totp_confirmed   BOOLEAN NOT NULL DEFAULT FALSE,
    -- Highest TOTP time-step counter already accepted for this user.
    -- Successful logins must present a strictly newer period (replay protection).
    last_used_period BIGINT  NOT NULL DEFAULT 0,
    created_at       BIGINT  NOT NULL,
    updated_at       BIGINT  NOT NULL
);

CREATE TABLE recovery_codes (
    id        BIGSERIAL PRIMARY KEY,
    user_id   TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- Argon2id PHC string of the normalized recovery code.
    code_hash TEXT NOT NULL,
    used_at   BIGINT
);

CREATE INDEX idx_recovery_codes_user ON recovery_codes (user_id);
