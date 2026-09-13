-- migrations/003_totp_backup_codes.sql
--
-- Recovery codes for TOTP.
--
-- Without these, enabling TOTP is a one-way door: a user who loses their
-- authenticator can never log in again, and because the server holds only
-- ciphertext it cannot recover their vaults either. That is data loss, not an
-- inconvenience, so recovery has to exist before anyone enables TOTP.
--
-- Codes are stored as BLAKE3 hashes, exactly like api_tokens: the plaintext is
-- shown to the user once at generation and never again.

CREATE TABLE totp_backup_codes (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- The same code can never be stored twice for one user, so a redemption
    -- cannot match more than one row.
    UNIQUE (user_id, code_hash)
);

-- Redemption looks up unused codes for one user; that is the only hot query.
CREATE INDEX idx_totp_backup_codes_unused
    ON totp_backup_codes (user_id, code_hash)
    WHERE used_at IS NULL;
