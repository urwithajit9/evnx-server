-- migrations/002_add_x25519_pubkey.sql

ALTER TABLE users ADD COLUMN x25519_public_key TEXT;

-- Backfill: for existing users, this will be null until they re-login
-- (re-login derives keypair from encrypted_private_key + master_key,
--  then the CLI can upload the x25519_public_key)

-- For new registrations: make it NOT NULL
-- (do the backfill first in prod, then apply the constraint)
-- ALTER TABLE users ALTER COLUMN x25519_public_key SET NOT NULL;