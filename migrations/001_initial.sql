-- migrations/001_initial.sql
-- Full schema — see Phase 1 plan for column-by-column explanation.
-- Run with: sqlx migrate run

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Users: ZKE material stored here. Password NEVER stored.
CREATE TABLE users (
    id                    UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email                 TEXT NOT NULL UNIQUE,
    email_verified        BOOLEAN NOT NULL DEFAULT FALSE,
    srp_verifier          TEXT NOT NULL,
    srp_salt              TEXT NOT NULL,
    argon2_salt           TEXT NOT NULL,
    ed25519_public_key    TEXT NOT NULL,
    encrypted_private_key TEXT NOT NULL,
    totp_secret_enc       TEXT,
    totp_enabled          BOOLEAN NOT NULL DEFAULT FALSE,
    is_active             BOOLEAN NOT NULL DEFAULT TRUE,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at         TIMESTAMPTZ
);

CREATE TABLE vaults (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        TEXT NOT NULL,
    environment TEXT NOT NULL DEFAULT 'production',
    owner_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at  TIMESTAMPTZ,
    UNIQUE(owner_id, name, environment)
);

CREATE TABLE vault_members (
    vault_id              UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    user_id               UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role                  TEXT NOT NULL DEFAULT 'viewer',
    encrypted_vault_key   TEXT NOT NULL,
    eph_pub_key           TEXT,
    granted_by            UUID REFERENCES users(id),
    granted_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (vault_id, user_id)
);

CREATE TABLE vault_versions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    vault_id        UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    version_num     INTEGER NOT NULL,
    blob_key        TEXT NOT NULL UNIQUE,
    blob_size_bytes INTEGER NOT NULL,
    blob_hash       TEXT NOT NULL,
    key_count       INTEGER NOT NULL DEFAULT 0,
    key_names       TEXT[],
    pushed_by       UUID NOT NULL REFERENCES users(id),
    pushed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(vault_id, version_num)
);

CREATE TABLE api_tokens (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    scope        TEXT NOT NULL DEFAULT 'read',
    vault_id     UUID REFERENCES vaults(id) ON DELETE CASCADE,
    expires_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE refresh_tokens (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id UUID NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE audit_events (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    vault_id        UUID REFERENCES vaults(id) ON DELETE SET NULL,
    user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type      TEXT NOT NULL,
    ip_hash         TEXT,
    user_agent_hash TEXT,
    metadata        JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE email_verifications (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '24 hours',
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_vaults_owner          ON vaults(owner_id)                          WHERE deleted_at IS NULL;
CREATE INDEX idx_vault_members_user    ON vault_members(user_id);
CREATE INDEX idx_vault_versions_vault  ON vault_versions(vault_id, version_num DESC);
CREATE INDEX idx_audit_events_vault    ON audit_events(vault_id, created_at DESC);
CREATE INDEX idx_audit_events_user     ON audit_events(user_id, created_at DESC);
CREATE INDEX idx_api_tokens_hash       ON api_tokens(token_hash)                    WHERE revoked_at IS NULL;
CREATE INDEX idx_refresh_tokens_hash   ON refresh_tokens(token_hash)                WHERE revoked_at IS NULL;