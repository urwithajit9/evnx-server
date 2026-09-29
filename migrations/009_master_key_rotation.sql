-- 009: changing the master password is possible, and survivable.
--
-- ⚠️ Read this before changing anything here. Master-key rotation is the only
-- operation in the system that can destroy every vault an account owns, and the
-- server cannot tell a correct rotation from random bytes — that is what zero
-- knowledge means. The whole safety story is therefore procedural, and half of it
-- lives in this table.
--
-- ─── What rotation does ──────────────────────────────────────────────────────
--
-- Four columns on `users` (srp_salt, srp_verifier, argon2_salt,
-- encrypted_private_key) and one column on each of the account's OWN-COPY
-- `vault_members` rows (encrypted_vault_key, where eph_pub_key IS NULL).
--
-- It does NOT touch the public keys. The identity keypair is derived from a seed
-- that rotation re-seals rather than replaces — `routes/users.rs` already states
-- this, and `backfill_public_keys` is write-once precisely because a mutable
-- public key is a share-interception primitive. Rotation must not become the
-- second way to do what that endpoint refuses.
--
-- It does NOT touch rows where eph_pub_key IS NOT NULL. Those are vault keys
-- shared TO this account, wrapped to the keypair, which does not change.
--
-- ─── Why a snapshot exists at all ────────────────────────────────────────────
--
-- An attacker holding a stolen session cannot produce a VALID rotation — that
-- needs the old password, to unwrap before re-wrapping. But they can send
-- garbage, and the server has no way to refuse it. The result is an account
-- whose owner can no longer log in and whose vaults no longer open, permanently.
--
-- So the previous material is kept for a window, and restoring it is authorised
-- by proving the OLD password — the one credential that separates the victim
-- from the attacker in exactly that case.
--
-- ⚠️ The tension, stated rather than buried: while a window is open, a rotation
-- performed BECAUSE the old password leaked is reversible by whoever leaked it.
-- That is why the rotation request carries a reason: 'compromised' stores no
-- snapshot and takes effect immediately; 'routine' keeps the window. The default
-- is 'routine', because the common case is routine and the common disaster is
-- lockout.

CREATE TABLE IF NOT EXISTS master_key_rotations (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    rotated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ NOT NULL,

    -- The account material as it was immediately before the rotation.
    --
    -- ⚠️ `prev_srp_verifier` is the same class of secret the `users` row already
    -- holds, not a new one: a verifier is not a password and cannot be replayed
    -- as one. It does mean a database breach exposes two verifiers for this
    -- account rather than one, for as long as the window is open — which is the
    -- price of the window and is bounded by it.
    prev_srp_salt              TEXT NOT NULL,
    prev_srp_verifier          TEXT NOT NULL,
    prev_argon2_salt           TEXT NOT NULL,
    prev_encrypted_private_key TEXT NOT NULL,

    -- [{ "vault_id": "...", "encrypted_vault_key": "..." }, ...]
    --
    -- JSONB rather than a child table because it is a snapshot restored
    -- wholesale and never queried by content. A child table would invite a
    -- partial restore, and a partially restored account opens nothing.
    prev_wraps   JSONB NOT NULL,

    -- Set when the snapshot stops being the live one. `outcome` says why.
    consumed_at  TIMESTAMPTZ,
    outcome      TEXT,

    CONSTRAINT master_key_rotations_outcome_is_known
        CHECK (outcome IS NULL OR outcome IN ('restored', 'expired', 'superseded')),

    -- consumed_at and outcome move together, so a row can never say "finished"
    -- without saying how — the same shape as vault_members_wrap_is_whole.
    CONSTRAINT master_key_rotations_outcome_is_whole
        CHECK ((consumed_at IS NULL AND outcome IS NULL)
            OR (consumed_at IS NOT NULL AND outcome IS NOT NULL))
);

-- ⚠️ **At most one live snapshot per account, and it is the OLDEST one in the
-- window — not the newest.** This index is what enforces it, together with an
-- `ON CONFLICT DO NOTHING` on insert.
--
-- That ordering is a security property, not a tidiness one. Consider an attacker
-- who has rotated the account to a password they chose. They now know the
-- current password, so nothing stops them rotating a second time. If a second
-- rotation replaced the snapshot, the stored "previous" material would be the
-- attacker's own garbage state, and the victim's real material would be gone —
-- the undo would restore them into the same locked-out account.
--
-- Keeping the first snapshot means no number of chained rotations can erase the
-- last state the real owner could actually have produced.
--
-- The cost is small and arguably right: someone who legitimately rotates twice
-- inside the window can only undo as far back as the first. "Undo takes you to
-- your last known-good state" is the behaviour people expect anyway.
CREATE UNIQUE INDEX IF NOT EXISTS idx_master_key_rotations_one_live
    ON master_key_rotations (user_id)
    WHERE consumed_at IS NULL;

-- The undo path looks a snapshot up by account. Small table, but the lookup sits
-- on an unauthenticated endpoint, so it should not be a sequential scan.
CREATE INDEX IF NOT EXISTS idx_master_key_rotations_user
    ON master_key_rotations (user_id, rotated_at DESC);

COMMENT ON TABLE master_key_rotations IS
    'One live snapshot per account of the material replaced by a master-key rotation. Restoring it is authorised by proving the OLD password — see routes/master_key.rs.';
