-- migrations/015_rotation_snapshots_are_audit_only.sql
--
-- A master-key rotation snapshot keeps the previous verifier, salts, sealed
-- seed and wraps for the undo window (migration 009). Once the window is over,
-- or the snapshot has been restored or superseded, nothing can use them again,
-- so they no longer belong in the row. The row stays, for the record of when a
-- rotation happened and how it ended.
--
-- Until now nothing removed that material: `expire_stale_snapshots` closed a
-- row but left every column filled, and only ran for an account that rotated a
-- second time. Application code now clears the columns whenever a snapshot is
-- closed, and clears expired ones on a timer. This migration does the same for
-- rows that already exist, and makes the database refuse the old state.

-- The columns held NOT NULL because a live snapshot always has them. A closed
-- one now has none, so the constraint moves from the column to the row.
ALTER TABLE master_key_rotations
    ALTER COLUMN prev_srp_salt              DROP NOT NULL,
    ALTER COLUMN prev_srp_verifier          DROP NOT NULL,
    ALTER COLUMN prev_argon2_salt           DROP NOT NULL,
    ALTER COLUMN prev_encrypted_private_key DROP NOT NULL,
    ALTER COLUMN prev_wraps                 DROP NOT NULL;

-- Snapshots whose window has run out but which nothing has closed yet. Closed
-- the way `expire_stale_snapshots` closes them. This also frees the
-- one-live-snapshot-per-account index for the account's next rotation.
UPDATE master_key_rotations
   SET consumed_at = NOW(), outcome = 'expired'
 WHERE consumed_at IS NULL
   AND expires_at <= NOW();

-- Everything that is closed, whatever the outcome.
UPDATE master_key_rotations
   SET prev_srp_salt              = NULL,
       prev_srp_verifier          = NULL,
       prev_argon2_salt           = NULL,
       prev_encrypted_private_key = NULL,
       prev_wraps                 = NULL
 WHERE consumed_at IS NOT NULL;

-- A live snapshot is whole: restoring half of one would leave an account that
-- opens nothing.
ALTER TABLE master_key_rotations
    ADD CONSTRAINT master_key_rotations_live_row_has_material
    CHECK (consumed_at IS NOT NULL
        OR (prev_srp_salt IS NOT NULL
            AND prev_srp_verifier IS NOT NULL
            AND prev_argon2_salt IS NOT NULL
            AND prev_encrypted_private_key IS NOT NULL
            AND prev_wraps IS NOT NULL));

-- A closed snapshot holds nothing. Without this, the next code path that closes
-- a row and forgets to clear it would bring the old state back without a sound.
ALTER TABLE master_key_rotations
    ADD CONSTRAINT master_key_rotations_closed_row_holds_nothing
    CHECK (consumed_at IS NULL
        OR (prev_srp_salt IS NULL
            AND prev_srp_verifier IS NULL
            AND prev_argon2_salt IS NULL
            AND prev_encrypted_private_key IS NULL
            AND prev_wraps IS NULL));

COMMENT ON TABLE master_key_rotations IS
    'One live snapshot per account of the material replaced by a master-key rotation, for the undo window. Restoring it is authorised by proving the OLD password - see routes/master_key.rs. A closed row (consumed_at set) keeps only the audit facts; its prev_* columns are NULL.';
