-- migrations/016_wrap_is_whole_is_validated.sql
--
-- Remove the vault key wraps that migration 004's CHECK was left unable to
-- cover, then validate that CHECK for every row.
--
-- `vault_members_wrap_is_whole` says a wrap is either an own copy (no ephemeral
-- key, no ML-KEM ciphertext) or a hybrid share (both). Migration 004 added it
-- NOT VALID so databases holding pre-hybrid shares could still upgrade: those
-- rows carry an ephemeral key and no ML-KEM ciphertext, and were exempt.
--
-- A client will not open such a wrap. It requires the ML-KEM half, so the member
-- has had no access since the hybrid format shipped and the row can only be
-- replaced by sharing the vault again. Leaving the rows does nothing except keep
-- the constraint unvalidated, and 005 records that an UPDATE touching an exempt
-- row fails.
--
-- ─── What this removes ───────────────────────────────────────────────────────
--
-- Rows with exactly one of eph_pub_key and mlkem_ciphertext set, and a role
-- other than 'owner'. The member loses a grant that did not work.
--
-- ─── What it refuses to do ───────────────────────────────────────────────────
--
-- If such a row has role 'owner' the migration stops with an error instead of
-- deleting it. An owner's own copy never uses key agreement, so a violating
-- owner row is a bug or a test fixture rather than history, and removing it
-- would take the vault away from the person who owns it. It is worth a person
-- looking at.
--
-- ─── Check first (read-only) ─────────────────────────────────────────────────
--
--     SELECT count(*) FILTER (WHERE role <> 'owner') AS will_be_removed,
--            count(*) FILTER (WHERE role =  'owner') AS will_stop_the_migration
--       FROM vault_members
--      WHERE (eph_pub_key IS NULL) <> (mlkem_ciphertext IS NULL);
--
--     SELECT conname, convalidated FROM pg_constraint
--      WHERE conname = 'vault_members_wrap_is_whole';
--
-- Production had no such rows and the constraint was validated there by hand on
-- 2026-09-18 (see 005), in which case this migration changes nothing there.
--
-- To see who would lose a grant:
--
--     SELECT v.name, v.environment, m.role, u.email, m.granted_at
--       FROM vault_members m
--       JOIN vaults v ON v.id = m.vault_id
--       JOIN users  u ON u.id = m.user_id
--      WHERE (m.eph_pub_key IS NULL) <> (m.mlkem_ciphertext IS NULL);

DO $$
DECLARE
    owner_rows bigint;
    removed    bigint;
BEGIN
    SELECT count(*) INTO owner_rows
      FROM vault_members
     WHERE (eph_pub_key IS NULL) <> (mlkem_ciphertext IS NULL)
       AND role = 'owner';

    IF owner_rows > 0 THEN
        RAISE EXCEPTION
            'migration 016: % owner row(s) in vault_members have exactly one of eph_pub_key and mlkem_ciphertext. Not deleting them: look at them first (see the query at the top of this file).',
            owner_rows;
    END IF;

    DELETE FROM vault_members
     WHERE (eph_pub_key IS NULL) <> (mlkem_ciphertext IS NULL);
    GET DIAGNOSTICS removed = ROW_COUNT;

    RAISE NOTICE 'migration 016: removed % unopenable shared wrap(s)', removed;
END
$$;

ALTER TABLE vault_members VALIDATE CONSTRAINT vault_members_wrap_is_whole;
