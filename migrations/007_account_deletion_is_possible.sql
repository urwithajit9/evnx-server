-- Make deleting a user possible at all.
--
-- ⚠️ Before this migration, `DELETE FROM users` failed for **anyone who had ever
-- used the product**. Two foreign keys were declared without an `ON DELETE`
-- clause, so they defaulted to `NO ACTION`:
--
--     vault_versions.pushed_by  UUID NOT NULL REFERENCES users(id)
--     vault_members.granted_by  UUID          REFERENCES users(id)
--
-- Push one version, or share one vault, and your account became undeletable —
-- surfacing as a bare foreign-key violation a long way from its cause. Right to
-- erasure is not optional for EU users, so this was a compliance problem hiding
-- as a schema default.
--
-- ─── Why SET NULL and not CASCADE ────────────────────────────────────────────
--
-- CASCADE on `pushed_by` would delete every version that user ever pushed — from
-- vaults that may belong to other people. Deleting your account must not destroy
-- someone else's history.
--
-- SET NULL keeps the row and forgets the person, which is exactly the trade
-- `audit_events.user_id` already makes (001) and which migration 006 wrote a
-- trigger exemption for. "Who pushed v7" becomes unknown; "v7 exists, here is its
-- blob" stays true. A vault stays openable, which is the property that matters.
--
-- `pushed_by` therefore has to lose its NOT NULL. Readers must treat it as
-- optional: an absent pusher means a deleted account, not a corrupt row.

-- ── vault_versions.pushed_by ────────────────────────────────────────────────

ALTER TABLE vault_versions ALTER COLUMN pushed_by DROP NOT NULL;

-- The constraints were created anonymously in 001, so Postgres named them.
-- Looking the name up rather than assuming `<table>_<column>_fkey` keeps this
-- working if an environment was ever built differently — and a migration that
-- guesses a name fails at startup, which is the worst place to find out.
DO $$
DECLARE
    con_name text;
BEGIN
    SELECT conname INTO con_name
    FROM pg_constraint
    WHERE conrelid = 'vault_versions'::regclass
      AND contype  = 'f'
      AND conkey   = ARRAY[(
          SELECT attnum FROM pg_attribute
          WHERE attrelid = 'vault_versions'::regclass AND attname = 'pushed_by'
      )]::smallint[];

    IF con_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE vault_versions DROP CONSTRAINT %I', con_name);
    END IF;
END $$;

ALTER TABLE vault_versions
    ADD CONSTRAINT vault_versions_pushed_by_fkey
    FOREIGN KEY (pushed_by) REFERENCES users(id) ON DELETE SET NULL;

-- ── vault_members.granted_by ────────────────────────────────────────────────

DO $$
DECLARE
    con_name text;
BEGIN
    SELECT conname INTO con_name
    FROM pg_constraint
    WHERE conrelid = 'vault_members'::regclass
      AND contype  = 'f'
      AND conkey   = ARRAY[(
          SELECT attnum FROM pg_attribute
          WHERE attrelid = 'vault_members'::regclass AND attname = 'granted_by'
      )]::smallint[];

    IF con_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE vault_members DROP CONSTRAINT %I', con_name);
    END IF;
END $$;

ALTER TABLE vault_members
    ADD CONSTRAINT vault_members_granted_by_fkey
    FOREIGN KEY (granted_by) REFERENCES users(id) ON DELETE SET NULL;

-- ─── What this migration deliberately does NOT change ───────────────────────
--
-- `vaults.owner_id` stays ON DELETE CASCADE, and that is why the delete-account
-- handler refuses to run while you own a vault anyone else is a member of.
--
-- Relaxing it here would be the wrong fix: an owner-less vault is one nobody can
-- administer, share or re-key, and the server cannot promote a new owner because
-- it cannot wrap the vault key for them — it has never seen it. The constraint is
-- correct; the handler is where the conflict gets named, so the person doing the
-- deleting can resolve it.
--
-- Solo vaults — the ones where the account being deleted is the only member —
-- cascade away as intended, and the handler removes their blobs from object
-- storage first, since a cascading row delete cannot reach them.
