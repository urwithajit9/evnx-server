-- 008: every account is on a plan, and the plan is a closed set.
--
-- ⚠️ Why this lands before anyone is invited, rather than when billing is built.
--
-- Limits are far harder to introduce after people are using a service than before.
-- An account that already holds nine vaults cannot be told it may have three without
-- either grandfathering it forever or taking something away — and P6's own notes
-- already anticipate that, describing read-only-mode machinery for downgrades. That
-- machinery is only needed *because* the limit arrived late.
--
-- So the column exists now and the enforcement with it. What is deliberately NOT here
-- is the numbers: those live in configuration, so every tier's limits can change
-- without a migration or a release. The existence of limits is the one-way door; the
-- values stay reversible.
--
-- Billing, seats and organisations are a separate and much later problem. This says
-- only which plan an account is on.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS plan TEXT NOT NULL DEFAULT 'free';

-- ⚠️ VALIDATED, not NOT VALID — unlike migration 004's wrap constraint, and for the
-- opposite reason. Every existing row was just given 'free' by the DEFAULT above, so
-- the scan cannot fail: there is no pre-existing data to disagree with it. 004 had to
-- be forward-only because real rows predated its rule.
--
-- The set is closed for the same reason `vault_members_role_is_known` closes roles: a
-- typo in a plan name would otherwise resolve to "no limits found" and silently grant
-- an account everything.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'users_plan_is_known'
    ) THEN
        ALTER TABLE users
            ADD CONSTRAINT users_plan_is_known
            CHECK (plan IN ('free', 'team', 'enterprise'));
    END IF;
END $$;

-- Quota checks count a user's vaults on every create, so the lookup that answers
-- "how many do they own" should not be a sequential scan once there are accounts
-- with many. Partial, because soft-deleted vaults do not count toward a limit.
CREATE INDEX IF NOT EXISTS idx_vaults_owner_live
    ON vaults (owner_id)
    WHERE deleted_at IS NULL;

COMMENT ON COLUMN users.plan IS
    'Billing tier. Limits per plan come from configuration, not from this table — see Config::quotas.';
