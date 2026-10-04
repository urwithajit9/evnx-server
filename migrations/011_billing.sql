-- 011: an organisation can have a Paddle subscription.
--
-- ═══ What this does NOT change ══════════════════════════════════════════════
--
-- ⚠️ `organizations.plan` and `organizations.seats` keep exactly the meaning
-- migration 010 gave them, and `quota::resolve_plan` is untouched. Every limit in
-- the server already routes through that one function; billing simply becomes a
-- new writer of two columns it already reads.
--
-- That is the whole point of the shape. A subscription is not a third source of
-- truth about what someone may do — it is the thing that sets `plan` and `seats`,
-- and nothing downstream needs to know it exists.
--
-- ⛔ And none of this touches a vault. A lapsed subscription changes an
-- organisation's limits. It cannot lock anyone out of a secret, and nothing is
-- deleted for non-payment — the server could not read it in order to delete it.

ALTER TABLE organizations
    -- Paddle's customer, so the billing screen can open a portal session for
    -- updating a card or reading invoices without us storing either.
    ADD COLUMN IF NOT EXISTS paddle_customer_id TEXT,

    -- ⚠️ UNIQUE. One subscription pays for one organisation. Two organisations
    -- sharing a subscription id would mean a webhook updating both, and a
    -- cancellation silently downgrading an organisation nobody cancelled.
    ADD COLUMN IF NOT EXISTS paddle_subscription_id TEXT,

    -- Mirrors Paddle's status. NULL means no subscription has ever existed,
    -- which is different from `canceled` and the billing screen says so.
    ADD COLUMN IF NOT EXISTS subscription_status TEXT,

    -- When the paid period ends. ⚠️ Load-bearing for `canceled`: a cancelled
    -- subscription keeps its plan until this passes, which is the state everyone
    -- forgets and the one people feel cheated by if it is got wrong.
    ADD COLUMN IF NOT EXISTS current_period_ends_at TIMESTAMPTZ,

    -- ⚠️ Paddle delivers webhooks out of order and more than once. This is the
    -- `occurred_at` of the newest event applied, and an event older than it is
    -- ignored. Without it, a retried `subscription.updated` from before a
    -- cancellation would quietly resurrect the subscription.
    ADD COLUMN IF NOT EXISTS billing_updated_at TIMESTAMPTZ;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'organizations_subscription_is_unique'
    ) THEN
        ALTER TABLE organizations
            ADD CONSTRAINT organizations_subscription_is_unique
            UNIQUE (paddle_subscription_id);
    END IF;
END $$;

-- Closed set, matching Paddle's own statuses plus NULL for "never subscribed".
-- Same reasoning as every other closed set here: an unrecognised value would
-- resolve to "no limits found" somewhere downstream and silently grant or revoke.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'organizations_subscription_status_is_known'
    ) THEN
        ALTER TABLE organizations
            ADD CONSTRAINT organizations_subscription_status_is_known
            CHECK (subscription_status IS NULL OR subscription_status IN (
                'trialing', 'active', 'past_due', 'paused', 'canceled'
            ));
    END IF;
END $$;

-- The webhook looks an organisation up by subscription id on every event, and
-- that is the only query it makes before deciding what to write.
CREATE INDEX IF NOT EXISTS idx_organizations_subscription
    ON organizations (paddle_subscription_id)
    WHERE paddle_subscription_id IS NOT NULL;

COMMENT ON COLUMN organizations.paddle_subscription_id IS
    'Paddle subscription. UNIQUE — one subscription pays for exactly one organisation.';
COMMENT ON COLUMN organizations.billing_updated_at IS
    'occurred_at of the newest webhook applied. Older events are ignored; Paddle delivers out of order and more than once.';
COMMENT ON COLUMN organizations.current_period_ends_at IS
    'A canceled subscription keeps its plan until this passes. Not the same as the subscription being over.';
