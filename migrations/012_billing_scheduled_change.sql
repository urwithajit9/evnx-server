-- 012: a subscription can be scheduled to end without having ended.
--
-- ═══ The state everyone forgets ═════════════════════════════════════════════
--
-- ⚠️ When a customer cancels in Paddle, the subscription does **not** become
-- `canceled`. Its status stays `active` and Paddle attaches a `scheduled_change`
-- saying what will happen and when:
--
--     "scheduled_change": { "action": "cancel", "effective_at": "2026-11-03T…" }
--
-- Migration 011 had nowhere to put that, so the server could only record
-- `active` — and the billing screen would have told someone who had just
-- cancelled that their plan *renews* on exactly the date it ends. That is the
-- single most expensive sentence a billing screen can get wrong, because the
-- person reads it, believes they failed to cancel, and cancels again through
-- their bank.
--
-- `current_period_ends_at` is not a substitute. It is set on every active
-- subscription and means "when the next invoice falls due". Renewal and ending
-- are the same date and the opposite event; nothing distinguishes them without
-- this column.
--
-- ═══ Why two columns and not a boolean ══════════════════════════════════════
--
-- Paddle schedules `cancel`, `pause` and `resume` through the same field. A
-- `cancels_at TIMESTAMPTZ` would model today's only button and silently
-- mis-describe a pause the moment one is offered — a paused subscription is not
-- a cancelled one, and the screen's wording differs completely.

ALTER TABLE organizations
    -- `cancel` | `pause` | `resume`, or NULL when nothing is scheduled.
    ADD COLUMN IF NOT EXISTS scheduled_change_action TEXT,

    -- When it takes effect. ⚠️ Until then the plan is unchanged and every limit
    -- still applies — a cancellation is a future event, not a current one.
    ADD COLUMN IF NOT EXISTS scheduled_change_at TIMESTAMPTZ,

    -- ⚠️ Which price the subscription is actually on.
    --
    -- Needed to change the seat count. Paddle's update operation replaces the
    -- whole `items` list, so it takes a price id as well as a quantity — and
    -- sending the wrong one would silently move a customer between plans, or
    -- from yearly to monthly, while they thought they were adding a seat.
    --
    -- `plan` is not a substitute: two prices map to `team` (monthly and yearly)
    -- and the interval cannot be recovered from the plan name.
    ADD COLUMN IF NOT EXISTS paddle_price_id TEXT;

-- Closed set, the same reasoning as `subscription_status`: an unrecognised
-- action would reach the billing screen and render as nothing at all, which
-- reads as "no change scheduled" — the one wrong answer.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'organizations_scheduled_change_is_known'
    ) THEN
        ALTER TABLE organizations
            ADD CONSTRAINT organizations_scheduled_change_is_known
            CHECK (scheduled_change_action IS NULL OR scheduled_change_action IN (
                'cancel', 'pause', 'resume'
            ));
    END IF;
END $$;

-- ⚠️ Both or neither. An action with no date cannot be rendered ("your plan ends
-- on — "), and a date with no action cannot be interpreted. Either half alone is
-- a bug that only shows up on a customer's screen.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'organizations_scheduled_change_is_whole'
    ) THEN
        ALTER TABLE organizations
            ADD CONSTRAINT organizations_scheduled_change_is_whole
            CHECK (
                (scheduled_change_action IS NULL     AND scheduled_change_at IS NULL)
             OR (scheduled_change_action IS NOT NULL AND scheduled_change_at IS NOT NULL)
            );
    END IF;
END $$;

COMMENT ON COLUMN organizations.scheduled_change_action IS
    'A cancellation/pause/resume Paddle has scheduled but not yet applied. The status stays `active` until scheduled_change_at passes.';
COMMENT ON COLUMN organizations.scheduled_change_at IS
    'When the scheduled change takes effect. Until then the plan and every limit are unchanged.';

COMMENT ON COLUMN organizations.paddle_price_id IS
    'The price the subscription is on. Required to change quantity without also changing plan or billing interval.';
