-- 013: paying does not assign a seat, and nothing told anyone.
--
-- ═══ Why a paid plan can change nothing ═════════════════════════════════════
--
-- `quota::resolve_plan` joins the member row with
-- `AND m.seat_assigned_at IS NOT NULL` **in the JOIN condition**, so a member
-- holding no seat does not join at all and `COALESCE(o.plan, u.plan)` falls
-- through to the account's own plan.
--
-- ⛔ And the default is unassigned. `routes/orgs.rs` inserts the owner with
-- `seat_assigned_at = NULL` explicitly, so the person who pays is — by default
-- — not holding a seat. That is not an edge case, it is the only path: buy a
-- team plan, run `evnx auth status`, and it still says `free`, `1 / 3`.
--
-- The fix is to say so, by email and on the billing screen. This column is what
-- makes the email send exactly once.
--
-- ═══ Why this is needed at all ══════════════════════════════════════════════
--
-- ⚠️ A single purchase produces MORE THAN ONE applied event. The first real
-- purchase (2026-10-11) delivered `subscription.created` and
-- `subscription.activated` **three milliseconds apart**, and both applied —
-- because the ordering guard is `billing_updated_at <= $n`, newer-*or-equal*,
-- so an event sharing a timestamp is not rejected.
--
-- Sending on "the update applied" would therefore send two emails for one
-- purchase. Nothing in the existing schema distinguishes the second event from
-- the first.
--
-- ═══ Why the subscription id, and not a timestamp ═══════════════════════════
--
-- A `seat_prompt_sent_at TIMESTAMPTZ` would be the obvious shape and would be
-- wrong in one direction that matters: somebody who cancels and subscribes
-- again a year later is in exactly the state this email exists for, and a bare
-- timestamp suppresses it forever. Keyed on the subscription, a new
-- subscription prompts again and a retry of the same one does not.
--
-- ⚠️ TEXT, matching `paddle_subscription_id`. Paddle ids are opaque strings
-- (`sub_01m4nvj3jr0z6956h4rpfk93ty`) and must never be parsed or shortened.
--
-- ═══ How the send is claimed ════════════════════════════════════════════════
--
-- One statement, never read-then-write — the same discipline as the ordering
-- guard, and for the same reason: two deliveries race each other.
--
--     UPDATE organizations
--        SET seat_prompt_sent_for = $2
--      WHERE id = $1
--        AND seat_prompt_sent_for IS DISTINCT FROM $2
--        AND NOT EXISTS (SELECT 1 FROM organization_members
--                         WHERE org_id = $1 AND seat_assigned_at IS NOT NULL)
--     RETURNING owner_id
--
-- ⚠️ `IS DISTINCT FROM`, not `<>`. The column starts NULL, and `NULL <> 'sub_…'`
-- is NULL rather than true — so with `<>` the very first send would never fire.
-- This is the whole reason the column cannot be compared the obvious way.
--
-- The `NOT EXISTS` clause is not an optimisation: it stops the email telling
-- someone to do a thing they have already done.
--
-- ⓘ One accepted consequence. If a seat is assigned and later released, the
-- claim never happened, so the next subscription event sends the prompt. The
-- email is accurate when it arrives — nobody holds a seat — so this is a quirk
-- rather than a defect, and it is better than the alternative of marking a
-- prompt sent that nobody needed.

ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS seat_prompt_sent_for TEXT;

COMMENT ON COLUMN organizations.seat_prompt_sent_for IS
    'The paddle_subscription_id the "assign a seat" email was last sent for; '
    'NULL means never. Keyed on the subscription rather than a timestamp so '
    'that cancelling and subscribing again prompts again, which a bare '
    'sent_at would suppress forever. Claimed by a single conditional UPDATE '
    'using IS DISTINCT FROM — `<>` is NULL against the NULL start value and '
    'would never fire.';
