-- 010: organisations — billing and a directory, and deliberately nothing else.
--
-- ═══ What an organisation is, and the one thing it is not ════════════════════
--
-- An organisation owns a PLAN and a set of SEATS. A seat holder is billed for and
-- gets that plan's limits. That is the whole feature.
--
-- ⛔ AN ORGANISATION CANNOT GRANT ACCESS TO A VAULT, and no amount of later work
-- will change that. Vault access means holding the vault key, wrapped to your
-- public key; the server has never been able to wrap a vault key and that is the
-- product's central guarantee, not a gap in it. Sharing stays a deliberate act by
-- a vault admin who holds the key — `evnx vault share`.
--
-- Note what is absent below: there is no reference from `organizations` to
-- `vaults`, and none from `organization_members` to `vault_members`. The
-- separation is structural, by having no column that could express it. Anyone
-- adding one is removing the guarantee.
--
-- ⚠️ This WILL be the first support question. "I added them to the org, why can't
-- they see the vault?" Every surface — CLI output, app UI, the invite email — has
-- to answer it before it is asked.
--
-- ═══ Why the plan lives here as well as on `users` ═══════════════════════════
--
-- Migration 008 put `plan` on `users`, and `quota::plan_for()` reads it. Solo
-- accounts are not going away, so that column stays and stays authoritative for
-- anyone without a seat. An organisation does not replace it — it OVERRIDES it for
-- the duration of a seat.
--
-- So after this migration there are two sources for one answer, and exactly one
-- function resolves them: `quota::plan_for()`. Every quota check in the server
-- already routes through it, which is what makes this a small change rather than a
-- sweep.

CREATE TABLE IF NOT EXISTS organizations (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        TEXT NOT NULL,

    -- Addressable in a CLI flag (`evnx org members --org acme`) and later in a URL,
    -- so the shape is constrained rather than trusted.
    --
    -- ⚠️ The CHECK excludes `.` on purpose. A vault named `..` sanitised to exactly
    -- `..` and escaped its output directory in `cloud export` — found while building
    -- v0.8.0. A slug is user-supplied text that will end up in paths and URLs, so it
    -- is constrained at the one place that cannot be forgotten.
    slug        TEXT NOT NULL UNIQUE
                CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),

    owner_id    UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,

    plan        TEXT NOT NULL DEFAULT 'free',

    -- Purchased seats. NULL is unlimited, spelled the same way a quota is.
    --
    -- ⚠️ NOT enforced by a trigger, and that is a decision. A trigger counting
    -- assigned seats would refuse the INSERT that exceeds them — including the one
    -- Paddle's webhook makes when a subscription is DOWNGRADED, which would leave
    -- billing and the database disagreeing with no way to reconcile. The handler
    -- refuses a seat assignment that would exceed `seats`; a downgrade may leave an
    -- org over-seated, and that is reported rather than refused.
    seats       INTEGER CHECK (seats IS NULL OR seats >= 0),

    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Soft delete, matching `vaults`. ⚠️ `plan_for()` MUST ignore a deleted org, or
    -- deleting one silently keeps granting its plan to every former seat holder.
    deleted_at  TIMESTAMPTZ
);

-- Closed set, same reasoning as `users_plan_is_known` and
-- `vault_members_role_is_known`: a typo would resolve to "no limits found" and
-- silently grant an org everything.
--
-- ⚠️ These three names must move together with `quota::Plan::ALL`, migration 008's
-- `users_plan_is_known`, and `GET /api/v1/plans`. A tier in one and not the others
-- is a tier nobody can hold, read back, or buy.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'organizations_plan_is_known'
    ) THEN
        ALTER TABLE organizations
            ADD CONSTRAINT organizations_plan_is_known
            CHECK (plan IN ('free', 'team', 'enterprise'));
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS organization_members (
    org_id            UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id           UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    role              TEXT NOT NULL DEFAULT 'member',

    -- NULL means "in the directory, holding no seat" — a real state, not a
    -- placeholder. Someone can be listed in an org without being billed for.
    seat_assigned_at  TIMESTAMPTZ,

    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (org_id, user_id)
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'organization_members_role_is_known'
    ) THEN
        ALTER TABLE organization_members
            ADD CONSTRAINT organization_members_role_is_known
            CHECK (role IN ('owner', 'admin', 'member'));
    END IF;
END $$;

-- ═══ AT MOST ONE SEAT PER PERSON ════════════════════════════════════════════
--
-- Directory membership is unconstrained — you may appear in as many organisations
-- as invite you, which is what makes a contractor working for two companies
-- representable. A SEAT is unique, and that is what makes `plan_for()` answer
-- exactly one plan.
--
-- ⚠️ Without this index the resolution is ambiguous, and every way of resolving it
-- is wrong in a different direction. "Highest plan wins" lets anyone with one
-- enterprise org raise the limits of every account they invite. "First wins"
-- depends on insert order, so the same two memberships give different answers on
-- two deployments. "Lowest wins" bills someone for a seat they do not benefit
-- from. Making the state unrepresentable is cheaper than choosing among three bad
-- answers — the same move as `vault_members_wrap_is_whole`.
--
-- The handler turns a violation into a message naming the organisation that
-- currently holds the seat, so an admin sees a conflict rather than silently
-- stealing a seat from another org's billing.
CREATE UNIQUE INDEX IF NOT EXISTS organization_members_one_seat_per_user
    ON organization_members (user_id)
    WHERE seat_assigned_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS organization_invites (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- The address invited, which may not have an account yet. ⚠️ Stored in the
    -- clear because the invite has to be matched to whoever redeems it, and a
    -- hash cannot be compared to an address typed at redemption time without
    -- also revealing it. It is the same exposure `email_verifications` accepts
    -- via `users.email`.
    email       TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'member',

    -- ⚠️ BLAKE3 of the token, never the token. Same discipline as
    -- `email_verifications` and `api_tokens`: an invite is a bearer credential
    -- that admits someone to a paid organisation, so a database read must not
    -- yield a usable one.
    token_hash  TEXT NOT NULL UNIQUE,

    invited_by  UUID REFERENCES users(id) ON DELETE SET NULL,

    -- Shorter than a verification link's 24 hours is wrong here (people forward
    -- these to colleagues and act on them next week) and unbounded is worse.
    expires_at  TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '7 days',

    -- Single-use. ⚠️ A used invite and a wrong token must answer identically at
    -- the API, or redemption becomes an oracle for which invitations exist.
    used_at     TIMESTAMPTZ,

    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'organization_invites_role_is_known'
    ) THEN
        ALTER TABLE organization_invites
            ADD CONSTRAINT organization_invites_role_is_known
            -- ⚠️ No 'owner'. An organisation has exactly one owner, set at
            -- creation and transferred by its own deliberate act — never handed
            -- out by an invitation, which is a link someone can forward.
            CHECK (role IN ('admin', 'member'));
    END IF;
END $$;

-- `plan_for()` runs on every quota check, so its lookup must not be a scan.
-- Partial and covering: the only rows it ever wants are assigned seats.
CREATE INDEX IF NOT EXISTS idx_org_members_seat
    ON organization_members (user_id, org_id)
    WHERE seat_assigned_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_org_members_org
    ON organization_members (org_id);

CREATE INDEX IF NOT EXISTS idx_organizations_live
    ON organizations (slug)
    WHERE deleted_at IS NULL;

-- Redemption looks an invite up by its hash and only ever wants a live one.
CREATE INDEX IF NOT EXISTS idx_org_invites_open
    ON organization_invites (token_hash)
    WHERE used_at IS NULL;

COMMENT ON TABLE organizations IS
    'Billing and a directory. CANNOT grant vault access — the server cannot wrap a vault key. See migration 010.';
COMMENT ON COLUMN organizations.seats IS
    'Purchased seats; NULL is unlimited. Enforced in the handler, not by a trigger — a downgrade must not be refused by the database.';
COMMENT ON COLUMN organization_members.seat_assigned_at IS
    'NULL means in the directory but holding no seat. At most one seat per user, enforced by organization_members_one_seat_per_user.';
