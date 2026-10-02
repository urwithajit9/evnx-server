//! Plan limits, and the checks that enforce them.
//!
//! # The numbers are configuration, not constants
//!
//! Every limit is read from the environment with a documented default, so a tier's
//! numbers change without a code change or a migration. That is deliberate: **the
//! existence of limits is a one-way door and their values are not.** Introducing a
//! limit after people are using the service means grandfathering or taking something
//! away; changing `3` to `5` afterwards means editing a variable.
//!
//! # `None` means unlimited, and it is spelled out
//!
//! A limit is `Option<u32>`. `None` is unlimited, written in configuration as
//! `unlimited` rather than as an empty value or a very large number — an operator
//! reading `QUOTA_TEAM_VAULTS=unlimited` knows what it means, and an operator reading
//! `QUOTA_TEAM_VAULTS=` does not know whether they disabled the limit or broke it.
//!
//! ⚠️ **An unparseable value is a startup failure, not a silent default.** The same
//! stance `Config::from_env` takes everywhere else: a typo that quietly grants
//! everyone unlimited vaults is worse than a server that refuses to boot.

use crate::errors::AppError;

/// Which tier an account is on.
///
/// A closed set, matching migration 008's CHECK. Parsing is total — an unknown
/// string is an error rather than a default — because defaulting an unrecognised
/// plan to `free` would lock out a paying customer, and defaulting it to
/// `enterprise` would give away the product.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan {
    Free,
    Team,
    Enterprise,
}

impl Plan {
    /// Every plan, in the order a pricing page lists them.
    ///
    /// ⚠️ A plan that exists in this enum but not in migration 008's
    /// `CHECK (plan IN (...))` is a plan no account can actually hold, and one
    /// that exists in the CHECK but not here is a plan nothing can read back.
    /// They have to move together; `GET /api/v1/plans` publishes this array, so
    /// a tier missing from it is a tier nobody can buy.
    pub const ALL: [Plan; 3] = [Plan::Free, Plan::Team, Plan::Enterprise];

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "free" => Some(Self::Free),
            "team" => Some(Self::Team),
            "enterprise" => Some(Self::Enterprise),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::Team => "team",
            Self::Enterprise => "enterprise",
        }
    }
}

/// What one plan allows. `None` is unlimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlanLimits {
    pub vaults: Option<u32>,
    pub versions_per_vault: Option<u32>,
    pub api_tokens: Option<u32>,
    pub audit_retention_days: Option<u32>,
}

/// Limits for every plan.
#[derive(Debug, Clone, Copy)]
pub struct Quotas {
    pub free: PlanLimits,
    pub team: PlanLimits,
    pub enterprise: PlanLimits,
}

impl Quotas {
    pub fn for_plan(&self, plan: Plan) -> PlanLimits {
        match plan {
            Plan::Free => self.free,
            Plan::Team => self.team,
            Plan::Enterprise => self.enterprise,
        }
    }
}

impl Default for Quotas {
    /// The first Free tier: 3 vaults, 5 versions each, 2 API tokens, 7 days of audit.
    ///
    /// Team and Enterprise are unlimited **for now**, because nothing sells them yet
    /// and a limit nobody can reach is only a trap for whoever builds billing. When
    /// seats exist, these get numbers — by changing configuration, which is the point.
    fn default() -> Self {
        Self {
            free: PlanLimits {
                vaults: Some(3),
                versions_per_vault: Some(5),
                api_tokens: Some(2),
                audit_retention_days: Some(7),
            },
            team: PlanLimits {
                vaults: None,
                versions_per_vault: None,
                api_tokens: None,
                audit_retention_days: Some(90),
            },
            enterprise: PlanLimits {
                vaults: None,
                versions_per_vault: None,
                api_tokens: None,
                audit_retention_days: None,
            },
        }
    }
}

/// Parse one limit: a number, or the word `unlimited`.
///
/// ⚠️ Returns an error rather than falling back. A mistyped `QUOTA_FREE_VAULTS=tree`
/// that silently became "unlimited" would hand the whole product away on the free
/// tier, and one that silently became `0` would make the service unusable — neither
/// is a failure anyone would notice from the outside.
pub fn parse_limit(raw: &str) -> Result<Option<u32>, String> {
    let raw = raw.trim();
    if raw.eq_ignore_ascii_case("unlimited") || raw.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    raw.parse::<u32>()
        .map(Some)
        .map_err(|_| format!("expected a number or `unlimited`, got {raw:?}"))
}

/// The error a caller sees when a limit is reached.
///
/// ⚠️ Names the limit and the plan, because "quota exceeded" tells someone they are
/// stuck without telling them what to do. It does **not** link to a pricing page:
/// there is nothing to upgrade to yet, and a dead upgrade link is worse than none.
pub fn exceeded(what: &str, limit: u32, plan: Plan, remedy: &str) -> AppError {
    AppError::QuotaExceeded(format!(
        "your plan ({}) allows {} {}. {}",
        plan.as_str(),
        limit,
        what,
        remedy
    ))
}

/// Look up an account's plan.
///
/// ⚠️ An unrecognised value is an **internal error**, not a fallback. Migration 008's
/// CHECK makes it unreachable through normal writes, so seeing one means the column
/// was changed out of band — and guessing at that point either locks out a paying
/// customer or gives the product away.
pub async fn plan_for(db: &sqlx::PgPool, user_id: uuid::Uuid) -> Result<Plan, AppError> {
    let row: Option<String> = sqlx::query_scalar("SELECT plan FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(db)
        .await?;

    let raw = row.ok_or(AppError::Unauthorized)?;
    Plan::parse(&raw)
        .ok_or_else(|| AppError::Internal(format!("unrecognised plan for user: {raw:?}")))
}

/// Refuse when the account already holds its plan's maximum number of vaults.
///
/// Counts live vaults only — a soft-deleted one does not occupy a slot, which is the
/// answer to "I deleted one and still cannot create another".
pub async fn check_vault_limit(
    db: &sqlx::PgPool,
    quotas: &Quotas,
    user_id: uuid::Uuid,
) -> Result<(), AppError> {
    let Some(limit) = quotas.for_plan(plan_for(db, user_id).await?).vaults else {
        return Ok(());
    };
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM vaults WHERE owner_id = $1 AND deleted_at IS NULL",
    )
    .bind(user_id)
    .fetch_one(db)
    .await?;

    if count >= i64::from(limit) {
        return Err(exceeded(
            "vaults",
            limit,
            plan_for(db, user_id).await?,
            "Delete one you no longer need, and it frees a slot immediately.",
        ));
    }
    Ok(())
}

/// Refuse when the account already holds its plan's maximum number of live tokens.
///
/// Revoked and expired tokens do not count: they cannot be used, so holding a slot
/// open for them would be a limit on history rather than on access.
pub async fn check_token_limit(
    db: &sqlx::PgPool,
    quotas: &Quotas,
    user_id: uuid::Uuid,
) -> Result<(), AppError> {
    let plan = plan_for(db, user_id).await?;
    let Some(limit) = quotas.for_plan(plan).api_tokens else {
        return Ok(());
    };
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM api_tokens \
         WHERE user_id = $1 AND revoked_at IS NULL \
           AND (expires_at IS NULL OR expires_at > NOW())",
    )
    .bind(user_id)
    .fetch_one(db)
    .await?;

    if count >= i64::from(limit) {
        return Err(exceeded(
            "active API tokens",
            limit,
            plan,
            "Revoke one you are no longer using.",
        ));
    }
    Ok(())
}

/// Refuse a push that would exceed the plan's version history.
///
/// ⚠️ **Refuses rather than pruning, and that is a deliberate choice worth revisiting.**
/// Pruning the oldest version is what most services do for a history limit and is
/// friendlier — a push never fails. But it deletes a user's data as a side effect of a
/// routine action, and for a vault the deleted thing is a *secret they may not have
/// anywhere else*. Refusing is recoverable; a silent delete is not.
///
/// The cost is real: on a limit of 5, the sixth push fails until something is removed.
/// If that proves too blunt, pruning is the alternative — but it should be a decision
/// someone makes, not one that arrives with a quota.
/// ⚠️ **The vault OWNER's plan, not the pusher's**, and the owner is looked up here
/// rather than passed in so no caller can get that wrong.
///
/// A developer pushing to a vault someone shared with them is spending the owner's
/// storage, not their own — so it is the owner's limit that applies. Charging it to
/// the pusher would mean a free-tier developer could not contribute to an enterprise
/// team's vault, and a free-tier owner could raise their own limit by inviting
/// someone on a bigger plan.
pub async fn check_version_limit(
    db: &sqlx::PgPool,
    quotas: &Quotas,
    vault_id: uuid::Uuid,
) -> Result<(), AppError> {
    let owner_id: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT owner_id FROM vaults WHERE id = $1 AND deleted_at IS NULL")
            .bind(vault_id)
            .fetch_optional(db)
            .await?;
    let owner_id = owner_id.ok_or(AppError::NotFound)?;

    let plan = plan_for(db, owner_id).await?;
    let Some(limit) = quotas.for_plan(plan).versions_per_vault else {
        return Ok(());
    };
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vault_versions WHERE vault_id = $1")
        .bind(vault_id)
        .fetch_one(db)
        .await?;

    if count >= i64::from(limit) {
        return Err(exceeded(
            "versions per vault",
            limit,
            plan,
            // ⚠️ This used to say "Delete older versions of this vault to make room"
            // when there was no way to delete a version — no endpoint, no command. An
            // error that advises an impossible action is worse than one admitting there
            // is nothing to be done, because it sends people looking for a door that is
            // not there. Both now exist; keep this sentence and that fact together.
            "Delete an older version to make room: `evnx cloud history` lists them and \
             `evnx cloud delete-version` removes one. The latest cannot be deleted.",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plan_round_trips_and_an_unknown_one_is_refused() {
        for p in [Plan::Free, Plan::Team, Plan::Enterprise] {
            assert_eq!(Plan::parse(p.as_str()), Some(p));
        }
        // ⚠️ Not defaulted. Defaulting to free would lock out a paying customer;
        // defaulting to enterprise would give the product away.
        assert_eq!(Plan::parse("pro"), None);
        assert_eq!(Plan::parse("Free"), None, "the column stores lowercase");
        assert_eq!(Plan::parse(""), None);
    }

    #[test]
    fn a_limit_is_a_number_or_the_word_unlimited() {
        assert_eq!(parse_limit("3"), Ok(Some(3)));
        assert_eq!(parse_limit("  3  "), Ok(Some(3)));
        assert_eq!(parse_limit("0"), Ok(Some(0)));
        assert_eq!(parse_limit("unlimited"), Ok(None));
        assert_eq!(parse_limit("UNLIMITED"), Ok(None));
        assert_eq!(parse_limit("none"), Ok(None));
    }

    /// ⚠️ The failure that must not be silent. `tree` becoming `None` would hand out
    /// unlimited vaults on the free tier, and nothing outside would show it.
    #[test]
    fn an_unparseable_limit_is_an_error_rather_than_a_default() {
        assert!(parse_limit("tree").is_err());
        assert!(parse_limit("").is_err());
        assert!(parse_limit("-1").is_err());
        assert!(parse_limit("3.5").is_err());
    }

    #[test]
    fn the_first_free_tier_is_the_agreed_numbers() {
        let q = Quotas::default();
        assert_eq!(q.free.vaults, Some(3));
        assert_eq!(q.free.versions_per_vault, Some(5));
        assert_eq!(q.free.api_tokens, Some(2));
        assert_eq!(q.free.audit_retention_days, Some(7));
    }

    #[test]
    fn for_plan_routes_to_the_right_limits() {
        let q = Quotas::default();
        assert_eq!(q.for_plan(Plan::Free).vaults, Some(3));
        assert_eq!(q.for_plan(Plan::Team).vaults, None);
        assert_eq!(q.for_plan(Plan::Enterprise).audit_retention_days, None);
    }

    /// The message has to say what to do, not only that you cannot.
    #[test]
    fn the_error_names_the_limit_the_plan_and_a_remedy() {
        let e = exceeded("vaults", 3, Plan::Free, "Delete one, or upgrade.");
        let msg = format!("{e}");
        assert!(msg.contains("free"), "{msg}");
        assert!(msg.contains('3'), "{msg}");
        assert!(msg.contains("vaults"), "{msg}");
        assert!(msg.contains("Delete one"), "{msg}");
    }
}
