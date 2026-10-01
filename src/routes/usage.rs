// src/routes/usage.rs

//! What your plan allows, and how much of it you are using.
//!
//! ## Why this exists
//!
//! Every limit in evnx was previously discoverable in exactly one way: by being
//! refused. The refusals are good — they name the limit and the remedy — but a
//! limit you learn about at the moment it blocks you is a limit nobody could plan
//! around, and the version limit in particular blocks a `push`, which is the one
//! action people run under time pressure.
//!
//! ## ⚠️ Counted the same way the enforcement counts, or not at all
//!
//! Each number here is produced by the **same predicate** as the matching
//! `check_*_limit` in [`crate::services::quota`]. A display that counts even
//! slightly differently is worse than no display: "2 of 3" beside a refusal that
//! says you are full destroys trust in both numbers, and the person has no way to
//! tell which one lied.
//!
//! The three that matter:
//!
//! * **Vaults** are those you **own** and have not deleted — not those you can
//!   reach. A vault shared *to* you is the owner's, and counts against them.
//! * **API tokens** count only **live** ones. A revoked or expired token cannot
//!   be used, so holding a slot open for it would be a limit on history.
//! * **Versions** are **per vault**, and charged to that vault's **owner**. So
//!   this reports a row per owned vault rather than one total — a sum would be a
//!   number that corresponds to no limit anyone can hit.
//!
//! ## ⚠️ `used == limit` means already full
//!
//! `check_*_limit` refuses on `count >= limit`, so at three of three the next
//! create is already refused. Anything rendering this must not imply one more is
//! available; "3 of 3" has to read as full, not as nearly full.
//!
//! `null` for a limit means unlimited — spelled as absence rather than as a
//! sentinel, because a very large number would be indistinguishable from a
//! misconfiguration.

use axum::{extract::State, Json};
use serde_json::json;

use crate::errors::AppError;
use crate::services::jwt::Claims;
use crate::state::AppState;

/// Plan limits and current usage for the caller.
///
/// `GET /api/v1/auth/usage`
///
/// # Errors
/// * `401` — no session.
/// * `403` — an API token; the route sits behind `require_user_session`.
///
/// ⚠️ Session-only, deliberately. The response names every vault you own, and
/// account-level reads are kept off API tokens throughout — a credential issued
/// for one pipeline should not enumerate the account's holdings. A pipeline that
/// actually hits a limit still gets the refusal, which names the limit and the
/// remedy, so nothing is lost but the ability to ask in advance.
pub async fn usage(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<Claims>,
) -> Result<Json<serde_json::Value>, AppError> {
    let user_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;
    let plan = crate::services::quota::plan_for(&state.db, user_id).await?;
    let limits = state.config.quotas.for_plan(plan);

    // Same predicate as `check_vault_limit`: owned, not deleted.
    let vaults_used: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"count!\" FROM vaults WHERE owner_id = $1 AND deleted_at IS NULL",
        user_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(AppError::Database)?;

    // Same predicate as `check_token_limit`: live only.
    let tokens_used: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"count!\" FROM api_tokens \
         WHERE user_id = $1 AND revoked_at IS NULL \
           AND (expires_at IS NULL OR expires_at > NOW())",
        user_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(AppError::Database)?;

    // Per owned vault, because that is the shape of the limit. Vaults shared to
    // this account are excluded: their versions count against their owner.
    let per_vault = sqlx::query!(
        r#"
        SELECT v.id, v.name, v.environment,
               COUNT(vv.id) AS "used!"
        FROM vaults v
        LEFT JOIN vault_versions vv ON vv.vault_id = v.id
        WHERE v.owner_id = $1 AND v.deleted_at IS NULL
        GROUP BY v.id, v.name, v.environment
        ORDER BY v.name, v.environment
        "#,
        user_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(AppError::Database)?;

    Ok(Json(json!({
        "plan": plan.as_str(),
        "vaults": {
            "used":  vaults_used,
            "limit": limits.vaults,
            "counts": "vaults you own that are not deleted",
        },
        "api_tokens": {
            "used":  tokens_used,
            "limit": limits.api_tokens,
            "counts": "tokens that are neither revoked nor expired",
        },
        "versions_per_vault": {
            "limit": limits.versions_per_vault,
            // One row per owned vault. A total would correspond to no limit that
            // exists, since the cap applies per vault.
            "vaults": per_vault.iter().map(|v| json!({
                "id":          v.id,
                "name":        v.name,
                "environment": v.environment,
                "used":        v.used,
            })).collect::<Vec<_>>(),
        },
        // ⚠️ A VISIBILITY limit, not deletion. `audit_events` is append-only by
        // trigger since migration 006 — nothing prunes it and nothing can. Any
        // copy describing this must not call it deletion.
        "audit_retention_days": limits.audit_retention_days,
        "note": "A null limit means unlimited. `used` equal to `limit` means the \
                 next one is already refused, not that one remains.",
    })))
}
