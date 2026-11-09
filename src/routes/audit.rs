// src/routes/audit.rs

//! `GET /api/v1/audit`: recent activity across every vault the caller can read.
//!
//! The per-vault view (`GET /vaults/:id/audit`, `routes::vaults::vault_audit`)
//! answers "what happened to this vault". This answers "what has happened to
//! anything of mine", for a dashboard, and is the same data under the same rule
//! applied once per vault.

use axum::{
    extract::{Query, State},
    Json,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    errors::AppError,
    middleware::vault_role::{AuditReader, MinRole, Role},
    services::{
        audit::{self, FeedCursor},
        jwt::Claims,
    },
    state::AppState,
};

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 200;
/// More than anyone has vaults on any plan; a bound so `ANY($n)` stays small.
const MAX_VAULT_FILTER: usize = 100;

/// Raw strings, parsed by hand, so that every malformed value answers with the
/// standard validation envelope instead of the extractor's own rejection.
#[derive(Debug, Deserialize)]
pub struct FeedQuery {
    limit: Option<String>,
    before: Option<String>,
    vault_id: Option<String>,
}

/// Recent audit events across the caller's vaults, newest first.
///
/// ─── Who sees what ───────────────────────────────────────────────────────────
///
/// An event appears if, at this moment, the caller could read that vault's audit
/// at `GET /vaults/:id/audit`: a current membership at [`AuditReader`] or above on
/// a vault that is not deleted. The requirement is the same type
/// `vault_audit` takes in its signature, and is applied in SQL
/// ([`audit::list_feed`]). Revoked memberships stop contributing immediately;
/// vaults the caller never belonged to never contribute.
///
/// Plan retention is applied as the per-vault view applies it: the caller's plan
/// decides how far back events are *shown*, nothing is deleted.
///
/// ─── Auth ────────────────────────────────────────────────────────────────────
///
/// `require_verified`, as the per-vault view. A user session or an unscoped API
/// token (read scope suffices, it is a GET). ⚠️ A token scoped to one vault gets
/// 403 `TOKEN_SCOPE`: the route has no `:vault_id` for the guard to match, and
/// such a token must not read other vaults' activity. Use the per-vault route.
///
/// ─── Paging ──────────────────────────────────────────────────────────────────
///
/// Keyset on `(created_at, id)`. `next_cursor` is `null` on the last page.
pub async fn audit_feed(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<Claims>,
    Query(q): Query<FeedQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let user_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;

    let limit = match q.limit.as_deref() {
        None => DEFAULT_LIMIT,
        Some(raw) => match raw.parse::<i64>() {
            Ok(n) if (1..=MAX_LIMIT).contains(&n) => n,
            _ => {
                return Err(AppError::Validation(format!(
                    "limit: must be a whole number from 1 to {MAX_LIMIT}"
                )))
            }
        },
    };

    let before = match q.before.as_deref() {
        None => None,
        Some(raw) => Some(
            FeedCursor::decode(raw)
                .ok_or_else(|| AppError::Validation("before: not a valid cursor".into()))?,
        ),
    };

    let filter: Option<Vec<Uuid>> = match q.vault_id.as_deref() {
        None => None,
        Some(raw) => {
            let mut ids = Vec::new();
            for part in raw.split(',') {
                let id = Uuid::parse_str(part.trim()).map_err(|_| {
                    AppError::Validation("vault_id: comma-separated vault ids".into())
                })?;
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
            if ids.len() > MAX_VAULT_FILTER {
                return Err(AppError::Validation(format!(
                    "vault_id: at most {MAX_VAULT_FILTER} ids"
                )));
            }
            Some(ids)
        }
    };

    let roles = Role::names_at_least(<AuditReader as MinRole>::MIN);

    // ⚠️ 404, not a quiet omission, when a requested vault is not readable —
    // the answer every vault route gives a non-member, so the filter cannot be
    // used to probe which ids exist. (Also: a revoked member's stale id.)
    if let Some(ids) = &filter {
        let readable = audit::count_readable_vaults(&state.db, user_id, &roles, ids).await?;
        if readable != ids.len() as i64 {
            return Err(AppError::NotFound);
        }
    }

    // Retention, exactly as `vault_audit` resolves it.
    let plan = crate::services::quota::plan_for(&state.db, user_id).await?;
    let retention_days = state.config.quotas.for_plan(plan).audit_retention_days;
    let not_before =
        retention_days.map(|days| chrono::Utc::now() - chrono::Duration::days(i64::from(days)));

    // One extra row says whether there is another page without a second query.
    let mut rows = audit::list_feed(
        &state.db,
        user_id,
        &roles,
        filter.as_deref(),
        not_before,
        before,
        limit + 1,
    )
    .await?;
    let has_more = rows.len() as i64 > limit;
    rows.truncate(limit as usize);

    let next_cursor = if has_more {
        rows.last().map(|r| {
            FeedCursor {
                created_at: r.event.created_at,
                id: r.event.id,
            }
            .encode()
        })
    } else {
        None
    };

    let removed = audit::removed_emails(&state.db, rows.iter().map(|r| &r.event)).await?;
    let events: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            let (vault_id, vault_name) = (r.vault_id, r.vault_name);
            let mut e = audit::event_json(r.event, &removed);
            if let Some(obj) = e.as_object_mut() {
                obj.insert("vault_id".into(), serde_json::json!(vault_id));
                obj.insert("vault_name".into(), vault_name.into());
            }
            e
        })
        .collect();

    Ok(Json(serde_json::json!({
        "events": events,
        "limit": limit,
        "next_cursor": next_cursor,
        "retention_days": retention_days,
    })))
}
