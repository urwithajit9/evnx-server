//! Session listing and revocation.
//!
//! A "session" is one `session_id` in `refresh_tokens`. Refresh tokens rotate on
//! every use, so a single session accumulates rows over its lifetime; they are
//! grouped here so a user sees devices rather than token churn.
//!
//! The login-alert email has always told users to "revoke all sessions from your
//! account settings". Until now there was no endpoint behind that sentence.

use axum::{
    extract::{Path, State},
    Json,
};
use serde::Serialize;
use uuid::Uuid;

use crate::{errors::AppError, services::jwt::Claims, state::AppState};

#[derive(Serialize)]
pub struct SessionSummary {
    pub session_id: Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_used_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// True for the session making this request, so a UI can label it and warn
    /// before the user signs themselves out.
    pub current: bool,
}

/// List the caller's active sessions, newest first.
pub async fn list_sessions(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<Claims>,
) -> Result<Json<serde_json::Value>, AppError> {
    let user_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;
    let current_session = claims.session_id().ok();

    // One row per session_id. A rotating refresh token leaves a trail of revoked
    // rows behind it, so the live row is the one that is neither revoked nor
    // expired; created_at comes from the oldest row in the group, which is when
    // the device actually signed in.
    let rows = sqlx::query!(
        r#"
        SELECT
            session_id                          AS "session_id!",
            MIN(created_at)                     AS "created_at!",
            MAX(created_at)                     AS "last_used_at!",
            MAX(expires_at)                     AS "expires_at!"
        FROM refresh_tokens
        WHERE user_id = $1
          AND revoked_at IS NULL
          AND expires_at > NOW()
        GROUP BY session_id
        ORDER BY MAX(created_at) DESC
        "#,
        user_id,
    )
    .fetch_all(&state.db)
    .await
    .map_err(AppError::Database)?;

    let sessions: Vec<SessionSummary> = rows
        .into_iter()
        .map(|r| SessionSummary {
            session_id: r.session_id,
            created_at: r.created_at,
            last_used_at: r.last_used_at,
            expires_at: r.expires_at,
            current: current_session == Some(r.session_id),
        })
        .collect();

    Ok(Json(serde_json::json!({ "sessions": sessions })))
}

/// Revoke one session.
///
/// Revokes its refresh tokens so it cannot be renewed, and blocklists the
/// session id in Valkey so its access token stops working immediately rather
/// than lingering for up to its 15-minute lifetime.
pub async fn revoke_session(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<Claims>,
    Path(session_id): Path<Uuid>,
) -> Result<axum::http::StatusCode, AppError> {
    let user_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;

    // Scope the update to this user: without the user_id predicate, anyone could
    // revoke anyone else's session by guessing a UUID.
    let result = sqlx::query!(
        r#"
        UPDATE refresh_tokens
        SET revoked_at = NOW()
        WHERE user_id = $1 AND session_id = $2 AND revoked_at IS NULL
        "#,
        user_id,
        session_id,
    )
    .execute(&state.db)
    .await
    .map_err(AppError::Database)?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }

    // The access token outlives the refresh token it came from, so revocation is
    // not complete until the blocklist entry exists.
    let ttl = (state.config.jwt_expiry_minutes.max(1) * 60) as u64;
    state
        .cache
        .set_flag(&format!("jwt_blocklist:{}", session_id), ttl)
        .await?;

    tracing::info!(user_id = %user_id, session_id = %session_id, "Session revoked");
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Revoke every session except the one making the request.
///
/// This is the action the login-alert email points at: someone who sees an
/// unrecognised login wants everything else gone without signing themselves out
/// and losing the ability to act.
pub async fn revoke_other_sessions(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<Claims>,
) -> Result<Json<serde_json::Value>, AppError> {
    let user_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;
    let current = claims.session_id().map_err(|_| AppError::Unauthorized)?;

    let victims = sqlx::query!(
        r#"
        UPDATE refresh_tokens
        SET revoked_at = NOW()
        WHERE user_id = $1 AND session_id <> $2 AND revoked_at IS NULL
        RETURNING session_id
        "#,
        user_id,
        current,
    )
    .fetch_all(&state.db)
    .await
    .map_err(AppError::Database)?;

    let ttl = (state.config.jwt_expiry_minutes.max(1) * 60) as u64;
    let mut revoked: Vec<Uuid> = victims.into_iter().map(|r| r.session_id).collect();
    revoked.sort_unstable();
    revoked.dedup();

    for sid in &revoked {
        state
            .cache
            .set_flag(&format!("jwt_blocklist:{}", sid), ttl)
            .await?;
    }

    tracing::info!(
        user_id = %user_id,
        count = revoked.len(),
        "Revoked all other sessions"
    );
    Ok(Json(serde_json::json!({ "revoked": revoked.len() })))
}
