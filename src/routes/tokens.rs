// src/routes/tokens.rs

use crate::errors::AppError;
use crate::middleware::client_ip::ClientContext;
use crate::services::jwt::Claims;
use crate::AppState;
use axum::{
    extract::{Path, State},
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Deserialize)]
pub struct CreateTokenRequest {
    pub name: String,
    pub scope: String, // "read" | "read_write"
    pub vault_id: Option<Uuid>,
    pub expires_in_days: Option<i64>,
}

/// The longest lifetime a token may be given: ten years (DEC-AU2).
pub const MAX_TOKEN_DAYS: i64 = 3650;
/// The longest token name, in characters.
pub const MAX_TOKEN_NAME_CHARS: usize = 64;

/// The token name, trimmed, or 422.
///
/// ⚠️ It was stored exactly as sent — blank, or any length — so a direct API
/// call could create a token nobody can tell apart in `token list` (I-206).
fn valid_token_name(name: &str) -> Result<String, AppError> {
    let name = name.trim();
    let chars = name.chars().count();
    if chars == 0 || chars > MAX_TOKEN_NAME_CHARS {
        return Err(AppError::Validation(format!(
            "name must be 1–{MAX_TOKEN_NAME_CHARS} characters"
        )));
    }
    Ok(name.to_string())
}

/// When a token made at `now` with `days` of life expires, or 422.
///
/// ⚠️ `days` was used unchecked: 0 or a negative number minted a token that was
/// already expired, and a huge one overflowed `Duration::days` — which panics —
/// inside the request (I-205). `None` still means "no expiry".
fn expiry_from_days(
    days: Option<i64>,
    now: chrono::DateTime<Utc>,
) -> Result<Option<chrono::DateTime<Utc>>, AppError> {
    let Some(days) = days else {
        return Ok(None);
    };
    if !(1..=MAX_TOKEN_DAYS).contains(&days) {
        return Err(AppError::Validation(format!(
            "expires_in_days must be between 1 and {MAX_TOKEN_DAYS}"
        )));
    }
    chrono::Duration::try_days(days)
        .and_then(|d| now.checked_add_signed(d))
        .map(Some)
        .ok_or_else(|| AppError::Validation("expires_in_days is out of range".into()))
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub id: Uuid,
    pub name: String,
    pub scope: String,
    pub vault_id: Option<Uuid>,
    pub expires_at: Option<chrono::DateTime<Utc>>,
    pub created_at: chrono::DateTime<Utc>,
    pub last_used_at: Option<chrono::DateTime<Utc>>,
}

pub async fn create_token(
    State(state): State<AppState>,
    client: ClientContext,
    axum::Extension(claims): axum::Extension<Claims>,
    Json(req): Json<CreateTokenRequest>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), AppError> {
    let user_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;

    // Validated before the quota check and before anything is written, so a bad
    // request costs nothing and stores nothing (SV-2).
    let name = valid_token_name(&req.name)?;
    let expires_at = expiry_from_days(req.expires_in_days, Utc::now())?;

    crate::services::quota::check_token_limit(&state.db, &state.config.quotas, user_id).await?;

    let valid_scopes = ["read", "read_write"];
    if !valid_scopes.contains(&req.scope.as_str()) {
        return Err(AppError::Validation(
            "scope must be 'read' or 'read_write'".into(),
        ));
    }

    // Generate random token with evnx_tok_ prefix (detectable by evnx scan)
    use rand::RngCore;
    let mut raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let raw_token = format!("evnx_tok_{}", hex::encode(raw));
    let token_hash = blake3::hash(raw_token.as_bytes()).to_hex().to_string();

    let token_id = Uuid::new_v4();

    sqlx::query!(
        r#"
        INSERT INTO api_tokens (id, user_id, name, token_hash, scope, vault_id, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
        token_id,
        user_id,
        name,
        token_hash,
        req.scope,
        req.vault_id,
        expires_at,
    )
    .execute(&state.db)
    .await
    .map_err(AppError::Database)?;

    // Record audit
    tokio::spawn({
        let db = state.db.clone();
        let scope_for_audit = req.scope.clone();
        let vault_id_for_audit = req.vault_id;
        async move {
            let _ = crate::services::audit::record(
                &db,
                crate::services::audit::AuditEvent {
                    vault_id: req.vault_id,
                    user_id: Some(user_id),
                    event_type: "token_create".into(),
                    ip_hash: client.ip_hash.clone(),
                    user_agent_hash: client.user_agent_hash.clone(),
                    metadata: Some(serde_json::json!({ "token_id": token_id, "scope": scope_for_audit, "vault_id": vault_id_for_audit })),
                },
            )
            .await;
        }
    });

    Ok((
        axum::http::StatusCode::CREATED,
        Json(serde_json::json!({
            "id": token_id,
            "raw_token": raw_token,  // shown ONCE — client must save it
            "name": name,
            "scope": req.scope,
            "expires_at": expires_at,
            "note": "Save this token — it cannot be retrieved again.",
        })),
    ))
}

pub async fn list_tokens(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<Claims>,
) -> Result<Json<serde_json::Value>, AppError> {
    let user_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;

    let tokens = sqlx::query_as!(
        TokenResponse,
        r#"
        SELECT id, name, scope, vault_id, expires_at, created_at, last_used_at
        FROM api_tokens
        WHERE user_id = $1 AND revoked_at IS NULL
        ORDER BY created_at DESC
        "#,
        user_id,
    )
    .fetch_all(&state.db)
    .await
    .map_err(AppError::Database)?;

    Ok(Json(serde_json::json!({ "tokens": tokens })))
}

pub async fn revoke_token(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<Claims>,
    Path(token_id): Path<Uuid>,
) -> Result<axum::http::StatusCode, AppError> {
    let user_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;

    let result = sqlx::query!(
        "UPDATE api_tokens SET revoked_at = NOW() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
        token_id, user_id,
    )
    .execute(&state.db)
    .await
    .map_err(AppError::Database)?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }

    Ok(axum::http::StatusCode::NO_CONTENT)
}
