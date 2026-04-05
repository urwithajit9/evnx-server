// src/middleware/auth.rs

use crate::{errors::AppError, services::jwt::Claims, state::AppState};
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use chrono::Utc;

/// Extract Bearer token from Authorization header.
fn extract_bearer(req: &Request) -> Option<&str> {
    req.headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

// /// JWT authentication middleware.
// ///
// /// On success: injects `Claims` extension, calls next handler.
// /// On failure: returns 401 Unauthorized immediately.
// pub async fn require_auth(
//     State(state): State<AppState>,
//     mut req: Request,
//     next: Next,
// ) -> Result<Response, AppError> {
//     let token = extract_bearer(&req).ok_or(AppError::Unauthorized)?;

//     // Verify JWT signature and expiry
//     let claims = state
//         .jwt
//         .verify(token)
//         .map_err(|_| AppError::Unauthorized)?;

//     // Check JWT blocklist (handles logout before token expiry)
//     let session_id = claims.session_id().map_err(|_| AppError::Unauthorized)?;
//     let blocked = state
//         .cache
//         .exists(&format!("jwt_blocklist:{}", session_id))
//         .await
//         .unwrap_or(false); // if Redis fails, fail open (don't block all users)

//     if blocked {
//         return Err(AppError::Unauthorized);
//     }

//     // Inject claims for downstream handlers to use
//     req.extensions_mut().insert(claims);

//     Ok(next.run(req).await)
// }

/// Like `require_auth` but additionally checks `email_verified = true`.
/// Apply to vault endpoints.
pub async fn require_verified(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    // Run standard auth first
    let token = extract_bearer(&req).ok_or(AppError::Unauthorized)?;
    let claims = state
        .jwt
        .verify(token)
        .map_err(|_| AppError::Unauthorized)?;

    let session_id = claims.session_id().map_err(|_| AppError::Unauthorized)?;
    let blocked = state
        .cache
        .exists(&format!("jwt_blocklist:{}", session_id))
        .await
        .unwrap_or(false);
    if blocked {
        return Err(AppError::Unauthorized);
    }

    // Additional check: email verified
    if !claims.email_verified {
        return Err(AppError::EmailNotVerified);
    }

    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}

/// Detect if the Authorization header contains an API token (not a JWT).
fn is_api_token(token: &str) -> bool {
    token.starts_with("evnx_tok_")
}

/// Authenticate an API token from the database.
async fn authenticate_api_token(state: &AppState, raw_token: &str) -> Result<Claims, AppError> {
    let token_hash = blake3::hash(raw_token.as_bytes()).to_hex().to_string();

    let row = sqlx::query!(
        r#"
        SELECT id, user_id, scope, vault_id, expires_at
        FROM api_tokens
        WHERE token_hash = $1
          AND revoked_at IS NULL
          AND (expires_at IS NULL OR expires_at > NOW())
        "#,
        token_hash,
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| AppError::Unauthorized)?
    .ok_or(AppError::Unauthorized)?;

    // Update last_used_at (fire-and-forget)
    let db = state.db.clone();
    let token_id = row.id;
    tokio::spawn(async move {
        let _ = sqlx::query!(
            "UPDATE api_tokens SET last_used_at = NOW() WHERE id = $1",
            token_id,
        )
        .execute(&db)
        .await;
    });

    // Build Claims-like struct from API token data
    Ok(Claims {
        sub: row.user_id.to_string(),
        sid: row.id.to_string(),
        email_verified: true, // tokens only issued to verified users
        scope: format!("ci_token:{}", row.scope),
        iat: Utc::now().timestamp(),
        exp: row.expires_at.map(|dt| dt.timestamp()).unwrap_or(i64::MAX),
    })
}

/// Updated require_auth that handles both JWT and API tokens.
pub async fn require_auth(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let token = extract_bearer(&req).ok_or(AppError::Unauthorized)?;

    let claims = if is_api_token(token) {
        authenticate_api_token(&state, token).await?
    } else {
        let claims = state
            .jwt
            .verify(token)
            .map_err(|_| AppError::Unauthorized)?;
        let session_id = claims.session_id().map_err(|_| AppError::Unauthorized)?;
        let blocked = state
            .cache
            .exists(&format!("jwt_blocklist:{}", session_id))
            .await
            .unwrap_or(false);
        if blocked {
            return Err(AppError::Unauthorized);
        }
        claims
    };

    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}
