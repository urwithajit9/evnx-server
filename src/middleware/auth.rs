// src/middleware/auth.rs

//! Request authentication guards.
//!
//! Three guards, in increasing strictness:
//!
//! | Guard | JWT `user` | `evnx_tok_` API token | `totp_pending` | Email verified |
//! |-------|-----------|----------------------|----------------|----------------|
//! | [`require_auth`]         | ✅ | ✅ | ❌ | not checked |
//! | [`require_verified`]     | ✅ | ❌ | ❌ | **required** |
//! | [`require_user_session`] | ✅ | ❌ | ❌ | not checked |
//!
//! Every guard injects [`Claims`] as a request extension. A handler that takes
//! `Extension<Claims>` **must** sit behind one of them — Axum returns 500, not
//! 401, when the extension is missing.

use crate::{errors::AppError, services::jwt::Claims, state::AppState};
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use chrono::Utc;

// ─── Scopes ────────────────────────────────────────────────────────────────────

/// A fully authenticated user session, issued once login completes.
const SCOPE_USER: &str = "user";

/// The short-lived token issued between SRP verify and TOTP verify. The password
/// has been proven but the second factor has **not**, so this scope must never
/// authenticate a request. `POST /auth/totp/verify` is the only endpoint allowed
/// to accept it, and it takes it from the request body and checks the scope itself.
const SCOPE_TOTP_PENDING: &str = "totp_pending";

/// Synthetic scope prefix given to `evnx_tok_` API tokens
/// (`ci_token:read`, `ci_token:read_write`).
const SCOPE_CI_TOKEN_PREFIX: &str = "ci_token:";

/// Raw prefix that distinguishes an API token from a JWT in the Authorization header.
const API_TOKEN_PREFIX: &str = "evnx_tok_";

/// True if these claims came from an `evnx_tok_` API token rather than a user login.
pub fn is_ci_token(claims: &Claims) -> bool {
    claims.scope.starts_with(SCOPE_CI_TOKEN_PREFIX)
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

/// Extract the Bearer token from the Authorization header.
fn extract_bearer(req: &Request) -> Option<&str> {
    req.headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

/// Look up and validate an `evnx_tok_` API token.
///
/// Returns synthetic [`Claims`] so downstream handlers treat CI tokens and user
/// sessions uniformly. `sid` carries the token id, which is what `is_ci_token`
/// and any future per-token revocation key off.
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

    // Update last_used_at without blocking the request.
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

    Ok(Claims {
        sub: row.user_id.to_string(),
        sid: row.id.to_string(),
        email_verified: true, // tokens are only issued to verified users
        scope: format!("{SCOPE_CI_TOKEN_PREFIX}{}", row.scope),
        iat: Utc::now().timestamp(),
        exp: row.expires_at.map(|dt| dt.timestamp()).unwrap_or(i64::MAX),
    })
}

/// Shared authentication core.
///
/// `allow_api_tokens` decides whether an `evnx_tok_` CI token may stand in for a
/// user's JWT. Account-management endpoints pass `false`: a CI token must never be
/// able to enrol TOTP or revoke a user's sessions.
async fn authenticate(
    state: &AppState,
    token: &str,
    allow_api_tokens: bool,
) -> Result<Claims, AppError> {
    if token.starts_with(API_TOKEN_PREFIX) {
        if !allow_api_tokens {
            // Valid credential, wrong kind for this endpoint — 403, not 401.
            return Err(AppError::Forbidden);
        }
        return authenticate_api_token(state, token).await;
    }

    let claims = state
        .jwt
        .verify(token)
        .map_err(|_| AppError::Unauthorized)?;

    // Scope decides what a JWT may do. `verify()` only checks signature and expiry,
    // so without this a `totp_pending` token — issued after the password is proven
    // but before the second factor — would authenticate like a completed session
    // and bypass 2FA entirely.
    if claims.scope != SCOPE_USER {
        debug_assert!(
            claims.scope == SCOPE_TOTP_PENDING || is_ci_token(&claims),
            "unexpected JWT scope",
        );
        return Err(AppError::Unauthorized);
    }

    // Blocklist covers logout before the token expires naturally.
    // Fail open if the cache is unreachable — a cache outage must not lock every
    // user out; the token is still signature- and expiry-valid.
    let session_id = claims.session_id().map_err(|_| AppError::Unauthorized)?;
    let blocked = state
        .cache
        .exists(&format!("jwt_blocklist:{}", session_id))
        .await
        .unwrap_or(false);
    if blocked {
        return Err(AppError::Unauthorized);
    }

    Ok(claims)
}

// ─── Guards ────────────────────────────────────────────────────────────────────

/// Authenticated as either a user session or a CI API token.
/// Does **not** require a verified email.
///
/// Used by `GET /auth/me` (the CLI must fetch its encrypted private key straight
/// after registration, before the verification email is clicked) and by
/// `GET /users/{email}/public-key`.
pub async fn require_auth(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let token = extract_bearer(&req).ok_or(AppError::Unauthorized)?;
    let claims = authenticate(&state, token, true).await?;

    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}

/// A real user session only — no API tokens, no half-authenticated tokens.
///
/// Use for account management (`/auth/logout`, `/auth/totp/setup`,
/// `/auth/totp/confirm`). A CI token that could reach these would be able to
/// enrol its own authenticator on the account or revoke the owner's sessions.
pub async fn require_user_session(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let token = extract_bearer(&req).ok_or(AppError::Unauthorized)?;
    let claims = authenticate(&state, token, false).await?;

    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}

/// Authenticated **and** email-verified. Applied to every vault endpoint.
///
/// API tokens are not accepted yet — CI push/pull over `evnx_tok_` is a separate
/// change that also needs the token's `vault_id` scope enforced, which this guard
/// has no way to express today.
pub async fn require_verified(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let token = extract_bearer(&req).ok_or(AppError::Unauthorized)?;
    let claims = authenticate(&state, token, false).await?;

    if !claims.email_verified {
        return Err(AppError::EmailNotVerified);
    }

    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}
