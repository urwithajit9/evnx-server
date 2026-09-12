// src/middleware/auth.rs

//! Request authentication guards.
//!
//! Three guards, in increasing strictness:
//!
//! | Guard | JWT `user` | `evnx_tok_` API token | `totp_pending` | Email verified |
//! |-------|-----------|----------------------|----------------|----------------|
//! | [`require_auth`]         | ✅ | ✅ | ❌ | not checked |
//! | [`require_verified`]     | ✅ | ✅ *(scope-enforced)* | ❌ | **required** |
//! | [`require_user_session`] | ✅ | ❌ | ❌ | not checked |
//!
//! Every guard injects [`Claims`] as a request extension. A handler that takes
//! `Extension<Claims>` **must** sit behind one of them — Axum returns 500, not
//! 401, when the extension is missing.
//!
//! [`require_verified`] additionally injects [`ApiTokenContext`] when the caller
//! authenticated with an API token, and enforces that token's limits centrally
//! so no handler has to remember to.

use std::collections::HashMap;

use crate::{errors::AppError, services::jwt::Claims, state::AppState};
use axum::{
    extract::{Path, Request, State},
    http::Method,
    middleware::Next,
    response::Response,
    RequestExt,
};
use chrono::Utc;
use uuid::Uuid;

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

/// The `api_tokens.scope` value that grants mutation.
const TOKEN_SCOPE_READ_WRITE: &str = "read_write";

/// Raw prefix that distinguishes an API token from a JWT in the Authorization header.
const API_TOKEN_PREFIX: &str = "evnx_tok_";

/// True if these claims came from an `evnx_tok_` API token rather than a user login.
pub fn is_ci_token(claims: &Claims) -> bool {
    claims.scope.starts_with(SCOPE_CI_TOKEN_PREFIX)
}

/// The limits attached to an authenticated `evnx_tok_` API token.
///
/// Injected as a request extension by [`require_verified`], which also enforces
/// these limits — handlers do not need to check them, and must not rely on
/// being able to.
#[derive(Clone, Debug)]
pub struct ApiTokenContext {
    /// Row id in `api_tokens`.
    pub token_id: Uuid,
    /// The single vault this token may touch. `None` means every vault the
    /// owning user can reach.
    pub vault_id: Option<Uuid>,
    /// `api_tokens.scope == "read_write"`.
    pub can_write: bool,
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

/// Extract the Bearer token from the Authorization header.
fn extract_bearer(req: &Request) -> Option<&str> {
    req.headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

/// Anything that is not a safe read is treated as a mutation.
///
/// Deliberately a denylist-free formulation: a new verb added to the router is
/// treated as a write until someone decides otherwise, rather than slipping
/// past a read-only token.
fn is_write_method(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// Read the `:vault_id` path parameter, if this route has one.
///
/// Returns `None` for collection routes such as `GET /vaults`, and for any
/// value that is not a UUID.
async fn vault_id_from_path(req: &mut Request) -> Option<Uuid> {
    let Path(params) = req
        .extract_parts::<Path<HashMap<String, String>>>()
        .await
        .ok()?;
    params.get("vault_id").and_then(|v| Uuid::parse_str(v).ok())
}

/// Look up and validate an `evnx_tok_` API token.
///
/// Returns synthetic [`Claims`] so downstream handlers treat CI tokens and user
/// sessions uniformly, plus the [`ApiTokenContext`] carrying the token's limits.
async fn authenticate_api_token(
    state: &AppState,
    raw_token: &str,
) -> Result<(Claims, ApiTokenContext), AppError> {
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

    let claims = Claims {
        sub: row.user_id.to_string(),
        sid: row.id.to_string(),
        email_verified: true, // tokens are only issued to verified users
        scope: format!("{SCOPE_CI_TOKEN_PREFIX}{}", row.scope),
        iat: Utc::now().timestamp(),
        exp: row.expires_at.map(|dt| dt.timestamp()).unwrap_or(i64::MAX),
    };

    let ctx = ApiTokenContext {
        token_id: row.id,
        vault_id: row.vault_id,
        can_write: row.scope == TOKEN_SCOPE_READ_WRITE,
    };

    Ok((claims, ctx))
}

/// Shared authentication core.
///
/// `allow_api_tokens` decides whether an `evnx_tok_` CI token may stand in for a
/// user's JWT. Account-management endpoints pass `false`: a CI token must never be
/// able to enrol TOTP, revoke a user's sessions, or mint further tokens.
async fn authenticate(
    state: &AppState,
    token: &str,
    allow_api_tokens: bool,
) -> Result<(Claims, Option<ApiTokenContext>), AppError> {
    if token.starts_with(API_TOKEN_PREFIX) {
        if !allow_api_tokens {
            // Valid credential, wrong kind for this endpoint — 403, not 401.
            return Err(AppError::Forbidden);
        }
        let (claims, ctx) = authenticate_api_token(state, token).await?;
        return Ok((claims, Some(ctx)));
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

    Ok((claims, None))
}

// ─── Guards ────────────────────────────────────────────────────────────────────

/// Authenticated as either a user session or a CI API token.
/// Does **not** require a verified email, and does **not** enforce token scope —
/// only use it on routes where a token's vault scope is irrelevant.
///
/// Used by `GET /auth/me` (the CLI must fetch its encrypted private key straight
/// after registration, before the verification email is clicked) and by
/// `GET /users/{email}/public-key`.
pub async fn require_auth(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let token = extract_bearer(&req)
        .ok_or(AppError::Unauthorized)?
        .to_owned();
    let (claims, _) = authenticate(&state, &token, true).await?;

    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}

/// A real user session only — no API tokens, no half-authenticated tokens.
///
/// Use for account management (`/auth/logout`, `/auth/totp/*`, `/auth/tokens`).
/// A CI token that could reach these would be able to enrol its own authenticator
/// on the account, revoke the owner's sessions, or mint fresh tokens for itself.
pub async fn require_user_session(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let token = extract_bearer(&req)
        .ok_or(AppError::Unauthorized)?
        .to_owned();
    let (claims, _) = authenticate(&state, &token, false).await?;

    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}

/// Authenticated, email-verified, and — for API tokens — within the token's scope.
/// Applied to every vault endpoint.
///
/// For an `evnx_tok_` caller this enforces two limits centrally, so no handler
/// has to remember them:
///
/// 1. **Read-only tokens cannot mutate.** Any method other than GET/HEAD/OPTIONS
///    is refused unless `api_tokens.scope = 'read_write'`.
/// 2. **A vault-scoped token reaches only that vault.** If `api_tokens.vault_id`
///    is set, the request's `:vault_id` must match it. Routes with no `:vault_id`
///    (e.g. `GET /vaults`, `POST /vaults`) are refused outright for such a token —
///    listing every vault, or creating a new one, is outside what it was issued for.
pub async fn require_verified(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let token = extract_bearer(&req)
        .ok_or(AppError::Unauthorized)?
        .to_owned();
    let (claims, api_token) = authenticate(&state, &token, true).await?;

    if !claims.email_verified {
        return Err(AppError::EmailNotVerified);
    }

    if let Some(ctx) = api_token {
        if !ctx.can_write && is_write_method(req.method()) {
            return Err(AppError::Forbidden);
        }

        if let Some(scoped_vault) = ctx.vault_id {
            match vault_id_from_path(&mut req).await {
                Some(requested) if requested == scoped_vault => {}
                _ => return Err(AppError::Forbidden),
            }
        }

        req.extensions_mut().insert(ctx);
    }

    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}
