// src/middleware/auth.rs

use crate::{errors::AppError, services::jwt::Claims, state::AppState};
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};

/// Extract Bearer token from Authorization header.
fn extract_bearer(req: &Request) -> Option<&str> {
    req.headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

/// JWT authentication middleware.
///
/// On success: injects `Claims` extension, calls next handler.
/// On failure: returns 401 Unauthorized immediately.
pub async fn require_auth(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let token = extract_bearer(&req).ok_or(AppError::Unauthorized)?;

    // Verify JWT signature and expiry
    let claims = state
        .jwt
        .verify(token)
        .map_err(|_| AppError::Unauthorized)?;

    // Check JWT blocklist (handles logout before token expiry)
    let session_id = claims.session_id().map_err(|_| AppError::Unauthorized)?;
    let blocked = state
        .cache
        .exists(&format!("jwt_blocklist:{}", session_id))
        .await
        .unwrap_or(false); // if Redis fails, fail open (don't block all users)

    if blocked {
        return Err(AppError::Unauthorized);
    }

    // Inject claims for downstream handlers to use
    req.extensions_mut().insert(claims);

    Ok(next.run(req).await)
}

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
