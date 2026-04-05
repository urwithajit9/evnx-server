// src/errors.rs

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// All possible application-level errors.
///
/// Each variant maps to a specific HTTP status code and machine-readable code.
/// The user-facing message is intentionally generic for security errors
/// (never reveal whether an email exists, etc.).
///
/// ## Usage in handlers:
/// ```rust
/// async fn my_handler() -> Result<Json<MyResponse>, AppError> {
///     let user = db::find_user(&pool, id)
///         .await
///         .map_err(AppError::Database)?;  // convert sqlx::Error → AppError
///     Ok(Json(MyResponse::from(user)))
/// }
/// ```
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    // ─── Auth errors ───────────────────────────────────────────────────────────
    #[error("Authentication failed")]
    Unauthorized,

    #[error("Email not verified. Please check your inbox.")]
    EmailNotVerified,

    #[error("Account temporarily locked. Try again later.")]
    AccountLocked,

    #[error("Insufficient permissions")]
    Forbidden,

    // ─── Resource errors ───────────────────────────────────────────────────────
    #[error("Resource not found")]
    NotFound,

    #[error("Conflict: {0}")]
    Conflict(String),

    // ─── Validation errors ─────────────────────────────────────────────────────
    #[error("Validation error: {0}")]
    Validation(String),

    // ─── Rate limiting ─────────────────────────────────────────────────────────
    #[error("Too many requests. Try again in {retry_after_seconds} seconds.")]
    RateLimited { retry_after_seconds: u64 },

    // ─── Infrastructure errors (log internally, return generic message) ────────
    #[error("Internal server error")]
    Database(#[from] sqlx::Error),

    #[error("Internal server error")]
    Internal(String),
}

/// Map AppError → HTTP Response.
///
/// This is what Axum calls when a handler returns Err(AppError::...).
/// IMPORTANT: Never expose internal error details to the client.
/// Log them server-side, return generic messages to users.
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // Log internal errors (only in this impl, nowhere else)
        match &self {
            AppError::Database(e) => {
                tracing::error!(error = %e, "Database error");
            }
            AppError::Internal(msg) => {
                tracing::error!(error = %msg, "Internal error");
            }
            _ => {} // Auth/validation errors are not server errors
        }

        let (status, code, message) = match self {
            AppError::Unauthorized        => (StatusCode::UNAUTHORIZED,          "UNAUTHORIZED",        "Authentication failed".to_string()),
            AppError::EmailNotVerified    => (StatusCode::FORBIDDEN,             "EMAIL_NOT_VERIFIED",  "Please verify your email first".to_string()),
            AppError::AccountLocked       => (StatusCode::LOCKED,                "LOCKED",              "Account temporarily locked".to_string()),
            AppError::Forbidden           => (StatusCode::FORBIDDEN,             "FORBIDDEN",           "Insufficient permissions".to_string()),
            AppError::NotFound            => (StatusCode::NOT_FOUND,             "NOT_FOUND",           "Resource not found".to_string()),
            AppError::Conflict(msg)       => (StatusCode::CONFLICT,              "CONFLICT",            msg),
            AppError::Validation(msg)     => (StatusCode::UNPROCESSABLE_ENTITY,  "VALIDATION_ERROR",    msg),
            AppError::RateLimited { retry_after_seconds } => (
                StatusCode::TOO_MANY_REQUESTS,
                "RATE_LIMITED",
                format!("Too many requests. Try again in {retry_after_seconds} seconds."),
            ),
            AppError::Database(_)  => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "An internal error occurred".to_string()),
            AppError::Internal(_)  => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "An internal error occurred".to_string()),
        };

        (status, Json(json!({ "error": message, "code": code }))).into_response()
    }
}