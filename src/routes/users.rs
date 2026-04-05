// src/routes/users.rs

use crate::{db::users, errors::AppError, services::jwt::Claims, state::AppState};
use axum::{
    extract::{Path, State},
    Json,
};

/// Return a user's X25519 public key so vault owners can wrap vault keys for them.
/// Any authenticated user can look up another user's public key by email.
pub async fn get_public_key(
    State(state): State<AppState>,
    axum::Extension(_claims): axum::Extension<Claims>, // just need to be authenticated
    Path(email): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let email_lower = email.trim().to_lowercase();

    let user = users::find_by_email(&state.db, &email_lower)
        .await?
        .ok_or(AppError::NotFound)?; // return 404, not "user exists" info leak

    Ok(Json(serde_json::json!({
        "x25519_public_key": user.x25519_public_key,
        "ed25519_public_key": user.ed25519_public_key,
    })))
}
