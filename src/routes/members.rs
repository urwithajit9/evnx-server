// src/routes/members.rs

use crate::{
    db::{members, users as db_users, vaults},
    errors::AppError,
    services::jwt::Claims,
    state::AppState,
};
use axum::{
    extract::{Path, State},
    Json,
};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct AddMemberRequest {
    pub user_email: String,
    pub role: String,
    /// ECDH-wrapped vault key, prepared client-side for the recipient's X25519 pubkey
    pub encrypted_vault_key: String,
    pub eph_pub_key: String,
}

pub async fn add_member(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<Claims>,
    Path(vault_id): Path<Uuid>,
    Json(req): Json<AddMemberRequest>,
) -> Result<axum::http::StatusCode, AppError> {
    let requester_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;

    // Check requester has admin or owner role on this vault
    let role = vaults::find_member_role(&state.db, vault_id, requester_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if !["owner", "admin"].contains(&role.as_str()) {
        return Err(AppError::Forbidden);
    }

    // Validate the role being assigned
    let valid_roles = ["admin", "developer", "viewer"];
    if !valid_roles.contains(&req.role.as_str()) {
        return Err(AppError::Validation(format!(
            "role must be one of: {}",
            valid_roles.join(", ")
        )));
    }

    // Prevent assigning "owner" — only vault creation sets owner
    // Look up the target user by email
    let target = db_users::find_by_email(&state.db, &req.user_email.trim().to_lowercase())
        .await?
        .ok_or(AppError::NotFound)?;

    members::add_member(
        &state.db,
        vault_id,
        target.id,
        &req.role,
        &req.encrypted_vault_key,
        &req.eph_pub_key,
        requester_id,
    )
    .await?;

    Ok(axum::http::StatusCode::CREATED)
}

pub async fn remove_member(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<Claims>,
    Path((vault_id, member_user_id)): Path<(Uuid, Uuid)>,
) -> Result<axum::http::StatusCode, AppError> {
    let requester_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;

    // Only owner can remove members; users can remove themselves
    let role = vaults::find_member_role(&state.db, vault_id, requester_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let can_remove = role == "owner" || requester_id == member_user_id;
    if !can_remove {
        return Err(AppError::Forbidden);
    }

    // Prevent removing the owner
    let target_role = vaults::find_member_role(&state.db, vault_id, member_user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if target_role == "owner" {
        return Err(AppError::Conflict("Cannot remove vault owner".into()));
    }

    let removed = members::remove_member(&state.db, vault_id, member_user_id).await?;
    if !removed {
        return Err(AppError::NotFound);
    }

    Ok(axum::http::StatusCode::NO_CONTENT)
}
