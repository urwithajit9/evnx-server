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
    /// Vault key wrapped client-side for the recipient — hybrid X25519 + ML-KEM.
    pub encrypted_vault_key: String,
    /// The sender's ephemeral X25519 public key. 44 base64 characters.
    pub eph_pub_key: String,
    /// The ML-KEM-768 ciphertext. 1452 base64 characters.
    ///
    /// Required, not optional. A share is the one path where the post-quantum
    /// half matters, so this is exactly where its absence must be an error.
    pub mlkem_ciphertext: String,
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

    // ⚠️ Refuse to share with an account that has no ML-KEM public key.
    //
    // Such an account registered before F1 and has not signed in since with a
    // client that derives the key. The only alternative would be an X25519-only
    // wrap — and a vault key wrapped that way stays wrapped that way for as long
    // as the row exists. An adversary recording it today does not care that a
    // later version fixed the algorithm, so there is no "share now, upgrade
    // later". The share is refused instead.
    //
    // 409 rather than 400: nothing about the *request* is wrong. The server's
    // state is not yet ready, and the fix is on the recipient's side.
    if target.mlkem_public_key.is_none() {
        return Err(AppError::Conflict(format!(
            "{} has no post-quantum public key on file and cannot be shared with yet. \
             They need to sign in once with evnx 0.5 or later, or at app.evnx.dev, \
             which uploads it automatically. Sharing without it would wrap the vault \
             key under X25519 alone.",
            target.email
        )));
    }

    members::add_member(
        &state.db,
        vault_id,
        target.id,
        &req.role,
        // Always `Hybrid` here: a share wraps by ECDH *and* ML-KEM, together.
        // `MemberKeyWrap` has no variant that carries only one of them.
        &members::MemberKeyWrap::Hybrid {
            encrypted_vault_key: req.encrypted_vault_key.clone(),
            eph_pub_key: req.eph_pub_key.clone(),
            mlkem_ciphertext: req.mlkem_ciphertext.clone(),
        },
        requester_id,
    )
    .await?;

    Ok(axum::http::StatusCode::CREATED)
}

/// Everyone who can reach this vault.
///
/// ─── Who may see this ────────────────────────────────────────────────────────
///
/// **Any member, including a `viewer`.** Being able to see who else holds a key
/// to a vault you hold a key to is not a privilege — it is the minimum needed to
/// notice that someone has access they should not. Restricting it to admins
/// would mean the people most likely to spot a wrong grant are the ones who
/// cannot look.
///
/// A non-member gets **404**, not 403, matching every other vault route: a
/// distinct "this vault exists but is not yours" would let anyone probe for vault
/// ids.
///
/// ─── What it deliberately does not return ────────────────────────────────────
///
/// ⚠️ No wrapped keys. Each member's `encrypted_vault_key`, `eph_pub_key` and
/// `mlkem_ciphertext` are wrapped to that member and useless to anyone else, but
/// a listing endpoint is precisely where such a field gets copied into a response
/// without anyone noticing. `GET /vaults/:id/my-key` returns your own, and
/// nothing returns anybody else's.
pub async fn list_members(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<Claims>,
    Path(vault_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let requester_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;

    // Membership is the authorisation. Any role suffices, so this is a presence
    // check rather than a rank check — the only route in Phase 3 where that is
    // the whole rule.
    vaults::find_member_role(&state.db, vault_id, requester_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let members = members::list_members(&state.db, vault_id).await?;

    Ok(Json(serde_json::json!({
        "members": members
            .into_iter()
            .map(|m| serde_json::json!({
                "user_id":        m.user_id,
                "email":          m.email,
                "role":           m.role,
                "granted_at":     m.granted_at,
                "granted_by":     m.granted_by,
                // False for an account predating F1 that has not signed in since.
                // Such a member cannot be re-wrapped to, so a client should say so
                // before a re-key rather than after it fails.
                "has_mlkem_key":  m.has_mlkem_key,
                "is_you":         m.user_id == requester_id,
            }))
            .collect::<Vec<_>>(),
    })))
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
