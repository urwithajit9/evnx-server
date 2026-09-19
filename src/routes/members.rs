// src/routes/members.rs

use crate::{
    db::{members, users as db_users, vaults},
    errors::AppError,
    middleware::vault_role::{AtLeastAdmin, AtLeastViewer, Role, VaultAccess},
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
    // Admin or above — sharing hands out a key, so it is not a developer-level act.
    access: VaultAccess<AtLeastAdmin>,
    Json(req): Json<AddMemberRequest>,
) -> Result<axum::http::StatusCode, AppError> {
    let VaultAccess {
        vault_id,
        user_id: requester_id,
        ..
    } = access;

    let granted = Role::parse(&req.role)
        .filter(|r| Role::ASSIGNABLE.contains(r))
        .ok_or_else(|| {
            AppError::Validation(format!(
                "role must be one of: {}",
                Role::ASSIGNABLE
                    .iter()
                    .map(|r| r.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })?;

    // ⚠️ You may only grant a role you outrank.
    //
    // An admin granting `admin` would create a peer neither of them can remove —
    // see `remove_member`, where removal requires outranking the target — leaving
    // only the owner able to clean up. Nothing is *breached* by allowing it, but
    // it is a one-way door for everyone except the owner, and roles that are
    // easier to create than to undo accumulate.
    if !access.outranks(granted) {
        return Err(AppError::Forbidden);
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
        granted.as_str(),
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

    crate::services::audit::record_membership_event(
        &state.db,
        vault_id,
        requester_id,
        "member_grant",
        serde_json::json!({
            "member_user_id": target.id,
            "role": granted.as_str(),
        }),
    );

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
    // Any member — membership is the whole rule here. See the doc comment above
    // for why a viewer is included rather than excluded.
    access: VaultAccess<AtLeastViewer>,
) -> Result<Json<serde_json::Value>, AppError> {
    let VaultAccess {
        vault_id,
        user_id: requester_id,
        ..
    } = access;

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

/// Body of `PATCH /vaults/:id/members/:user_id`.
#[derive(Deserialize)]
pub struct SetRoleRequest {
    pub role: String,
}

/// Change a member's role.
///
/// ─── The rule, in one line ───────────────────────────────────────────────────
///
/// **You must outrank both what they are and what you are making them.**
///
/// Outranking the *current* role stops an admin demoting a peer or an owner.
/// Outranking the *new* role stops an admin promoting someone to admin — the
/// same one-way door `add_member` refuses, reached by a different route. Missing
/// either check would leave the other pointless, since a grant and a promotion
/// produce the same end state.
///
/// A consequence worth noting: **you cannot change your own role**, because
/// nobody outranks themselves. That rules out self-demotion too, which is a
/// small loss and keeps the rule to one sentence.
pub async fn set_member_role(
    State(state): State<AppState>,
    // Admin or above to reach this at all; the finer rules are below.
    access: VaultAccess<AtLeastAdmin>,
    Path((_, member_user_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<SetRoleRequest>,
) -> Result<axum::http::StatusCode, AppError> {
    let vault_id = access.vault_id;

    let new_role = Role::parse(&req.role)
        .filter(|r| Role::ASSIGNABLE.contains(r))
        .ok_or_else(|| {
            AppError::Validation(format!(
                "role must be one of: {}",
                Role::ASSIGNABLE
                    .iter()
                    .map(|r| r.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })?;

    let current_stored = vaults::find_member_role(&state.db, vault_id, member_user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let current_role = Role::parse(&current_stored).ok_or_else(|| {
        AppError::Internal(format!("unrecognised vault role: {current_stored:?}"))
    })?;

    // ⚠️ The owner's role is fixed. Demoting them would leave the vault with no
    // owner — nobody who can delete it or promote a replacement — and there is no
    // transfer-ownership endpoint yet. Same reasoning as `remove_member`.
    if current_role == Role::Owner {
        return Err(AppError::Conflict(
            "the vault owner's role cannot be changed. Transfer ownership first — \
             which is not built yet."
                .into(),
        ));
    }

    if !access.outranks(current_role) || !access.outranks(new_role) {
        return Err(AppError::Forbidden);
    }

    // A no-op is success rather than an error: a client reconciling desired state
    // should not have to check first.
    if !members::set_role(&state.db, vault_id, member_user_id, new_role.as_str()).await? {
        return Err(AppError::NotFound);
    }

    crate::services::audit::record_membership_event(
        &state.db,
        vault_id,
        access.user_id,
        "member_role_change",
        serde_json::json!({
            "member_user_id": member_user_id,
            "from": current_role.as_str(),
            "to": new_role.as_str(),
        }),
    );

    Ok(axum::http::StatusCode::NO_CONTENT)
}

pub async fn remove_member(
    State(state): State<AppState>,
    // Any member, because leaving is always allowed. Removing *somebody else*
    // needs more, and that is checked below against the target's own rank.
    access: VaultAccess<AtLeastViewer>,
    Path((_, member_user_id)): Path<(Uuid, Uuid)>,
) -> Result<axum::http::StatusCode, AppError> {
    let VaultAccess {
        vault_id,
        user_id: requester_id,
        ..
    } = access;

    let target_stored = vaults::find_member_role(&state.db, vault_id, member_user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let target_role = Role::parse(&target_stored)
        .ok_or_else(|| AppError::Internal(format!("unrecognised vault role: {target_stored:?}")))?;

    // ⚠️ The owner cannot be removed, by anyone, including themselves.
    //
    // A vault with no owner has nobody who can delete it or promote a
    // replacement, and there is no transfer-ownership endpoint yet. Refusing is
    // recoverable; an ownerless vault is not.
    if target_role == Role::Owner {
        return Err(AppError::Conflict(
            "the vault owner cannot be removed. Transfer ownership first —              which is not built yet."
                .into(),
        ));
    }

    // ⚠️ Removing someone else requires OUTRANKING them, not merely being an
    // admin.
    //
    // Expressed as a rank comparison rather than a role list, this gets "admins
    // cannot remove other admins" for free: `Admin > Admin` is false. Two admins
    // therefore cannot evict each other in a race, and only the owner resolves a
    // disagreement between them.
    //
    // Leaving on your own account is always allowed, whatever your rank.
    let leaving_voluntarily = requester_id == member_user_id;
    if !leaving_voluntarily && !access.outranks(target_role) {
        return Err(AppError::Forbidden);
    }

    let removed = members::remove_member(&state.db, vault_id, member_user_id).await?;
    if !removed {
        return Err(AppError::NotFound);
    }

    crate::services::audit::record_membership_event(
        &state.db,
        vault_id,
        requester_id,
        "member_revoke",
        serde_json::json!({
            "member_user_id": member_user_id,
            "role": target_role.as_str(),
            "voluntary": leaving_voluntarily,
            // ⚠️ Recorded because it is the difference between a revocation that
            // took effect and one that only looks like it did. A bare removal
            // leaves the vault key unchanged, so the member keeps the ability to
            // read everything they had — see routes::rekey.
            "rekeyed": false,
        }),
    );

    Ok(axum::http::StatusCode::NO_CONTENT)
}
