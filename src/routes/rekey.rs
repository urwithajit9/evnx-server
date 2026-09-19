// src/routes/rekey.rs

//! Vault key rotation — Phase 3 step 5.
//!
//! ## What re-keying is for, and what it cannot do
//!
//! Removing a member deletes their `vault_members` row. It does **not** change
//! the vault key, so a member who kept their unwrapped copy could decrypt every
//! blob they ever had access to — *including versions pushed after removal*.
//! Revocation that does not revoke is worse than none, because the UI implies it
//! worked.
//!
//! ⚠️ Rotation fixes the future, not the past. Someone who could already read a
//! version may hold a copy of it, and no server-side operation recalls that.
//! Clients must say so plainly rather than implying a revocation reaches
//! backwards — the same advice the API-token guide gives for a leaked token, and
//! the step people skip: **rotate the secrets themselves.**
//!
//! ## Why two requests and not one
//!
//! Re-encrypting a vault produces one new blob per version. Sending them inline
//! would be simplest, but `MAX_REQUEST_SIZE_KB` defaults to **64 KB** and a
//! single version can approach that, so a vault with any history would be
//! unre-keyable — and an unre-keyable vault is one whose members cannot be
//! revoked. That is the failure this phase exists to remove, so it cannot be
//! traded for tidiness.
//!
//! Instead: blobs are staged individually, then **one** request swaps all the
//! metadata atomically. Staged blobs that are never committed are orphans in
//! object storage — wasted bytes, not a correctness problem, and never reachable
//! because nothing references them.
//!
//! ## The invariant the swap must hold
//!
//! ⚠️ **All of it, or none of it.** A vault whose versions are split across two
//! keys cannot be opened by any client: the old key fails on the new blobs and
//! the new key fails on the old ones. There is no partial success worth keeping,
//! so the handler validates the whole payload *before* touching anything and
//! commits in a single transaction.

use axum::{extract::State, Json};
use serde::Deserialize;
use std::collections::HashSet;
use uuid::Uuid;

use crate::{
    db::{members, versions},
    errors::AppError,
    middleware::vault_role::{AtLeastAdmin, VaultAccess},
    state::AppState,
};

// ─── Staging a re-encrypted blob ──────────────────────────────────────────────

#[derive(Deserialize)]
pub struct StageBlobRequest {
    /// The version this blob replaces. Must already exist.
    pub version_num: i32,
    /// Base64 12-byte AES-GCM nonce.
    pub nonce: String,
    /// Base64 ciphertext with the GCM tag appended.
    pub ciphertext: String,
    /// BLAKE3 hex of the ciphertext, as `push_version` requires.
    pub blob_hash: String,
}

/// Upload one re-encrypted version, without committing anything.
///
/// Returns the storage key to quote back in the swap. Nothing about the vault
/// changes here — the version still points at its old blob, and a caller that
/// abandons the re-key leaves only an orphan object behind.
pub async fn stage_blob(
    State(state): State<AppState>,
    access: VaultAccess<AtLeastAdmin>,
    Json(req): Json<StageBlobRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let vault_id = access.vault_id;

    let nonce = super::versions::base64_decode(&req.nonce)
        .map_err(|_| AppError::Validation("nonce: invalid base64".into()))?;
    let ciphertext = super::versions::base64_decode(&req.ciphertext)
        .map_err(|_| AppError::Validation("ciphertext: invalid base64".into()))?;

    // Same integrity check as a push. A staged blob whose hash does not match
    // would fail at the swap instead, after the client had uploaded everything.
    if blake3::hash(&ciphertext).to_hex().to_string() != req.blob_hash {
        return Err(AppError::Validation(
            "blob_hash does not match ciphertext content".into(),
        ));
    }

    // Refuse a version that does not exist rather than storing an object nothing
    // can ever reference.
    if !versions::all_version_nums(&state.db, vault_id)
        .await?
        .contains(&req.version_num)
    {
        return Err(AppError::NotFound);
    }

    let mut blob = Vec::with_capacity(nonce.len() + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    let blob_size = blob.len() as i32;

    // A fresh key — `blob_key` ends in a UUID, so this never overwrites the blob
    // the version currently points at. That matters: if the swap is abandoned,
    // the vault must still open with the old key.
    let blob_key = crate::services::storage::StorageService::blob_key(vault_id, req.version_num);
    state
        .storage
        .upload_blob(&blob_key, bytes::Bytes::from(blob))
        .await?;

    Ok(Json(serde_json::json!({
        "version_num":     req.version_num,
        "blob_key":        blob_key,
        "blob_size_bytes": blob_size,
    })))
}

// ─── The atomic swap ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RekeyedVersion {
    pub version_num: i32,
    /// From a `stage_blob` response — never constructed by the client.
    pub blob_key: String,
    pub blob_hash: String,
    pub blob_size_bytes: i32,
}

#[derive(Deserialize)]
pub struct RekeyedMember {
    pub user_id: Uuid,
    /// The vault key wrapped afresh for this member under the **new** key.
    pub encrypted_vault_key: String,
    pub eph_pub_key: String,
    pub mlkem_ciphertext: String,
}

#[derive(Deserialize)]
pub struct RekeyRequest {
    pub versions: Vec<RekeyedVersion>,
    pub members: Vec<RekeyedMember>,
    /// The member being revoked, if this re-key is a revocation.
    ///
    /// Removed in the same transaction, so there is no window in which they are
    /// still a member of a vault whose key has already rotated — nor one in which
    /// they are gone but the key has not.
    #[serde(default)]
    pub remove_user_id: Option<Uuid>,
}

/// Rotate a vault's key: repoint every version and re-wrap for every member.
///
/// ⚠️ **Validated whole, then committed whole.** Every check below runs before
/// anything is written, and the writes share one transaction. A partially
/// re-keyed vault is unopenable by anyone and unrecoverable without the old key,
/// which by then only the departing member still has.
///
/// # Errors
/// * `403` — not an admin, or attempting to remove someone you do not outrank.
/// * `409` — the payload does not cover exactly the vault's versions and members.
/// * `404` — the vault, or the member being removed, is not there.
pub async fn rekey(
    State(state): State<AppState>,
    // Admin or above — decided 2026-09-19. Gating this to the owner alone would
    // mean a team whose owner is away cannot revoke a departing colleague, and a
    // revocation that has to wait is the failure mode this phase removes.
    access: VaultAccess<AtLeastAdmin>,
    Json(req): Json<RekeyRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let vault_id = access.vault_id;

    // ── Who is leaving, if anyone ────────────────────────────────────────────
    if let Some(leaving) = req.remove_user_id {
        let stored = crate::db::vaults::find_member_role(&state.db, vault_id, leaving)
            .await?
            .ok_or(AppError::NotFound)?;
        let their_role = crate::middleware::vault_role::Role::parse(&stored)
            .ok_or_else(|| AppError::Internal(format!("unrecognised vault role: {stored:?}")))?;

        if their_role == crate::middleware::vault_role::Role::Owner {
            return Err(AppError::Conflict(
                "the vault owner cannot be removed. Transfer ownership first — \
                 which is not built yet."
                    .into(),
            ));
        }
        // Same rule as `remove_member`: removing someone requires outranking
        // them, which is what stops two admins evicting each other.
        if !access.outranks(their_role) {
            return Err(AppError::Forbidden);
        }
    }

    // ── Every version, exactly once ──────────────────────────────────────────
    let existing: HashSet<i32> = versions::all_version_nums(&state.db, vault_id)
        .await?
        .into_iter()
        .collect();
    let supplied: HashSet<i32> = req.versions.iter().map(|v| v.version_num).collect();

    if supplied.len() != req.versions.len() {
        return Err(AppError::Conflict(
            "the same version appears twice in `versions`".into(),
        ));
    }
    if supplied != existing {
        let missing: Vec<i32> = existing.difference(&supplied).copied().collect();
        let unknown: Vec<i32> = supplied.difference(&existing).copied().collect();
        return Err(AppError::Conflict(format!(
            "a re-key must cover every version at once. missing: {missing:?}, unknown: {unknown:?}. \
             A vault whose versions are split across two keys cannot be opened by anyone."
        )));
    }

    // ── Every remaining member, exactly once ─────────────────────────────────
    let mut remaining: HashSet<Uuid> = members::member_ids(&state.db, vault_id)
        .await?
        .into_iter()
        .collect();
    if let Some(leaving) = req.remove_user_id {
        remaining.remove(&leaving);
    }
    let rewrapped: HashSet<Uuid> = req.members.iter().map(|m| m.user_id).collect();

    if rewrapped.len() != req.members.len() {
        return Err(AppError::Conflict(
            "the same member appears twice in `members`".into(),
        ));
    }
    if let Some(leaving) = req.remove_user_id {
        // ⚠️ Wrapping the new key for the person being removed would undo the
        // entire operation, silently.
        if rewrapped.contains(&leaving) {
            return Err(AppError::Conflict(
                "the member being removed must not be given the new key".into(),
            ));
        }
    }
    if rewrapped != remaining {
        let missing: Vec<Uuid> = remaining.difference(&rewrapped).copied().collect();
        let unknown: Vec<Uuid> = rewrapped.difference(&remaining).copied().collect();
        return Err(AppError::Conflict(format!(
            "a re-key must re-wrap for every remaining member at once. \
             missing: {missing:?}, not a member: {unknown:?}. \
             A member left on the old key loses access to the whole vault."
        )));
    }

    // ── Commit ───────────────────────────────────────────────────────────────
    let mut tx = state.db.begin().await.map_err(AppError::Database)?;

    for v in &req.versions {
        if !versions::repoint_blob(
            &mut *tx,
            vault_id,
            v.version_num,
            &v.blob_key,
            &v.blob_hash,
            v.blob_size_bytes,
        )
        .await?
        {
            return Err(AppError::Conflict(format!(
                "version {} vanished mid-re-key",
                v.version_num
            )));
        }
    }

    for m in &req.members {
        let wrap = members::MemberKeyWrap::Hybrid {
            encrypted_vault_key: m.encrypted_vault_key.clone(),
            eph_pub_key: m.eph_pub_key.clone(),
            mlkem_ciphertext: m.mlkem_ciphertext.clone(),
        };
        if !members::set_wrap(&mut *tx, vault_id, m.user_id, &wrap).await? {
            return Err(AppError::Conflict(format!(
                "member {} vanished mid-re-key",
                m.user_id
            )));
        }
    }

    if let Some(leaving) = req.remove_user_id {
        members::remove_member_tx(&mut *tx, vault_id, leaving).await?;
    }

    tx.commit().await.map_err(AppError::Database)?;

    Ok(Json(serde_json::json!({
        "versions_rekeyed": req.versions.len(),
        "members_rewrapped": req.members.len(),
        "removed": req.remove_user_id,
        // ⚠️ Said here so a client has no excuse for implying otherwise.
        "note": "Rotation prevents future reads with the old key. It cannot \
                 recall copies of versions the removed member could already read \
                 — rotate those secrets at their source.",
    })))
}
