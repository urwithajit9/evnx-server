// src/routes/versions.rs

use axum::{
    body::Body,
    extract::{Path, State},
    response::Response,
    Json,
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::middleware::client_ip::ClientContext;
use crate::{
    db::versions,
    errors::AppError,
    middleware::vault_role::{AtLeastAdmin, AtLeastDeveloper, AtLeastViewer, VaultAccess},
    state::AppState,
};

// ─── Push (Upload encrypted blob) ─────────────────────────────────────────────

#[derive(Deserialize)]
pub struct PushVersionRequest {
    /// Base64-encoded 12-byte AES-GCM nonce
    pub nonce: String,
    /// Base64-encoded ciphertext + GCM auth tag
    pub ciphertext: String,
    /// BLAKE3 hex hash of the ciphertext (transport integrity)
    pub blob_hash: String,
    /// List of .env key names (not values) for display
    pub key_names: Vec<String>,
    pub key_count: i32,
    /// The version number this push is based on (optimistic locking)
    pub base_version: Option<i32>,
}

#[derive(Serialize)]
pub struct PushVersionResponse {
    pub version_num: i32,
    pub pushed_at: chrono::DateTime<chrono::Utc>,
}

pub async fn push_version(
    State(state): State<AppState>,
    client: ClientContext,
    // Developer or above. A viewer is refused before the body is read — the
    // requirement is in the signature, not in the body, so it cannot be skipped.
    access: VaultAccess<AtLeastDeveloper>,
    Json(req): Json<PushVersionRequest>,
) -> Result<(axum::http::StatusCode, Json<PushVersionResponse>), AppError> {
    let VaultAccess {
        vault_id, user_id, ..
    } = access;

    // Before the blob is uploaded, so an obvious refusal leaves no orphan in
    // storage. Like the stale-base check below this is an early, lock-free
    // refusal and not the guarantee: the count is taken again inside the
    // transaction, under the locks, and that is the one that holds.
    let cap =
        crate::services::quota::version_cap(&state.db, &state.config.quotas, vault_id).await?;
    cap.check(versions::count(&state.db, vault_id).await?)?;

    // 2. Optimistic locking: check base_version matches current latest.
    //
    // This is an early, lock-free refusal so a stale push fails before its blob
    // is uploaded. It is NOT the guarantee — the same check is repeated inside
    // the transaction below, where nothing can move underneath it.
    let current_version = versions::get_latest_version_num(&state.db, vault_id).await?;
    let current_num = current_version.unwrap_or(0);

    if let Some(base) = req.base_version {
        if base != current_num {
            return Err(stale_push(current_num, base));
        }
    }

    let new_version_num = current_num + 1;

    // 3. Decode and validate the blob
    let nonce_bytes = base64_decode(&req.nonce)
        .map_err(|_| AppError::Validation("nonce: invalid base64".into()))?;
    let ciphertext_bytes = base64_decode(&req.ciphertext)
        .map_err(|_| AppError::Validation("ciphertext: invalid base64".into()))?;
    check_blob_fields(&nonce_bytes, &req.blob_hash)?;

    // Verify the client's declared blob_hash matches the actual ciphertext
    let actual_hash = blake3::hash(&ciphertext_bytes).to_hex().to_string();
    if actual_hash != req.blob_hash {
        return Err(AppError::Validation(
            "blob_hash does not match ciphertext content".into(),
        ));
    }

    // Combine: [12-byte nonce || ciphertext] for S3 storage
    let mut blob = Vec::with_capacity(nonce_bytes.len() + ciphertext_bytes.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext_bytes);
    let blob_bytes = Bytes::from(blob);
    let blob_size = blob_bytes.len() as i32;

    // 4. Upload to storage — OUTSIDE any transaction, so no network IO happens
    // while a lock is held. The key ends in a fresh UUID, so an upload that ends
    // up unreferenced is an orphan, never an overwrite.
    let blob_key = crate::services::storage::StorageService::blob_key(vault_id, new_version_num);
    state.storage.upload_blob(&blob_key, blob_bytes).await?;

    // 5. Insert version record in DB, under the C4 locks.
    let inserted = commit_version(
        &state.db,
        user_id,
        &cap,
        current_num,
        req.base_version,
        versions::CreateVersion {
            vault_id,
            version_num: new_version_num,
            blob_key: blob_key.clone(),
            blob_size_bytes: blob_size,
            blob_hash: req.blob_hash,
            key_count: req.key_count,
            key_names: req.key_names,
            pushed_by: user_id,
        },
    )
    .await;

    let version = match inserted {
        Ok(v) => v,
        Err(e) => {
            // The blob is referenced by nothing. Best effort: a failed delete is
            // an orphan object, which is what an abandoned re-key leaves too.
            if let Err(del) = state.storage.delete_blob(&blob_key).await {
                tracing::warn!(
                    %vault_id, blob_key = %blob_key, error = %del,
                    "push refused after upload; could not delete the orphan blob"
                );
            }
            return Err(e);
        }
    };

    // 6. Record audit event (fire-and-forget — don't block response)
    tokio::spawn({
        let db = state.db.clone();
        // vault_id and user_id are Copy — `async move` captures them directly.
        let version_num = new_version_num;
        async move {
            let _ = crate::services::audit::record(
                &db,
                crate::services::audit::AuditEvent {
                    vault_id: Some(vault_id),
                    user_id: Some(user_id),
                    event_type: "push".into(),
                    metadata: Some(serde_json::json!({ "version": version_num })),
                    ip_hash: client.ip_hash.clone(),
                    user_agent_hash: client.user_agent_hash.clone(),
                },
            )
            .await;
        }
    });

    Ok((
        axum::http::StatusCode::CREATED,
        Json(PushVersionResponse {
            version_num: version.version_num,
            pushed_at: version.pushed_at,
        }),
    ))
}

/// The 409 for a push that was based on a version the vault has moved past.
/// The CLI appends "pull first" guidance to this message, so keep it a plain
/// statement of where the remote is.
fn stale_push(remote_at: i32, based_on: i32) -> AppError {
    AppError::Conflict(format!(
        "Remote is at version {remote_at}. Pull latest before pushing (you based on {based_on})."
    ))
}

/// Re-check the caller's role and insert the version, in one transaction.
///
/// ⚠️ **Lock order: vault row, then the caller's membership row** — see
/// [`crate::db::locks`] for the table and the reasoning. The extractor's role
/// check ran on its own connection, before the upload; it can be stale by the
/// time we get here, which is the C4 hole. Holding the membership row `FOR
/// SHARE` until commit makes a concurrent removal or downgrade wait for this
/// push, and makes a push that starts afterwards see it.
///
/// The version limit is counted after those locks and before the insert, so two
/// writers cannot each count under the limit and both add a row past it.
///
/// `expected_latest` is what the pre-upload read saw. The blob key was named for
/// `expected_latest + 1`, so if the vault has moved on the push is stale
/// whether or not the client sent a `base_version`: 409, not a renumbered
/// version that disagrees with its own blob key.
async fn commit_version(
    db: &sqlx::PgPool,
    user_id: Uuid,
    cap: &crate::services::quota::VersionCap,
    expected_latest: i32,
    base_version: Option<i32>,
    input: versions::CreateVersion,
) -> Result<versions::VersionRow, AppError> {
    use crate::db::locks;
    use crate::middleware::vault_role::{MinRole, Role};

    let vault_id = input.vault_id;
    let mut tx = db.begin().await?;

    if !locks::lock_vault_shared(&mut tx, vault_id).await? {
        return Err(AppError::NotFound);
    }

    // 403 with the extractor's own refusal. A member removed in the meantime is
    // also a 403 rather than the extractor's 404: they were a member when the
    // request was admitted, so the vault's existence is no secret from them.
    let refused = || {
        AppError::Refused(crate::errors::Refusal::RoleTooLow {
            required: AtLeastDeveloper::MIN.as_str(),
        })
    };
    let stored = locks::lock_member_shared(&mut tx, vault_id, user_id)
        .await?
        .ok_or_else(refused)?;
    let role = Role::parse(&stored).ok_or_else(|| {
        AppError::Internal(format!(
            "unrecognised vault role in the database: {stored:?}"
        ))
    })?;
    if role < AtLeastDeveloper::MIN {
        return Err(refused());
    }

    let latest = versions::get_latest_version_num(&mut *tx, vault_id)
        .await?
        .unwrap_or(0);
    if latest != expected_latest {
        return Err(stale_push(latest, base_version.unwrap_or(expected_latest)));
    }

    // The plan's version limit, counted here so that it is the number that
    // holds when the row goes in. The answer is the same 403 as the early check.
    crate::services::quota::check_version_limit_in_tx(&mut tx, cap, vault_id).await?;

    let version = match versions::create(&mut *tx, input).await {
        Ok(v) => v,
        // Two pushes read the same latest under shared locks; the second INSERT
        // waits on the first's index entry and fails here once it commits.
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(stale_push(
                expected_latest + 1,
                base_version.unwrap_or(expected_latest),
            ));
        }
        Err(e) => return Err(e.into()),
    };

    tx.commit().await?;
    Ok(version)
}

// ─── Get Latest Version Metadata ──────────────────────────────────────────────

pub async fn get_latest_version(
    State(state): State<AppState>,
    // Any member. Version metadata carries no secret values — only key *names*.
    access: VaultAccess<AtLeastViewer>,
) -> Result<Json<serde_json::Value>, AppError> {
    let vault_id = access.vault_id;

    let version = versions::get_latest(&state.db, vault_id)
        .await?
        .ok_or(AppError::NotFound)?;

    Ok(Json(serde_json::json!({
        "version_num":     version.version_num,
        "blob_hash":       version.blob_hash,
        "key_count":       version.key_count,
        "key_names":       version.key_names,
        "blob_size_bytes": version.blob_size_bytes,
        "pushed_by":       version.pushed_by,
        "pushed_at":       version.pushed_at,
    })))
}

// ─── Download Blob ─────────────────────────────────────────────────────────────

#[derive(Deserialize, Default)]
pub struct DownloadQuery {
    /// Optional; `"rekey"` marks the pull as part of a key rotation.
    #[serde(default)]
    pub purpose: Option<String>,
}

pub async fn download_blob(
    State(state): State<AppState>,
    client: ClientContext,
    // Any member may pull. The blob is ciphertext either way — the server could
    // not hand over plaintext if it wanted to — so this gate is about metadata
    // and audit trail, not confidentiality.
    access: VaultAccess<AtLeastViewer>,
    Path((_, version_num)): Path<(Uuid, i32)>,
    axum::extract::Query(q): axum::extract::Query<DownloadQuery>,
) -> Result<Response, AppError> {
    let VaultAccess {
        vault_id,
        user_id,
        role,
        ..
    } = access;

    // RM-57: a rekey read is marked in the audit trail. Only roles that can
    // rekey (admin+) are believed; anyone else's `purpose` is ignored and the
    // pull is recorded exactly as before. Never a reason to refuse.
    let rekey_read =
        q.purpose.as_deref() == Some("rekey") && role >= crate::middleware::vault_role::Role::Admin;
    let pull_metadata = if rekey_read {
        serde_json::json!({ "version": version_num, "purpose": "rekey" })
    } else {
        serde_json::json!({ "version": version_num })
    };

    let version = versions::get_by_num(&state.db, vault_id, version_num)
        .await?
        .ok_or(AppError::NotFound)?;

    // Download blob from S3
    let blob_bytes = state.storage.download_blob(&version.blob_key).await?;

    // Verify integrity before sending to client
    let download_hash = blake3::hash(&blob_bytes[12..]).to_hex().to_string(); // skip 12-byte nonce prefix
    if download_hash != version.blob_hash {
        tracing::error!(
            vault_id = %vault_id,
            version = version_num,
            "Blob hash mismatch — possible S3 corruption"
        );
        return Err(AppError::Internal("Blob integrity check failed".into()));
    }

    // Record audit (fire-and-forget)
    tokio::spawn({
        let db = state.db.clone();
        async move {
            let _ = crate::services::audit::record(
                &db,
                crate::services::audit::AuditEvent {
                    vault_id: Some(vault_id),
                    user_id: Some(user_id),
                    event_type: "pull".into(),
                    metadata: Some(pull_metadata),
                    ip_hash: client.ip_hash.clone(),
                    user_agent_hash: client.user_agent_hash.clone(),
                },
            )
            .await;
        }
    });

    // Stream blob to client as binary
    Ok(Response::builder()
        .status(200)
        .header("Content-Type", "application/octet-stream")
        .header("Content-Length", blob_bytes.len())
        .header("X-Blob-Hash", &version.blob_hash)
        .body(Body::from(blob_bytes))
        .unwrap())
}

/// Length of the AES-256-GCM nonce stored in front of every blob.
pub(crate) const BLOB_NONCE_LEN: usize = 12;

/// Length of a hex-encoded BLAKE3 digest.
const BLOB_HASH_HEX_LEN: usize = 64;

/// Refuse a blob whose fixed-size fields have the wrong size.
///
/// Only the ciphertext is hashed, so a nonce of the wrong length used to be
/// stored without complaint and surface later as a failed download. Shared with
/// `routes::rekey` so a push and a staged blob are held to the same rules.
pub(crate) fn check_blob_fields(nonce: &[u8], blob_hash: &str) -> Result<(), AppError> {
    if nonce.len() != BLOB_NONCE_LEN {
        return Err(AppError::Validation(format!(
            "nonce: must be {BLOB_NONCE_LEN} bytes, got {}",
            nonce.len()
        )));
    }
    check_blob_hash_format(blob_hash)
}

/// A `blob_hash` is 64 lowercase hex characters.
pub(crate) fn check_blob_hash_format(blob_hash: &str) -> Result<(), AppError> {
    let ok = blob_hash.len() == BLOB_HASH_HEX_LEN
        && blob_hash
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c));
    if !ok {
        return Err(AppError::Validation(format!(
            "blob_hash: must be {BLOB_HASH_HEX_LEN} lowercase hex characters"
        )));
    }
    Ok(())
}

/// Shared with `routes::rekey`, which stages blobs in the same wire format a
/// push uses. Two decoders would be two chances to disagree about padding.
pub(crate) fn base64_decode(s: &str) -> Result<Vec<u8>, base64ct::Error> {
    use base64ct::{Base64, Encoding};
    Base64::decode_vec(s)
}

pub async fn list_versions(
    State(state): State<AppState>,
    // Any member. History is key *names* and hashes, never values.
    access: VaultAccess<AtLeastViewer>,
) -> Result<Json<serde_json::Value>, AppError> {
    let vault_id = access.vault_id;

    let versions = versions::list(&state.db, vault_id).await?;

    let list: Vec<serde_json::Value> = versions
        .iter()
        .map(|v| {
            serde_json::json!({
                "version_num":     v.version_num,
                "blob_hash":       v.blob_hash,
                "key_count":       v.key_count,
                "key_names":       v.key_names,
                "blob_size_bytes": v.blob_size_bytes,
                "pushed_by":       v.pushed_by,
                "pushed_at":       v.pushed_at,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({ "versions": list })))
}

// ─── Deleting a version ───────────────────────────────────────────────────────

/// Remove one version of a vault, and its blob.
///
/// ─── Why this exists ─────────────────────────────────────────────────────────
///
/// ⚠️ It was written because the version quota refused a push with *"Delete older
/// versions of this vault to make room"* while there was **no way to delete a
/// version** — no endpoint, no command. A free-tier account that reached the limit
/// could never push again, and the remedy the error named did not exist. An error
/// message that advises an impossible action is worse than one that admits there is
/// nothing to be done, because it sends people looking.
///
/// ─── Why an admin, and not whoever can push ──────────────────────────────────
///
/// A developer can add history; removing it takes an admin. Pushing is additive and
/// recoverable — the previous version is still there. This is neither: the blob goes
/// from object storage and no server-side action brings it back, because the server
/// never held anything that could reconstruct it.
///
/// ─── The latest version, and when it can go ─────────────────────────────────
///
/// `cloud pull` and `cloud run` fetch the latest, so deleting it changes what every
/// consumer of the vault receives: the previous version becomes the latest. That is
/// the point when the latest is a bad push — undecryptable, or wrong — and the only
/// way back otherwise is another push, which can only move forward. It is also why
/// this stays an admin action, and why it is audited with `was_latest`.
///
/// It is refused when it is the only version, since that would leave a vault with
/// nothing in it and no way to tell a consumer why. The vault itself is deleted
/// through its own endpoint.
///
/// ⚠️ The version number is not retired. The next push is numbered
/// `latest + 1`, so after deleting version N the next push is N again. A client
/// that remembers having seen N may report that the vault went backwards.
///
/// The decision is taken under the vault lock, so two admins deleting the last
/// two versions at once cannot empty the vault between them, and a push cannot
/// land in the middle of it.
pub async fn delete_version(
    State(state): State<AppState>,
    client: ClientContext,
    access: VaultAccess<AtLeastAdmin>,
    Path((_vault_id, version_num)): Path<(Uuid, i32)>,
) -> Result<Json<serde_json::Value>, AppError> {
    let VaultAccess {
        vault_id, user_id, ..
    } = access;

    let mut tx = state.db.begin().await?;
    if !crate::db::locks::lock_vault_exclusive(&mut tx, vault_id).await? {
        return Err(AppError::NotFound);
    }

    let nums = versions::all_version_nums(&mut *tx, vault_id).await?;
    let latest = *nums.last().ok_or(AppError::NotFound)?;
    let was_latest = version_num == latest;

    if was_latest && nums.len() == 1 {
        return Err(AppError::Conflict(format!(
            "version {version_num} is the only version, and deleting it would leave the \
             vault empty. Push a newer version first, or delete the whole vault. \
             Nothing has been changed."
        )));
    }

    let blob_key = versions::delete_by_num(&mut *tx, vault_id, version_num)
        .await?
        .ok_or(AppError::NotFound)?;

    // What `cloud pull` returns from now on.
    let new_latest = if was_latest {
        nums[nums.len() - 2]
    } else {
        latest
    };

    tx.commit().await?;

    // Recorded before the blob goes, and awaited rather than spawned: this is the
    // only remaining evidence that the version existed at all.
    if let Err(e) = crate::services::audit::record(
        &state.db,
        crate::services::audit::AuditEvent {
            vault_id: Some(vault_id),
            user_id: Some(user_id),
            event_type: "version_deleted".into(),
            ip_hash: client.ip_hash.clone(),
            user_agent_hash: client.user_agent_hash.clone(),
            metadata: Some(serde_json::json!({
                "version_num": version_num,
                "was_latest": was_latest,
                "latest_after": new_latest,
            })),
        },
    )
    .await
    {
        tracing::warn!(error = %e, "could not record a version deletion");
    }

    // ⚠️ After the row, and best-effort. The other order is worse: freeing the blob
    // first and then failing the row delete leaves a version that cannot be
    // downloaded and looks fine in every listing. An orphaned object is wasted
    // bytes; a version pointing at nothing is a lie. Same trade as `delete_account`.
    if let Err(e) = state.storage.delete_blob(&blob_key).await {
        tracing::warn!(
            error = %e,
            "version deleted, but its blob could not be removed from storage"
        );
    }

    tracing::info!(%vault_id, version_num, was_latest, "version deleted");

    Ok(Json(serde_json::json!({
        "deleted":    version_num,
        // The latest after this deletion, which is the previous version when the
        // latest was the one deleted.
        "latest":     new_latest,
        "was_latest": was_latest,
    })))
}
