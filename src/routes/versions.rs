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

use crate::{
    db::{vaults, versions},
    errors::AppError,
    services::jwt::Claims,
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
    axum::Extension(claims): axum::Extension<Claims>,
    Path(vault_id): Path<Uuid>,
    Json(req): Json<PushVersionRequest>,
) -> Result<(axum::http::StatusCode, Json<PushVersionResponse>), AppError> {
    let user_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;

    // 1. Check push permission (owner, admin, developer)
    let role = vaults::find_member_role(&state.db, vault_id, user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if !["owner", "admin", "developer"].contains(&role.as_str()) {
        return Err(AppError::Forbidden);
    }

    // 2. Optimistic locking: check base_version matches current latest
    let current_version = versions::get_latest_version_num(&state.db, vault_id).await?;
    let current_num = current_version.unwrap_or(0);

    if let Some(base) = req.base_version {
        if base != current_num {
            return Err(AppError::Conflict(format!(
                "Remote is at version {}. Pull latest before pushing (you based on {}).",
                current_num, base
            )));
        }
    }

    let new_version_num = current_num + 1;

    // 3. Decode and validate the blob
    let nonce_bytes = base64_decode(&req.nonce)
        .map_err(|_| AppError::Validation("nonce: invalid base64".into()))?;
    let ciphertext_bytes = base64_decode(&req.ciphertext)
        .map_err(|_| AppError::Validation("ciphertext: invalid base64".into()))?;

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

    // 4. Upload to S3
    let blob_key = crate::services::storage::StorageService::blob_key(vault_id, new_version_num);
    state.storage.upload_blob(&blob_key, blob_bytes).await?;

    // 5. Insert version record in DB
    let version = versions::create(
        &state.db,
        versions::CreateVersion {
            vault_id,
            version_num: new_version_num,
            blob_key,
            blob_size_bytes: blob_size,
            blob_hash: req.blob_hash,
            key_count: req.key_count,
            key_names: req.key_names,
            pushed_by: user_id,
        },
    )
    .await?;

    // 6. Record audit event (fire-and-forget — don't block response)
    tokio::spawn({
        let db = state.db.clone();
        let vault_id = vault_id;
        let user_id = user_id;
        let version_num = new_version_num;
        async move {
            let _ = crate::services::audit::record(
                &db,
                crate::services::audit::AuditEvent {
                    vault_id: Some(vault_id),
                    user_id: Some(user_id),
                    event_type: "push".into(),
                    metadata: Some(serde_json::json!({ "version": version_num })),
                    ip_hash: None,
                    user_agent_hash: None,
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

// ─── Get Latest Version Metadata ──────────────────────────────────────────────

pub async fn get_latest_version(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<Claims>,
    Path(vault_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let user_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;

    // Any vault member can get version metadata
    vaults::find_member_role(&state.db, vault_id, user_id)
        .await?
        .ok_or(AppError::NotFound)?;

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

pub async fn download_blob(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<Claims>,
    Path((vault_id, version_num)): Path<(Uuid, i32)>,
) -> Result<Response, AppError> {
    let user_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;

    // Any vault member can pull
    vaults::find_member_role(&state.db, vault_id, user_id)
        .await?
        .ok_or(AppError::NotFound)?;

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
                    metadata: Some(serde_json::json!({ "version": version_num })),
                    ip_hash: None,
                    user_agent_hash: None,
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

fn base64_decode(s: &str) -> Result<Vec<u8>, base64ct::Error> {
    use base64ct::{Base64, Encoding};
    Base64::decode_vec(s)
}

pub async fn list_versions(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<Claims>,
    Path(vault_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let user_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;

    vaults::find_member_role(&state.db, vault_id, user_id)
        .await?
        .ok_or(AppError::NotFound)?;

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
