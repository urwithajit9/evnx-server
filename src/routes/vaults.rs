// src/routes/vaults.rs

use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

use crate::{
    db::{members, vaults},
    errors::AppError,
    services::jwt::Claims,
    state::AppState,
};

// ─── Create Vault ─────────────────────────────────────────────────────────────

#[derive(Deserialize, Validate)]
pub struct CreateVaultRequest {
    #[validate(length(min = 1, max = 64, message = "name must be 1–64 chars"))]
    #[validate(regex(path = "NAME_RE", message = "name: only alphanumeric and hyphens"))]
    pub name: String,

    #[validate(length(min = 1, max = 32))]
    pub environment: String,

    /// ECDH-wrapped vault key for the owner (generated client-side).
    pub encrypted_vault_key: String,
    pub eph_pub_key: String,
}

// Regex for vault names: lowercase alphanumeric + hyphens
static NAME_RE: once_cell::sync::Lazy<regex::Regex> =
    once_cell::sync::Lazy::new(|| regex::Regex::new(r"^[a-z0-9\-]+$").unwrap());

#[derive(Serialize)]
pub struct CreateVaultResponse {
    pub vault_id: Uuid,
    pub name: String,
    pub environment: String,
}

pub async fn create_vault(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<Claims>,
    Json(req): Json<CreateVaultRequest>,
) -> Result<(axum::http::StatusCode, Json<CreateVaultResponse>), AppError> {
    req.validate()
        .map_err(|e| AppError::Validation(format!("{e}")))?;

    let user_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;

    // Valid environment values
    let valid_envs = ["production", "staging", "development", "test"];
    if !valid_envs.contains(&req.environment.as_str()) {
        return Err(AppError::Validation(format!(
            "environment must be one of: {}",
            valid_envs.join(", ")
        )));
    }

    // Create vault
    let vault_id = vaults::create(&state.db, user_id, &req.name, &req.environment)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.constraint() == Some("vaults_owner_id_name_environment_key") {
                    return AppError::Conflict(format!(
                        "Vault '{}/{}' already exists",
                        req.name, req.environment
                    ));
                }
            }
            AppError::Database(e)
        })?;

    // Add owner as vault member with their ECDH-wrapped vault key
    members::add_member(
        &state.db,
        vault_id,
        user_id,
        "owner",
        &req.encrypted_vault_key,
        &req.eph_pub_key,
        user_id,
    )
    .await?;

    Ok((
        axum::http::StatusCode::CREATED,
        Json(CreateVaultResponse {
            vault_id,
            name: req.name,
            environment: req.environment,
        }),
    ))
}

// ─── List Vaults ──────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct VaultSummary {
    pub id: Uuid,
    pub name: String,
    pub environment: String,
    pub role: String,
    pub version_count: i64,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

pub async fn list_vaults(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<Claims>,
) -> Result<Json<serde_json::Value>, AppError> {
    let user_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;

    let vault_rows = vaults::list_for_user(&state.db, user_id).await?;

    let vaults_json: Vec<VaultSummary> = vault_rows
        .into_iter()
        .map(|v| VaultSummary {
            id: v.id,
            name: v.name,
            environment: v.environment,
            role: v.role,
            version_count: v.version_count,
            updated_at: v.updated_at,
        })
        .collect();

    Ok(Json(serde_json::json!({ "vaults": vaults_json })))
}

// ─── Delete Vault ─────────────────────────────────────────────────────────────

pub async fn delete_vault(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<Claims>,
    Path(vault_id): Path<Uuid>,
) -> Result<axum::http::StatusCode, AppError> {
    let user_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;

    // Only owners can delete
    let role = vaults::find_member_role(&state.db, vault_id, user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if role != "owner" {
        return Err(AppError::Forbidden);
    }

    let deleted = vaults::soft_delete(&state.db, vault_id, user_id).await?;
    if !deleted {
        return Err(AppError::NotFound);
    }

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ─── Get My Vault Key ─────────────────────────────────────────────────────────

pub async fn get_my_key(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<Claims>,
    Path(vault_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let user_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;

    let key_row = members::get_wrapped_key(&state.db, vault_id, user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    Ok(Json(serde_json::json!({
        "encrypted_vault_key": key_row.encrypted_vault_key,
        "eph_pub_key": key_row.eph_pub_key,
    })))
}
