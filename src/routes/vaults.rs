// src/routes/vaults.rs

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

use crate::{
    db::{members, vaults},
    errors::AppError,
    middleware::vault_role::{AtLeastViewer, OwnerOnly, VaultAccess},
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

    /// The creator's own copy of the vault key, wrapped client-side. The server
    /// never sees it unwrapped and never inspects it.
    pub encrypted_vault_key: String,

    /// Ephemeral X25519 public key, present **only** when the wrap was done by
    /// ECDH — that is, for a key wrapped *for someone else*.
    ///
    /// A vault's creator wraps their own copy under their master key
    /// (`wrap_vault_key_with_master_key`), which involves no ECDH and therefore
    /// no ephemeral, so this is `None`. That is not a detail: solo vaults are
    /// post-quantum safe precisely because that path is Argon2id + XChaCha20 and
    /// never touches X25519. Requiring an ephemeral here would force the creator
    /// through ECDH and silently make every vault vulnerable to
    /// harvest-now-decrypt-later, contradicting the guarantee in CLAUDE.md and
    /// `evnx-crypto/docs/security-model.md`.
    ///
    /// The column is nullable for the same reason.
    #[serde(default)]
    pub eph_pub_key: Option<String>,

    /// ML-KEM-768 ciphertext, present **only** alongside `eph_pub_key`.
    ///
    /// Same reasoning: the creator's own copy uses no key agreement of either
    /// kind, so there is nothing to encapsulate. A CHECK constraint on
    /// `vault_members` refuses a row carrying one of the two without the other,
    /// so a client that sent only an ephemeral would get a database error rather
    /// than a silently downgraded wrap.
    #[serde(default)]
    pub mlkem_ciphertext: Option<String>,
}

// Regex for vault names: lowercase alphanumeric + hyphens.
// std::sync::LazyLock rather than once_cell::sync::Lazy — validator 0.21
// implements its AsRegex trait for the former only.
static NAME_RE: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"^[a-z0-9\-]+$").unwrap());

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

    // One transaction for both inserts. A vault without its owner row in
    // vault_members is invisible to list_vaults (which inner joins that table)
    // yet still occupies its unique (owner, name, environment) — the owner could
    // neither see the vault nor reuse the name.
    let mut tx = state.db.begin().await.map_err(AppError::Database)?;

    let vault_id = vaults::create(&mut *tx, user_id, &req.name, &req.environment)
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

    // The owner's own copy of the vault key, wrapped client-side under their
    // master key. The server never sees it unwrapped, and stores no ephemeral
    // because that path uses no ECDH — see CreateVaultRequest::eph_pub_key.
    //
    // A client that sends one key-agreement field without the other is sending
    // half a wrap; `MemberKeyWrap` has no shape for that, so it is refused here
    // rather than stored.
    let wrap = match (&req.eph_pub_key, &req.mlkem_ciphertext) {
        (None, None) => members::MemberKeyWrap::OwnMasterKey {
            encrypted_vault_key: req.encrypted_vault_key.clone(),
        },
        (Some(eph), Some(ct)) => members::MemberKeyWrap::Hybrid {
            encrypted_vault_key: req.encrypted_vault_key.clone(),
            eph_pub_key: eph.clone(),
            mlkem_ciphertext: ct.clone(),
        },
        _ => {
            return Err(AppError::Validation(
                "eph_pub_key and mlkem_ciphertext must be sent together or not at \
                 all. One without the other is a vault key wrapped by ECDH with no \
                 post-quantum half, which a quantum computer breaks."
                    .into(),
            ))
        }
    };

    members::add_member(&mut *tx, vault_id, user_id, "owner", &wrap, user_id).await?;

    tx.commit().await.map_err(AppError::Database)?;

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
    // Owner only. An admin can share, revoke and re-key, but destroying the vault
    // — and everyone else's access with it — stays with the one account that
    // created it.
    access: VaultAccess<OwnerOnly>,
) -> Result<axum::http::StatusCode, AppError> {
    let VaultAccess {
        vault_id, user_id, ..
    } = access;

    let deleted = vaults::soft_delete(&state.db, vault_id, user_id).await?;
    if !deleted {
        return Err(AppError::NotFound);
    }

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ─── Get My Vault Key ─────────────────────────────────────────────────────────

pub async fn get_my_key(
    State(state): State<AppState>,
    // Any member. Previously this had no explicit check and relied on the query
    // returning nothing for a non-member — correct, but authorisation by
    // side-effect. Now it is stated.
    access: VaultAccess<AtLeastViewer>,
) -> Result<Json<serde_json::Value>, AppError> {
    let VaultAccess {
        vault_id, user_id, ..
    } = access;

    let key_row = members::get_wrapped_key(&state.db, vault_id, user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    Ok(Json(serde_json::json!({
        "encrypted_vault_key": key_row.encrypted_vault_key,
        // Both null together for the creator's own copy — unwrap it with the
        // master key. Both present for a share — unwrap it with the hybrid path.
        // The pair is what tells a client which of the two it is holding.
        "eph_pub_key": key_row.eph_pub_key,
        "mlkem_ciphertext": key_row.mlkem_ciphertext,
    })))
}

// ─── Audit trail ──────────────────────────────────────────────────────────────

/// What has happened to this vault.
///
/// ─── Who may read it ─────────────────────────────────────────────────────────
///
/// **Any member.** The same reasoning as the member list: noticing that someone
/// pulled a secret they should not have, or granted access you did not expect,
/// requires being able to look. Restricting the trail to admins would leave the
/// people best placed to spot something unable to.
///
/// ─── What it does not return ─────────────────────────────────────────────────
///
/// ⚠️ No `ip_hash`, no `user_agent_hash`. They are stable digests, so they
/// correlate a person's activity across events without naming them — useful to
/// an operator investigating, and a tracking primitive handed to every colleague
/// who shares a vault. They stay in the database.
///
/// No key material either; `services::audit` never writes any, and there is a
/// test asserting so.
pub async fn vault_audit(
    State(state): State<AppState>,
    access: VaultAccess<AtLeastViewer>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Capped rather than paginated. An audit view is read by a human scanning for
    // something surprising, and 200 events is more than anyone scans; proper
    // paging can arrive when someone actually needs to walk further back.
    const LIMIT: i64 = 200;

    let events = crate::services::audit::list_for_vault(&state.db, access.vault_id, LIMIT).await?;

    Ok(Json(serde_json::json!({
        "events": events
            .into_iter()
            .map(|e| serde_json::json!({
                "id":           e.id,
                "event_type":   e.event_type,
                "user_id":      e.user_id,
                // `null` when the account has been deleted since.
                "actor_email":  e.actor_email,
                "metadata":     e.metadata,
                "created_at":   e.created_at,
            }))
            .collect::<Vec<_>>(),
        "limit": LIMIT,
    })))
}
