// src/routes/export.rs

//! Data portability — GDPR Article 20, the other half of account deletion.
//!
//! ## What this is, and the one sentence that matters
//!
//! **Your secrets are not in here, and they cannot be.** Article 20 covers the
//! data the controller holds. For evnx that is metadata plus opaque ciphertext:
//! the server has never held a plaintext secret, a master key, or a vault key, so
//! there is nothing to export that it could decrypt. The document says so in its
//! own body — pointing at `evnx cloud pull` — rather than leaving someone to
//! discover it by searching the file for a value they expected to find.
//!
//! That is not a limitation to apologise for. It is the product guarantee,
//! stated at the one moment someone is most likely to test it.
//!
//! ## ⚠️ What is deliberately left out, and why each
//!
//! The rule is one line: **this export carries metadata, never credentials or key
//! material.** Public keys are included because they are public.
//!
//! | Left out | Why |
//! |---|---|
//! | `srp_verifier`, `srp_salt` | password-equivalent for an **offline dictionary attack**. A file in someone's Downloads folder must not be a password-cracking target, and this is the same reasoning the backup script's header gives for the nightly dump |
//! | `totp_secret_enc`, recovery-code hashes | a live second factor |
//! | `api_tokens.token_hash` | a live credential |
//! | `encrypted_private_key` | key material. Useless without the master password, and already reachable at `/auth/me` by a client that genuinely needs it — a metadata export landing in Downloads is the wrong carrier |
//! | `audit_events.ip_hash`, `user_agent_hash` | **keyed** BLAKE3 digests. Not reversible by the person they describe, so exporting them would add noise and no portability |
//! | the encrypted blobs | opaque ciphertext, and potentially large. `evnx cloud pull` is the way to get the contents, decrypted, on a machine that holds the key |
//!
//! ## Why the audit trail is scoped to the account, not to its vaults
//!
//! Only events with `user_id = <you>` are exported. A vault's trail also records
//! what **other** members did, and Article 20 covers data concerning *the data
//! subject* — not everyone they happen to share a vault with. Exporting vault-wide
//! activity would widen exposure under the banner of a privacy right, which is
//! exactly backwards. The existing per-vault audit view already serves that need,
//! behind its own access control.

use axum::{extract::State, Json};
use serde_json::json;

use crate::errors::AppError;
use crate::services::jwt::Claims;
use crate::state::AppState;

/// How many audit events the export carries.
///
/// Capped rather than paginated, matching the per-vault audit view. An export is
/// a one-off download read by a person, and a file that grows without bound is a
/// worse artefact than one that says where it stopped — which the document does,
/// via `audit_events_truncated`.
const AUDIT_LIMIT: i64 = 1000;

/// Everything the server holds about the caller, as JSON.
///
/// `GET /api/v1/auth/account/export`
///
/// # Errors
/// * `401` — no session.
/// * `403` — an API token tried this; the route sits behind `require_user_session`.
///
/// ⚠️ **Behind `require_user_session`, not `require_verified`.** A CI token must
/// not be able to pull down the account's entire metadata map — every vault name,
/// every member's email, the whole activity trail. That is the same reasoning
/// that keeps `DELETE /account` and the TOTP routes off API tokens: a credential
/// issued for a pipeline should not be able to act on the account itself.
pub async fn export_account(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<Claims>,
) -> Result<Json<serde_json::Value>, AppError> {
    let user_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;

    // ── The account ──────────────────────────────────────────────────────────
    let account = sqlx::query!(
        r#"
        SELECT email, email_verified, totp_enabled, plan,
               created_at, updated_at, last_login_at,
               ed25519_public_key, x25519_public_key, mlkem_public_key
        FROM users WHERE id = $1
        "#,
        user_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::Database)?
    .ok_or(AppError::Unauthorized)?;

    // ── Vaults you can reach ─────────────────────────────────────────────────
    //
    // Soft-deleted vaults are excluded: `deleted_at IS NULL` matches what every
    // other route considers to exist, and an export listing vaults the product
    // says are gone would be a different kind of wrong.
    let vaults = sqlx::query!(
        r#"
        SELECT v.id, v.name, v.environment, v.created_at,
               m.role, m.granted_at,
               (v.owner_id = $1) AS "is_owner!"
        FROM vaults v
        JOIN vault_members m ON m.vault_id = v.id
        WHERE m.user_id = $1 AND v.deleted_at IS NULL
        ORDER BY v.name, v.environment
        "#,
        user_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(AppError::Database)?;

    let vault_ids: Vec<uuid::Uuid> = vaults.iter().map(|v| v.id).collect();

    // ── Who else is in them ──────────────────────────────────────────────────
    //
    // Other members' email addresses are part of what the account holds — you can
    // already see them with `evnx vault members` — so withholding them here would
    // make the export less useful without making anyone more private.
    let members = sqlx::query!(
        r#"
        SELECT m.vault_id, u.email, m.role, m.granted_at
        FROM vault_members m
        JOIN users u ON u.id = m.user_id
        WHERE m.vault_id = ANY($1)
        ORDER BY m.vault_id, u.email
        "#,
        &vault_ids
    )
    .fetch_all(&state.db)
    .await
    .map_err(AppError::Database)?;

    // ── Version history ──────────────────────────────────────────────────────
    //
    // `key_names` is the variable NAMES, never their values — the server stores
    // the names so `evnx cloud history` can show what a version contained without
    // decrypting anything. Worth knowing before sharing the file: it reveals the
    // shape of your configuration, if not its contents.
    let versions = sqlx::query!(
        r#"
        SELECT vv.vault_id, vv.version_num, vv.blob_hash, vv.blob_size_bytes,
               vv.key_count, vv.key_names, vv.pushed_at,
               u.email AS "pushed_by_email?"
        FROM vault_versions vv
        LEFT JOIN users u ON u.id = vv.pushed_by
        WHERE vv.vault_id = ANY($1)
        ORDER BY vv.vault_id, vv.version_num
        "#,
        &vault_ids
    )
    .fetch_all(&state.db)
    .await
    .map_err(AppError::Database)?;

    // ── API tokens, without the tokens ───────────────────────────────────────
    let tokens = sqlx::query!(
        r#"
        SELECT id, name, scope, vault_id, created_at, expires_at, last_used_at, revoked_at
        FROM api_tokens WHERE user_id = $1 ORDER BY created_at
        "#,
        user_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(AppError::Database)?;

    // ── Your activity ────────────────────────────────────────────────────────
    let events = sqlx::query!(
        r#"
        SELECT id, event_type, vault_id, metadata, created_at
        FROM audit_events
        WHERE user_id = $1
        ORDER BY created_at DESC
        LIMIT $2
        "#,
        user_id,
        AUDIT_LIMIT
    )
    .fetch_all(&state.db)
    .await
    .map_err(AppError::Database)?;

    // ── Assemble ─────────────────────────────────────────────────────────────
    let vaults_json: Vec<_> = vaults
        .iter()
        .map(|v| {
            json!({
                "id":          v.id,
                "name":        v.name,
                "environment": v.environment,
                "created_at":  v.created_at,
                "your_role":   v.role,
                "you_are_the_owner": v.is_owner,
                "you_joined_at":     v.granted_at,
                "members": members.iter().filter(|m| m.vault_id == v.id).map(|m| json!({
                    "email":      m.email,
                    "role":       m.role,
                    "granted_at": m.granted_at,
                })).collect::<Vec<_>>(),
                "versions": versions.iter().filter(|x| x.vault_id == v.id).map(|x| json!({
                    "version_num":     x.version_num,
                    "pushed_at":       x.pushed_at,
                    "pushed_by_email": x.pushed_by_email,
                    "key_count":       x.key_count,
                    // Names only. Never values — the server has never held one.
                    "key_names":       x.key_names,
                    "blob_hash":       x.blob_hash,
                    "blob_size_bytes": x.blob_size_bytes,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();

    Ok(Json(json!({
        "evnx_export": {
            "format_version": 1,
            "generated_at":   chrono::Utc::now(),
            "account":        account.email,

            // ⚠️ Stated in the document, not only in the docs. Someone opening this
            // file is looking for their data; the first thing they must learn is
            // which part of it is deliberately absent and how to get it instead.
            "your_secrets_are_not_in_this_file": {
                "why": "evnx is zero-knowledge. Your secrets are encrypted on your \
                        machine with a key derived from your master password, and the \
                        server has never held that password, that key, or any plaintext \
                        value. There is nothing here to decrypt them with because the \
                        server has never been able to.",
                "how_to_get_them": "Run `evnx cloud pull` for each vault listed below, \
                                    on a machine signed in to this account. That decrypts \
                                    locally and writes a .env file.",
                "what_is_here_instead": "Metadata: which vaults exist, who can reach \
                                         them, what each version contained by variable \
                                         NAME, and what this account did and when.",
            },

            "also_not_included": {
                "password_material": "Your SRP verifier and salts are excluded. They are \
                                      password-equivalent for an offline attack, and a \
                                      downloaded file should not be a cracking target.",
                "second_factor":     "TOTP secret and recovery codes are excluded — they \
                                      are live credentials.",
                "api_token_values":  "Tokens are listed by name and scope. The values \
                                      themselves exist only as hashes and were shown once \
                                      at creation.",
                "encrypted_blobs":   "The ciphertext itself is not inlined. Use \
                                      `evnx cloud pull`.",
            },

            "note_before_sharing_this_file": "`key_names` lists your variable names, \
                                              which describe the shape of your \
                                              configuration even though no value appears \
                                              anywhere in this document.",
        },

        "account": {
            "email":          account.email,
            "email_verified": account.email_verified,
            "totp_enabled":   account.totp_enabled,
            "plan":           account.plan,
            "created_at":     account.created_at,
            "updated_at":     account.updated_at,
            "last_login_at":  account.last_login_at,
            // Public by definition — these are what other people encrypt to.
            "public_keys": {
                "ed25519": account.ed25519_public_key,
                "x25519":  account.x25519_public_key,
                "ml_kem":  account.mlkem_public_key,
            },
        },

        "vaults": vaults_json,

        "api_tokens": tokens.iter().map(|t| json!({
            "id":           t.id,
            "name":         t.name,
            "scope":        t.scope,
            "vault_id":     t.vault_id,
            "created_at":   t.created_at,
            "expires_at":   t.expires_at,
            "last_used_at": t.last_used_at,
            "revoked_at":   t.revoked_at,
        })).collect::<Vec<_>>(),

        "audit_events": events.iter().map(|e| json!({
            "id":         e.id,
            "event_type": e.event_type,
            "vault_id":   e.vault_id,
            "metadata":   e.metadata,
            "created_at": e.created_at,
        })).collect::<Vec<_>>(),

        // Told rather than left to be inferred. A trail that silently stops is
        // indistinguishable from an account with no older activity.
        "audit_events_limit": AUDIT_LIMIT,
        "audit_events_truncated": events.len() as i64 == AUDIT_LIMIT,
    })))
}
