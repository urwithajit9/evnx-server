// src/routes/users.rs

use crate::{db::users, errors::AppError, services::jwt::Claims, state::AppState};
use axum::{
    extract::{Path, State},
    Json,
};

/// Return a user's public keys so vault owners can wrap vault keys for them.
///
/// Any authenticated user can look up another user's public keys by email. That
/// is intended: public keys are public, and the lookup is how sharing works. The
/// 404 for an unknown address is deliberate too — a distinct "no such user"
/// would turn this into an account-enumeration oracle.
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
        // ⚠️ May be null for an account that predates F1. A client MUST refuse to
        // share in that case rather than wrapping under X25519 alone — a wrap
        // missing its post-quantum half is one Shor opens, and it stays that way
        // for as long as the row exists.
        "mlkem_public_key": user.mlkem_public_key,
    })))
}

// ─── Public-key backfill ──────────────────────────────────────────────────────

/// Body of `PUT /api/v1/auth/public-keys`.
#[derive(serde::Deserialize, validator::Validate)]
pub struct BackfillPublicKeysRequest {
    #[validate(length(
        equal = 1580,
        message = "mlkem_public_key must be 1580 base64 chars (1184 bytes)"
    ))]
    pub mlkem_public_key: String,
}

/// Upload the caller's ML-KEM public key, for an account that predates F1.
///
/// ─── Why this endpoint exists ────────────────────────────────────────────────
///
/// The ML-KEM keypair is derived from the Ed25519 seed, and the server cannot
/// derive it — only a client holding the master password can, because only that
/// client can unseal the seed. So the server has no way to backfill existing
/// rows itself, and the key has to arrive from a client after a real login.
///
/// Clients should call this on **every** login, not only when they suspect it is
/// missing. It is idempotent when the value matches, so an unconditional call
/// costs one request and removes any need for the client to track state.
///
/// ─── Why it is write-once, and why that is a security property ───────────────
///
/// ⚠️ An endpoint that freely updated a user's public key would be a
/// key-substitution primitive. Anyone holding a session — a stolen access token,
/// a borrowed laptop — could replace the victim's ML-KEM key with their own, and
/// **every vault shared with that account afterwards would be wrapped to the
/// attacker**. The victim would see nothing wrong; their own vaults would keep
/// working, because those are wrapped under their master key.
///
/// There is no legitimate reason to change the key. It is derived
/// deterministically from a seed that never changes — not even across a master
/// password change, which re-seals the seed rather than replacing it. So a
/// second, different value is always either a client bug or an attack, and
/// `409` is the honest answer to both.
///
/// ─── Why a session, not an API token ─────────────────────────────────────────
///
/// Routed behind `require_user_session`. A CI token that could rewrite the
/// account's public key would turn a leaked deploy credential into a way to
/// intercept every future share — which is exactly the escalation that keeps
/// token minting behind a session too.
pub async fn backfill_public_keys(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<Claims>,
    Json(req): Json<BackfillPublicKeysRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    use validator::Validate;
    req.validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let user_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;

    match users::backfill_mlkem_public_key(&state.db, user_id, &req.mlkem_public_key).await? {
        users::PublicKeyBackfill::Stored => Ok(Json(serde_json::json!({
            "status": "stored",
            "message": "ML-KEM public key recorded. This account can now be shared with."
        }))),
        users::PublicKeyBackfill::AlreadyMatches => Ok(Json(serde_json::json!({
            "status": "unchanged",
            "message": "This key is already on file."
        }))),
        users::PublicKeyBackfill::Conflict => Err(AppError::Conflict(
            "A different ML-KEM public key is already recorded for this account. \
             The key is derived from your identity seed and cannot change; if you \
             are seeing this, the client sending it is not the one that registered \
             this account."
                .into(),
        )),
    }
}
