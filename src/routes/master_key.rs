// src/routes/master_key.rs

//! Changing the master password — P4.3, Chain 4.1a.
//!
//! ## What makes this different from every other endpoint
//!
//! The master key is derived from the password, so changing the password
//! re-derives the key and **every vault key wrapped under it has to be re-wrapped
//! in the same breath**. All of that happens on the client; the server performs
//! an atomic swap of opaque blobs.
//!
//! ⚠️ **The server cannot tell a correct rotation from random bytes.** That is
//! what zero knowledge means here, and it is the whole reason this module is
//! written the way it is. An attacker holding a stolen session cannot produce a
//! *valid* rotation — that needs the old password, to unwrap before re-wrapping —
//! but nothing stops them sending garbage. The result would be an account whose
//! owner can no longer log in and whose vaults no longer open, permanently, with
//! no recovery anywhere in the system.
//!
//! So rotation is a **destruction primitive**, not an exfiltration one: the
//! attacker gains nothing and the owner loses everything. Every decision below
//! follows from that sentence.
//!
//! ## Why a fresh password proof, and not a recency check
//!
//! The obvious cheap answer is to allow the rotation when the access token was
//! issued recently, reasoning that SRP proved the password at login. **It does
//! not work in this codebase.** `POST /auth/refresh` re-issues through
//! `issue_token_pair` → `JwtService::issue`, which stamps `iat = now`; a refresh
//! needs only the refresh token, which lives 30 days and sits in the same
//! `0600` file as the access token. A recency check would therefore measure "was
//! the refresh token used recently" — a value the attacker controls — rather than
//! "was the password proven recently". `Claims` carries no `auth_time`, and
//! `issue_token_pair` mints a fresh `session_id` on every refresh, so session age
//! is not a fallback either.
//!
//! The check used instead is a **fresh SRP proof of the current password**, plus
//! TOTP when it is enabled. That is the right shape for one reason worth stating:
//! anyone who can legitimately rotate **already knows the old password**, because
//! the client cannot compute the payload without it. The check demands exactly
//! the secret the operation already requires — free for the real user, decisive
//! against someone holding only a session.
//!
//! TOTP stays because the two defend against different attackers: a proof stops
//! whoever stole a session, and TOTP stops whoever phished the password. Neither
//! subsumes the other.
//!
//! ## What rotation does not touch
//!
//! - **The public keys.** The identity keypair is derived from a seed this
//!   re-seals rather than replaces. `backfill_public_keys` is write-once exactly
//!   because a mutable public key lets a session-holder intercept every future
//!   share; rotation must not become the second route to that.
//! - **Rows where `eph_pub_key IS NOT NULL`** — vault keys shared *to* this
//!   account, wrapped to the keypair, which does not change.
//! - **Vault blobs.** The vault key itself is unchanged; only its wrapping moves.
//!   So this is O(vaults owned), not O(versions) — which is why it fits in one
//!   request and needs none of the staging `routes::rekey` requires.
//! - **Vault keys held by former members.** That is `evnx vault rekey`, a
//!   different operation. No copy may imply otherwise.

use axum::{extract::State, Json};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use srp::groups::G_2048;
use srp::server::SrpServer;
use std::collections::BTreeSet;
use uuid::Uuid;
use validator::Validate;

use crate::{
    db::{rotation, totp as db_totp, users},
    errors::AppError,
    routes::auth::{
        email_subject, fake_salt, fake_srp_verifier, hash_token, verify_totp_code,
        SRP_LOCKOUT_SECONDS, SRP_MAX_FAILURES,
    },
    services::jwt::Claims,
    state::AppState,
};

/// How long a re-authentication stays good for, and how long an SRP challenge
/// lives. Matches `totp_pending`, for the same reason: long enough to finish the
/// operation, short enough that a proof left lying around is not a credential.
const CHALLENGE_TTL_SECONDS: u64 = 300;

/// Failures allowed against the *old* password before the undo path locks.
///
/// Deliberately its own counter rather than `srp_lockout`. They bound different
/// secrets, and sharing one would let an attacker lock the victim out of the
/// recovery path by hammering the login path — or the reverse.
const UNDO_MAX_FAILURES: u64 = 5;
const UNDO_LOCKOUT_SECONDS: u64 = 900;

// ─── The SRP challenge, reused by both flows ──────────────────────────────────

/// Server-side state of an SRP exchange that is **not** a login.
///
/// ⚠️ Stored under its own Valkey prefix, never `srp:`. A challenge issued here
/// is answered against a verifier that may be the account's *previous* one, and
/// a shared prefix would let such a challenge be redeemed at `/auth/srp/verify`
/// — minting a live session from a password that has already been replaced.
#[derive(Serialize, Deserialize)]
struct Challenge {
    user_id: Option<Uuid>,
    email: String,
    verifier_hex: String,
    server_private_b_hex: String,
    client_public_hex: String,
    /// `false` for a fabricated challenge. It is still run through the full
    /// exchange before failing, so an unknown subject costs the same as a known
    /// one — the discipline `srp_init` already applies to unknown addresses.
    is_real: bool,
    /// Which snapshot this challenge would restore. `None` for re-authentication.
    snapshot_id: Option<Uuid>,
}

/// Compute the server's ephemeral pair against a verifier.
fn server_ephemeral(verifier_hex: &str) -> Result<(String, String), AppError> {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    let verifier = hex::decode(verifier_hex)
        .map_err(|_| AppError::Internal("stored verifier is not valid hex".into()))?;
    let srp = SrpServer::<Sha256>::new(&G_2048);
    let big_b = srp.compute_public_ephemeral(&b, &verifier);
    Ok((hex::encode(b), hex::encode(big_b)))
}

/// Check the client's proof. Returns the server's proof (M2) on success.
///
/// A fabricated challenge runs `process_reply` before failing so that the work
/// done — and therefore the time taken — does not say whether the subject exists.
fn answer(ch: &Challenge, client_proof_hex: &str) -> Result<String, AppError> {
    let b = hex::decode(&ch.server_private_b_hex).map_err(|_| AppError::Unauthorized)?;
    let v = hex::decode(&ch.verifier_hex).map_err(|_| AppError::Unauthorized)?;
    let a = hex::decode(&ch.client_public_hex).map_err(|_| AppError::Unauthorized)?;
    let srp = SrpServer::<Sha256>::new(&G_2048);

    if !ch.is_real {
        let _ = srp.process_reply(&b, &v, &a);
        return Err(AppError::Unauthorized);
    }

    let verifier = srp
        .process_reply(&b, &v, &a)
        .map_err(|_| AppError::Unauthorized)?;
    let proof = hex::decode(client_proof_hex).map_err(|_| AppError::Unauthorized)?;
    verifier
        .verify_client(&proof)
        .map_err(|_| AppError::Unauthorized)?;
    Ok(hex::encode(verifier.proof()))
}

#[derive(Serialize)]
pub struct ChallengeResponse {
    pub session_id: Uuid,
    pub srp_salt: String,
    pub argon2_salt: String,
    pub server_public: String,
}

// ─── Re-authentication ────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ReauthInitRequest {
    /// Client ephemeral public A, hex.
    pub client_public: String,
}

/// Begin proving the **current** password again, inside a live session.
///
/// No email is accepted or returned: the address comes from the session, so
/// unlike `/auth/srp/init` there is no enumeration surface here to defend and no
/// fabrication needed.
pub async fn reauth_init(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<Claims>,
    Json(req): Json<ReauthInitRequest>,
) -> Result<Json<ChallengeResponse>, AppError> {
    let user_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;

    hex::decode(&req.client_public)
        .map_err(|_| AppError::Validation("client_public is not valid hex".into()))?;

    let rate_key = format!("rate:reauth_init:{user_id}");
    if !state.cache.check_rate_limit(&rate_key, 10, 900).await? {
        return Err(AppError::RateLimited {
            retry_after_seconds: 900,
        });
    }

    let user = users::find_by_id(&state.db, user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let (b_hex, big_b_hex) = server_ephemeral(&user.srp_verifier)?;
    let session_id = Uuid::new_v4();

    state
        .cache
        .set_json(
            &format!("reauth_srp:{session_id}"),
            &Challenge {
                user_id: Some(user_id),
                email: user.email.clone(),
                verifier_hex: user.srp_verifier,
                server_private_b_hex: b_hex,
                client_public_hex: req.client_public,
                is_real: true,
                snapshot_id: None,
            },
            CHALLENGE_TTL_SECONDS,
        )
        .await?;

    Ok(Json(ChallengeResponse {
        session_id,
        srp_salt: user.srp_salt,
        argon2_salt: user.argon2_salt,
        server_public: big_b_hex,
    }))
}

#[derive(Deserialize)]
pub struct ReauthVerifyRequest {
    pub session_id: Uuid,
    /// Client proof M1, hex.
    pub client_proof: String,
    /// Required when the account has TOTP enabled. A backup code is accepted.
    #[serde(default)]
    pub totp_code: Option<String>,
}

#[derive(Serialize)]
pub struct ReauthVerifyResponse {
    pub server_proof: String,
    pub expires_in_seconds: u64,
}

/// Finish proving the current password, and arm the rotation.
///
/// On success writes `reauth:{session_id-of-the-JWT}`, which
/// `rotate_master_key` requires. Bound to the **caller's session**, so a proof
/// made on your laptop cannot authorise a rotation from a session someone else
/// is holding.
pub async fn reauth_verify(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<Claims>,
    Json(req): Json<ReauthVerifyRequest>,
) -> Result<Json<ReauthVerifyResponse>, AppError> {
    let user_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;
    let sid = claims.session_id().map_err(|_| AppError::Unauthorized)?;

    let key = format!("reauth_srp:{}", req.session_id);
    let ch: Challenge = state
        .cache
        .get_json(&key)
        .await?
        .ok_or(AppError::Unauthorized)?;

    // A challenge belongs to the session that asked for it.
    if ch.user_id != Some(user_id) {
        return Err(AppError::Unauthorized);
    }

    // ⚠️ **Shares `srp_lockout` with the login path, and must.** This endpoint
    // answers against the same verifier `/auth/srp/verify` does, so a separate
    // counter — or none — would hand anyone holding a session an unmetered
    // password-guessing oracle, bypassing the bound login is under. D12 was this
    // same mistake one layer up.
    let lockout_key = format!("srp_lockout:{}", email_subject(&ch.email));
    let failures: u64 = state
        .cache
        .get_json::<u64>(&lockout_key)
        .await?
        .unwrap_or(0);
    if failures >= SRP_MAX_FAILURES {
        return Err(AppError::AccountLocked);
    }

    let server_proof = match answer(&ch, &req.client_proof) {
        Ok(p) => p,
        Err(e) => {
            state
                .cache
                .incr_with_ttl(&lockout_key, SRP_LOCKOUT_SECONDS)
                .await?;
            tracing::warn!(%user_id, "re-authentication failed");
            return Err(e);
        }
    };

    // ── Second factor ───────────────────────────────────────────────────────
    let user = users::find_by_id(&state.db, user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    if user.totp_enabled {
        // ⚠️ Bounded by the same `totp_lockout` the login path uses. Without a
        // counter, six digits is a million guesses and a session-holder has all
        // the time they want.
        let totp_lock = format!("totp_lockout:{user_id}");
        let totp_failures: u64 = state.cache.get_json::<u64>(&totp_lock).await?.unwrap_or(0);
        if totp_failures >= 3 {
            return Err(AppError::AccountLocked);
        }

        let code = req.totp_code.as_deref().unwrap_or_default();
        let secret = user
            .totp_secret_enc
            .clone()
            .ok_or_else(|| AppError::Internal("TOTP enabled but no secret".into()))?;
        let ok = verify_totp_code(&secret, code).is_ok()
            || db_totp::redeem(&state.db, user_id, &hash_token(code)).await?;
        if !ok {
            state.cache.incr_with_ttl(&totp_lock, 900).await?;
            return Err(AppError::Unauthorized);
        }
        state.cache.del(&totp_lock).await?;
    }

    // Spent, and the counter cleared — a correct proof should not leave the user
    // carrying failures toward a lockout they did not earn.
    state.cache.del(&key).await?;
    state.cache.del(&lockout_key).await?;

    state
        .cache
        .set_flag(&format!("reauth:{sid}"), CHALLENGE_TTL_SECONDS)
        .await?;

    Ok(Json(ReauthVerifyResponse {
        server_proof,
        expires_in_seconds: CHALLENGE_TTL_SECONDS,
    }))
}

// ─── The rotation ─────────────────────────────────────────────────────────────

#[derive(Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct VaultWrap {
    pub vault_id: Uuid,
    pub encrypted_vault_key: String,
}

/// Why the password is being changed. It decides whether an undo is kept.
#[derive(Deserialize, Default, PartialEq, Eq, Clone, Copy, Debug)]
#[serde(rename_all = "snake_case")]
pub enum RotationReason {
    /// Keep the undo window. The default, because the common case is routine and
    /// the common disaster is lockout.
    #[default]
    Routine,
    /// Store no snapshot. The old password is believed to be in someone else's
    /// hands, and an undo authorised by that password would hand the account
    /// straight back.
    Compromised,
}

#[derive(Deserialize, Validate)]
pub struct RotateRequest {
    #[validate(length(min = 16, max = 256))]
    pub srp_salt: String,
    /// Hex, and **checked here**: a verifier that is not valid hex parses fine as
    /// JSON and then fails at `/auth/srp/init` with a 500, locking the account out
    /// through the one door this endpoint exists to keep open.
    #[validate(length(min = 16, max = 1024))]
    pub srp_verifier: String,
    #[validate(length(min = 16, max = 256))]
    pub argon2_salt: String,
    #[validate(length(min = 16, max = 8192))]
    pub encrypted_private_key: String,
    pub vault_wraps: Vec<VaultWrap>,
    #[serde(default)]
    pub reason: RotationReason,
}

#[derive(Serialize)]
pub struct RotateResponse {
    pub status: &'static str,
    pub vaults_rewrapped: usize,
    pub sessions_revoked: usize,
    /// `null` when no undo was kept — see `RotationReason::Compromised` and the
    /// `MASTER_KEY_UNDO_WINDOW_HOURS` setting.
    pub undo_available_until: Option<chrono::DateTime<chrono::Utc>>,
}

/// Replace the master password, and every wrap that depends on it.
pub async fn rotate_master_key(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<Claims>,
    Json(req): Json<RotateRequest>,
) -> Result<Json<RotateResponse>, AppError> {
    req.validate()
        .map_err(|e| AppError::Validation(format!("{e}")))?;

    let user_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;
    let sid = claims.session_id().map_err(|_| AppError::Unauthorized)?;

    hex::decode(&req.srp_verifier)
        .map_err(|_| AppError::Validation("srp_verifier is not valid hex".into()))?;

    // ── Was the current password proven ─────────────────────────────────────
    //
    // Checked without consuming, so that a request rejected below — a bad payload,
    // a missing wrap — can be corrected and retried inside the same window rather
    // than sending the user back through the whole proof for a typo. The flag is
    // spent only once a rotation has actually happened.
    let reauth_key = format!("reauth:{sid}");
    if !state.cache.exists(&reauth_key).await? {
        return Err(AppError::Forbidden);
    }

    let mut tx = state.db.begin().await.map_err(AppError::Database)?;

    let current = rotation::lock_account(&mut *tx, user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    // ── Already done? ───────────────────────────────────────────────────────
    //
    // A connection dropped after the commit leaves the client believing it failed
    // while the new password is live. Answering the retry rather than re-running
    // it is what makes that recoverable instead of merely confusing.
    if current.srp_verifier == req.srp_verifier {
        tx.rollback().await.map_err(AppError::Database)?;
        return Ok(Json(RotateResponse {
            status: "already_applied",
            vaults_rewrapped: 0,
            sessions_revoked: 0,
            undo_available_until: None,
        }));
    }

    // ── Every wrap, or none ─────────────────────────────────────────────────
    //
    // ⚠️ The rows are locked by `own_wraps_for_update`, and that is what makes
    // this check mean anything: without the lock a vault created between here and
    // the writes would keep a wrap under the old password, and a vault whose key
    // is under a password nobody has any more is simply gone.
    let existing = rotation::own_wraps_for_update(&mut *tx, user_id).await?;
    let have: BTreeSet<Uuid> = existing.iter().map(|w| w.vault_id).collect();
    let given: BTreeSet<Uuid> = req.vault_wraps.iter().map(|w| w.vault_id).collect();

    if given.len() != req.vault_wraps.len() {
        return Err(AppError::Validation(
            "vault_wraps contains the same vault twice.".into(),
        ));
    }
    if have != given {
        let missing: Vec<String> = have.difference(&given).map(|v| v.to_string()).collect();
        let extra: Vec<String> = given.difference(&have).map(|v| v.to_string()).collect();
        let mut why = String::from(
            "the rotation must re-wrap every vault key this account holds under its own \
             master key, in one request. Nothing has been changed.",
        );
        if !missing.is_empty() {
            why.push_str(&format!(" Missing: {}.", missing.join(", ")));
        }
        if !extra.is_empty() {
            why.push_str(&format!(
                " Not held under this account's master key: {}.",
                extra.join(", ")
            ));
        }
        return Err(AppError::Conflict(why));
    }

    // ── Keep a way back ─────────────────────────────────────────────────────
    let window = state.config.master_key_undo_window_hours;
    let keep_undo = req.reason == RotationReason::Routine && window > 0;
    let mut undo_until = None;

    if keep_undo {
        rotation::expire_stale_snapshots(&mut *tx, user_id).await?;
        // `false` means a window was already open. Not an error: the older
        // snapshot is the more valuable one — see `db::rotation::store_snapshot`.
        if rotation::store_snapshot(&mut *tx, user_id, &current, &existing, window).await? {
            undo_until = Some(chrono::Utc::now() + chrono::Duration::hours(window));
        }
    }

    // ── The swap ────────────────────────────────────────────────────────────
    if !rotation::apply_new_material(
        &mut *tx,
        user_id,
        &req.srp_salt,
        &req.srp_verifier,
        &req.argon2_salt,
        &req.encrypted_private_key,
    )
    .await?
    {
        return Err(AppError::Internal("the account row did not update".into()));
    }

    for w in &req.vault_wraps {
        if !rotation::set_own_wrap(&mut *tx, user_id, w.vault_id, &w.encrypted_vault_key).await? {
            // Unreachable while the lock holds — and if it ever is reached, the
            // transaction must die rather than leave one vault behind.
            return Err(AppError::Internal(format!(
                "vault {} could not be re-wrapped; nothing has been changed",
                w.vault_id
            )));
        }
    }

    tx.commit().await.map_err(AppError::Database)?;

    // ── After the commit ────────────────────────────────────────────────────
    //
    // Spent only now. Everything above can fail and be retried; this cannot.
    state.cache.take_flag(&reauth_key).await?;

    // Other sessions authenticated under the old password and hold material that
    // no longer opens anything. Signing them out is the point, not a side effect.
    let revoked = revoke_sessions(&state, user_id, Some(sid)).await?;

    if let Err(e) = crate::services::audit::record(
        &state.db,
        crate::services::audit::AuditEvent {
            vault_id: None,
            user_id: Some(user_id),
            event_type: "master_key_rotated".into(),
            ip_hash: None,
            user_agent_hash: None,
            // Counts and policy only. No salts, no verifier, no wrap.
            metadata: Some(serde_json::json!({
                "vaults_rewrapped":  req.vault_wraps.len(),
                "sessions_revoked":  revoked,
                "undo_window_hours": if keep_undo { Some(window) } else { None },
            })),
        },
    )
    .await
    {
        tracing::warn!(error = %e, "could not record a master-key rotation");
    }

    notify(&state, &current.email, MailKind::Rotated, undo_until);

    tracing::info!(
        %user_id,
        vaults = req.vault_wraps.len(),
        undo = keep_undo,
        "master key rotated"
    );

    Ok(Json(RotateResponse {
        status: "rotated",
        vaults_rewrapped: req.vault_wraps.len(),
        sessions_revoked: revoked,
        undo_available_until: undo_until,
    }))
}

// ─── Undo ─────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct UndoInitRequest {
    pub email: String,
    /// Client ephemeral public A, hex.
    pub client_public: String,
}

/// Begin restoring the material a rotation replaced.
///
/// ⚠️ **Unauthenticated, and it has to be.** The person who needs this is by
/// definition the person who can no longer log in — a session is exactly what
/// they do not have. So the only credential it can ask for is the one thing the
/// attacker lacks: the **old** password.
///
/// It answers identically whether the address is unknown, known with no snapshot,
/// or known with one, by fabricating a challenge in the first two cases and
/// running it through the same exchange. Otherwise this would report which
/// accounts exist and which have rotated recently — undoing what `/auth/srp/init`
/// goes to some trouble to prevent.
pub async fn undo_init(
    State(state): State<AppState>,
    Json(req): Json<UndoInitRequest>,
) -> Result<Json<ChallengeResponse>, AppError> {
    hex::decode(&req.client_public)
        .map_err(|_| AppError::Validation("client_public is not valid hex".into()))?;

    let subject = email_subject(&req.email);
    let rate_key = format!("rate:undo_init:{subject}");
    if !state.cache.check_rate_limit(&rate_key, 5, 900).await? {
        return Err(AppError::RateLimited {
            retry_after_seconds: 900,
        });
    }

    let email_lower = req.email.trim().to_lowercase();
    let snapshot = rotation::live_snapshot_for_email(&state.db, &email_lower).await?;

    let (user_id, snapshot_id, verifier, srp_salt, argon2_salt, is_real) = match snapshot {
        Some(s) => (
            Some(s.user_id),
            Some(s.id),
            s.prev_srp_verifier,
            s.prev_srp_salt,
            s.prev_argon2_salt,
            true,
        ),
        None => (
            None,
            None,
            fake_srp_verifier(),
            fake_salt(),
            fake_salt(),
            false,
        ),
    };

    let (b_hex, big_b_hex) = server_ephemeral(&verifier)?;
    let session_id = Uuid::new_v4();

    state
        .cache
        .set_json(
            &format!("undo_srp:{session_id}"),
            &Challenge {
                user_id,
                email: email_lower,
                verifier_hex: verifier,
                server_private_b_hex: b_hex,
                client_public_hex: req.client_public,
                is_real,
                snapshot_id,
            },
            CHALLENGE_TTL_SECONDS,
        )
        .await?;

    Ok(Json(ChallengeResponse {
        session_id,
        srp_salt,
        argon2_salt,
        server_public: big_b_hex,
    }))
}

#[derive(Deserialize)]
pub struct UndoVerifyRequest {
    pub session_id: Uuid,
    pub client_proof: String,
}

#[derive(Serialize)]
pub struct UndoResponse {
    pub server_proof: String,
    pub vaults_restored: usize,
    /// Vaults the account holds now that the snapshot does not describe —
    /// created after the rotation, so their keys are wrapped under the password
    /// being undone. Named rather than silently left: they will not open.
    pub vaults_not_in_snapshot: Vec<Uuid>,
    pub sessions_revoked: usize,
}

/// Prove the old password and put it back.
pub async fn undo_verify(
    State(state): State<AppState>,
    Json(req): Json<UndoVerifyRequest>,
) -> Result<Json<UndoResponse>, AppError> {
    let key = format!("undo_srp:{}", req.session_id);
    let ch: Challenge = state
        .cache
        .get_json(&key)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let lockout_key = format!("undo_lockout:{}", email_subject(&ch.email));
    let failures: u64 = state
        .cache
        .get_json::<u64>(&lockout_key)
        .await?
        .unwrap_or(0);
    if failures >= UNDO_MAX_FAILURES {
        return Err(AppError::AccountLocked);
    }

    let server_proof = match answer(&ch, &req.client_proof) {
        Ok(p) => p,
        Err(e) => {
            state
                .cache
                .incr_with_ttl(&lockout_key, UNDO_LOCKOUT_SECONDS)
                .await?;
            return Err(e);
        }
    };

    let (user_id, snapshot_id) = match (ch.user_id, ch.snapshot_id) {
        (Some(u), Some(s)) => (u, s),
        // `is_real` was true, so `answer` succeeded — which cannot happen without
        // a snapshot. Refuse rather than reason about it.
        _ => return Err(AppError::Unauthorized),
    };

    // Re-read under lock: the window may have closed, or been restored already,
    // between the challenge and the proof.
    let snapshot = rotation::live_snapshot_for_email(&state.db, &ch.email)
        .await?
        .filter(|s| s.id == snapshot_id)
        .ok_or(AppError::NotFound)?;

    let mut tx = state.db.begin().await.map_err(AppError::Database)?;

    let held = rotation::own_wraps_for_update(&mut *tx, user_id).await?;
    let in_snapshot: BTreeSet<Uuid> = snapshot.prev_wraps.iter().map(|w| w.vault_id).collect();
    let orphans: Vec<Uuid> = held
        .iter()
        .map(|w| w.vault_id)
        .filter(|v| !in_snapshot.contains(v))
        .collect();

    // ⚠️ Permissive where the rotation is strict, and on purpose. A vault created
    // after the rotation is wrapped under the password being undone, so it cannot
    // be restored — but refusing the whole undo for it would let an attacker who
    // rotated the account block the recovery simply by creating a vault. The
    // account comes back; the un-restorable vaults are named in the response.
    let mut restored = 0usize;
    for w in &snapshot.prev_wraps {
        if rotation::set_own_wrap(&mut *tx, user_id, w.vault_id, &w.encrypted_vault_key).await? {
            restored += 1;
        }
    }

    if !rotation::apply_new_material(
        &mut *tx,
        user_id,
        &snapshot.prev_srp_salt,
        &snapshot.prev_srp_verifier,
        &snapshot.prev_argon2_salt,
        &snapshot.prev_encrypted_private_key,
    )
    .await?
    {
        return Err(AppError::Internal("the account row did not update".into()));
    }

    if !rotation::consume(&mut *tx, snapshot.id, "restored").await? {
        // Someone else restored it between the read and here. Their transaction
        // did the same work; this one must not double-apply.
        return Err(AppError::Conflict(
            "this rotation has already been undone.".into(),
        ));
    }

    tx.commit().await.map_err(AppError::Database)?;

    state.cache.del(&key).await?;
    state.cache.del(&lockout_key).await?;

    // Every session, including any the person who rotated is still holding.
    let revoked = revoke_sessions(&state, user_id, None).await?;

    if let Err(e) = crate::services::audit::record(
        &state.db,
        crate::services::audit::AuditEvent {
            vault_id: None,
            user_id: Some(user_id),
            event_type: "master_key_restored".into(),
            ip_hash: None,
            user_agent_hash: None,
            metadata: Some(serde_json::json!({
                "vaults_restored":       restored,
                "vaults_not_in_snapshot": orphans.len(),
                "sessions_revoked":      revoked,
            })),
        },
    )
    .await
    {
        tracing::warn!(error = %e, "could not record a master-key restore");
    }

    notify(&state, &ch.email, MailKind::Restored, None);

    tracing::info!(%user_id, restored, "master key restored from snapshot");

    Ok(Json(UndoResponse {
        server_proof,
        vaults_restored: restored,
        vaults_not_in_snapshot: orphans,
        sessions_revoked: revoked,
    }))
}

// ─── Shared tail ──────────────────────────────────────────────────────────────

/// Revoke this account's sessions, optionally sparing one.
///
/// Revokes the refresh tokens **and** blocklists the session id, so the access
/// token dies now rather than lingering for its remaining minutes — the same
/// discipline `sessions::revoke_other_sessions` applies.
async fn revoke_sessions(
    state: &AppState,
    user_id: Uuid,
    except: Option<Uuid>,
) -> Result<usize, AppError> {
    let victims = sqlx::query!(
        r#"
        UPDATE refresh_tokens
           SET revoked_at = NOW()
         WHERE user_id = $1
           AND revoked_at IS NULL
           AND ($2::uuid IS NULL OR session_id <> $2)
        RETURNING session_id
        "#,
        user_id,
        except,
    )
    .fetch_all(&state.db)
    .await
    .map_err(AppError::Database)?;

    let ttl = (state.config.jwt_expiry_minutes.max(1) * 60) as u64;
    let mut ids: Vec<Uuid> = victims.into_iter().map(|r| r.session_id).collect();
    ids.sort_unstable();
    ids.dedup();

    for sid in &ids {
        state
            .cache
            .set_flag(&format!("jwt_blocklist:{sid}"), ttl)
            .await?;
    }
    Ok(ids.len())
}

enum MailKind {
    Rotated,
    Restored,
}

/// Tell the account holder, always.
///
/// ⚠️ Spawned, never awaited — the same discipline as the login alert. A mail
/// outage must not fail a rotation that has already committed, and the user would
/// then believe it failed while their password had in fact changed.
fn notify(
    state: &AppState,
    email: &str,
    kind: MailKind,
    undo_until: Option<chrono::DateTime<chrono::Utc>>,
) {
    let mail = state.email.clone();
    let to = email.to_string();
    let when = chrono::Utc::now();
    tokio::spawn(async move {
        let sent = match kind {
            MailKind::Rotated => mail.send_master_key_rotated(&to, when, undo_until).await,
            MailKind::Restored => mail.send_master_key_restored(&to, when).await,
        };
        if let Err(e) = sent {
            tracing::warn!("could not send the master-key alert: {e}");
        }
    });
}
