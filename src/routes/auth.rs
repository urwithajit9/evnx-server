// src/routes/auth.rs

use axum::{extract::State, Json};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

use sha2::Sha256;
use srp::groups::G_2048;
use srp::server::SrpServer;

use crate::{
    db::{tokens as db_tokens, users},
    errors::AppError,
    state::AppState,
};

use crate::services::jwt::JwtService;

use totp_rs::{Algorithm as TotpAlgorithm, Secret, TOTP};

use crate::services::jwt::Claims;

// ─── Request / Response Types ──────────────────────────────────────────────────

#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(email(message = "Invalid email format"))]
    #[validate(length(max = 254, message = "Email too long"))]
    pub email: String,

    // SRP verifier: large hex number from client-side SRP computation
    #[validate(length(min = 256, max = 1024, message = "Invalid srp_verifier length"))]
    pub srp_verifier: String,

    // Base64-encoded 32-byte salts
    #[validate(length(equal = 44, message = "srp_salt must be 44 base64 chars (32 bytes)"))]
    pub srp_salt: String,

    #[validate(length(equal = 44, message = "argon2_salt must be 44 base64 chars (32 bytes)"))]
    pub argon2_salt: String,

    // Ed25519 public key: 44 base64 chars = 32 bytes
    #[validate(length(equal = 44, message = "ed25519_public_key must be 44 base64 chars"))]
    pub ed25519_public_key: String,

    #[validate(length(equal = 44, message = "x25519_public_key must be 44 base64 chars"))]
    pub x25519_public_key: String,

    // Encrypted private key: nonce (24 bytes) + ciphertext (~32) + tag (16) + base64 overhead
    #[validate(length(min = 60, max = 300, message = "encrypted_private_key invalid length"))]
    pub encrypted_private_key: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub user_id: Uuid,
    pub message: String,
}

// ─── Registration Handler ──────────────────────────────────────────────────────

pub async fn register(
    State(state): State<AppState>,
    Json(mut req): Json<RegisterRequest>,
) -> Result<(axum::http::StatusCode, Json<RegisterResponse>), AppError> {
    // 1. Validate input fields
    req.validate().map_err(|e| {
        // Format all validation errors into a single readable string
        let messages: Vec<String> = e
            .field_errors()
            .iter()
            .flat_map(|(field, errs)| {
                errs.iter().map(move |err| {
                    format!("{}: {}", field, err.message.as_deref().unwrap_or("invalid"))
                })
            })
            .collect();
        AppError::Validation(messages.join("; "))
    })?;

    // 2. Normalize email (lowercase, trim whitespace)
    req.email = req.email.trim().to_lowercase();

    // 3. Check email uniqueness
    if users::exists_by_email(&state.db, &req.email).await? {
        return Err(AppError::Conflict("Email already registered".into()));
    }

    // 4. Generate user ID
    let user_id = Uuid::new_v4();

    // 5. Insert user (SRP verifier, encrypted key material, salts — no password)
    users::create(
        &state.db,
        users::CreateUser {
            id: user_id,
            email: req.email.clone(),
            srp_verifier: req.srp_verifier,
            srp_salt: req.srp_salt,
            argon2_salt: req.argon2_salt,
            ed25519_public_key: req.ed25519_public_key,
            x25519_public_key: req.x25519_public_key,
            encrypted_private_key: req.encrypted_private_key,
        },
    )
    .await
    .map_err(|e| {
        // Handle unique constraint violation (race condition — email checked above)
        if let sqlx::Error::Database(ref db_err) = e {
            if db_err.constraint() == Some("users_email_key") {
                return AppError::Conflict("Email already registered".into());
            }
        }
        AppError::Database(e)
    })?;

    // 6. Generate email verification token
    let raw_token = generate_secure_token();
    let token_hash = hash_token(&raw_token);

    db_tokens::create_email_verification(&state.db, user_id, &token_hash).await?;

    // 7. Send verification email (async — don't block the response)
    // Week 7 adds the email service. For now, log the token for testing.
    tracing::info!(
        user_id = %user_id,
        "Email verification token (dev only, remove in prod): {}",
        raw_token
    );

    // TODO Week 7: state.email.send_verification(&req.email, &raw_token).await?;

    Ok((
        axum::http::StatusCode::CREATED,
        Json(RegisterResponse {
            user_id,
            message: "Registration successful. Check your email to verify your account.".into(),
        }),
    ))
}

// ─── SRP Init Handler ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SrpInitRequest {
    pub email: String,
    pub client_public: String, // A: hex-encoded client ephemeral public key
}

#[derive(Serialize)]
pub struct SrpInitResponse {
    pub session_id: Uuid,
    pub srp_salt: String,
    pub argon2_salt: String,
    pub server_public: String, // B: hex-encoded server ephemeral public key
}

/// SRP Step 1 — exchange ephemeral public keys.
///
/// SECURITY CRITICAL: This endpoint must respond identically (same shape, similar timing)
/// for known and unknown email addresses. A timing or shape difference reveals user existence.
pub async fn srp_init(
    State(state): State<AppState>,
    Json(req): Json<SrpInitRequest>,
) -> Result<Json<SrpInitResponse>, AppError> {
    // Rate limiting (unchanged)
    let rate_key = format!(
        "rate:srp_init:{}",
        blake3::hash(req.email.as_bytes()).to_hex()
    );
    let allowed = state.cache.check_rate_limit(&rate_key, 5, 900).await?;
    if !allowed {
        return Err(AppError::RateLimited {
            retry_after_seconds: 900,
        });
    }

    // Lookup user — constant-time response for unknown emails
    let email_lower = req.email.trim().to_lowercase();
    let srp_data = users::find_srp_data(&state.db, &email_lower).await?;

    let (user_id, srp_verifier_hex, srp_salt_b64, argon2_salt_b64, is_real_user) = match srp_data {
        Some(data) => (
            Some(data.id),
            data.srp_verifier,
            data.srp_salt,
            data.argon2_salt,
            true,
        ),
        None => (None, fake_srp_verifier(), fake_salt(), fake_salt(), false),
    };

    // Decode client public A (hex → bytes)
    let _client_public_bytes = hex::decode(&req.client_public)
        .map_err(|_| AppError::Validation("client_public is not valid hex".into()))?;

    // Generate server ephemeral private key b (32 bytes = 256 bits minimum per RFC5054)
    let mut b_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b_bytes);

    // Decode verifier from hex (stored in DB) to bytes
    let verifier_bytes = hex::decode(&srp_verifier_hex)
        .map_err(|_| AppError::Internal("Invalid verifier format".into()))?;

    // Create SRP server and compute public ephemeral B
    // Note: compute_public_ephemeral takes &[u8] for both b and v, returns Vec<u8> for B
    let srp_server = SrpServer::<Sha256>::new(&G_2048);
    let server_public_bytes = srp_server.compute_public_ephemeral(&b_bytes, &verifier_bytes);
    let server_public_hex = hex::encode(&server_public_bytes);

    // Store session state in Redis (5-min TTL)
    let session_id = Uuid::new_v4();
    let srp_state = SrpSessionState {
        user_id,
        email: email_lower,
        verifier_hex: srp_verifier_hex,
        srp_salt: srp_salt_b64.clone(),
        server_private_b_hex: hex::encode(&b_bytes), // Store b for later verification
        client_public_hex: req.client_public,
        is_real_user,
    };

    state
        .cache
        .set_json(&format!("srp:{}", session_id), &srp_state, 300)
        .await?;

    Ok(Json(SrpInitResponse {
        session_id,
        srp_salt: srp_salt_b64,
        argon2_salt: argon2_salt_b64,
        server_public: server_public_hex,
    }))
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SrpSessionState {
    user_id: Option<Uuid>,
    email: String,
    verifier_hex: String,         // Verifier v (hex)
    srp_salt: String,             // SRP salt (base64)
    server_private_b_hex: String, // Server ephemeral private b (hex) — needed for process_reply
    client_public_hex: String,    // Client ephemeral public A (hex)
    is_real_user: bool,           // Track if this is a real user (for constant-time logic)
}

// ─── SRP Verify Handler ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SrpVerifyRequest {
    pub session_id: Uuid,
    pub client_proof: String, // M1: hex-encoded
}

#[derive(Serialize)]
pub struct SrpVerifyResponse {
    pub server_proof: String, // M2: hex-encoded
    pub requires_totp: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp_pending_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

/// SRP Step 2 — verify client proof M1, issue tokens.
///
/// On success: if TOTP disabled → issue JWT. If TOTP enabled → issue totp_pending JWT.
/// On failure: generic error (never reveal whether email/password is wrong vs session expired).
pub async fn srp_verify(
    State(state): State<AppState>,
    Json(req): Json<SrpVerifyRequest>,
) -> Result<Json<SrpVerifyResponse>, AppError> {
    // Fetch session from Redis
    let session_key = format!("srp:{}", req.session_id);
    let srp_state: Option<SrpSessionState> = state.cache.get_json(&session_key).await?;
    let srp_state = srp_state.ok_or(AppError::Unauthorized)?;

    // Decode stored values to bytes
    let b_bytes =
        hex::decode(&srp_state.server_private_b_hex).map_err(|_| AppError::Unauthorized)?;
    let verifier_bytes =
        hex::decode(&srp_state.verifier_hex).map_err(|_| AppError::Unauthorized)?;
    let client_public_bytes =
        hex::decode(&srp_state.client_public_hex).map_err(|_| AppError::Unauthorized)?;

    let srp_server = SrpServer::<Sha256>::new(&G_2048);

    // Constant-time: always run crypto even for fake users
    if !srp_state.is_real_user {
        // Dummy computation to match timing, then fail immediately
        let _ = srp_server.process_reply(&b_bytes, &verifier_bytes, &client_public_bytes);
        return Err(AppError::Unauthorized);
    }

    // Real user: process the reply normally
    let server_verifier = srp_server
        .process_reply(&b_bytes, &verifier_bytes, &client_public_bytes)
        .map_err(|_| AppError::Unauthorized)?;

    // Verify client proof M1
    let client_proof_bytes = hex::decode(&req.client_proof).map_err(|_| AppError::Unauthorized)?;

    server_verifier
        .verify_client(&client_proof_bytes)
        .map_err(|_| {
            tracing::warn!(user_id = ?srp_state.user_id, "SRP verification failed");
            AppError::Unauthorized
        })?;

    // Get server proof M2 (hex-encoded for JSON)
    let server_proof_bytes = server_verifier.proof();
    let server_proof_hex = hex::encode(&server_proof_bytes);

    // Optional: extract shared key for encryption if needed
    // let shared_key = server_verifier.key(); // Use HKDF to derive keys from this

    // Delete session (single-use)
    state.cache.del(&session_key).await?;

    // Must have real user at this point
    let user_id = srp_state.user_id.ok_or(AppError::Unauthorized)?;

    // Update last login timestamp
    users::update_last_login(&state.db, user_id).await?;

    // Check if TOTP is required
    let user = users::find_by_id(&state.db, user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    if user.totp_enabled {
        // Issue short-lived TOTP-pending token (Week 5)
        return Ok(Json(SrpVerifyResponse {
            server_proof: server_proof_hex,
            requires_totp: true,
            totp_pending_token: Some("todo_week5".into()),
            access_token: None,
            refresh_token: None,
        }));
    }

    // Issue JWT access + refresh token pair
    let (access_token, refresh_token) =
        issue_token_pair(&state, user_id, user.email_verified).await?;

    Ok(Json(SrpVerifyResponse {
        server_proof: server_proof_hex,
        requires_totp: false,
        totp_pending_token: None,
        access_token: Some(access_token),
        refresh_token: Some(refresh_token),
    }))
}

// ─── Email Verification Handler ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct VerifyEmailRequest {
    pub token: String,
}

// src/routes/auth.rs — verify_email (corrected)

pub async fn verify_email(
    State(state): State<AppState>,
    Json(req): Json<VerifyEmailRequest>,
) -> Result<axum::http::StatusCode, AppError> {
    let token_hash = hash_token(&req.token);

    // Use a transaction: both operations succeed or both fail
    let mut tx = state.db.begin().await.map_err(AppError::Database)?;

    let row = sqlx::query!(
        r#"
        SELECT user_id FROM email_verifications
        WHERE token_hash = $1
          AND used_at IS NULL
          AND expires_at > NOW()
        "#,
        token_hash,
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::Database)?;

    let user_id = row.map(|r| r.user_id).ok_or(AppError::NotFound)?;

    sqlx::query!(
        "UPDATE email_verifications SET used_at = NOW() WHERE token_hash = $1",
        token_hash
    )
    .execute(&mut *tx)
    .await
    .map_err(AppError::Database)?;

    sqlx::query!(
        "UPDATE users SET email_verified = true, updated_at = NOW() WHERE id = $1",
        user_id
    )
    .execute(&mut *tx)
    .await
    .map_err(AppError::Database)?;

    tx.commit().await.map_err(AppError::Database)?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

/// Generate a 32-byte cryptographically random token, hex-encoded.
fn generate_secure_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Hash a token for storage. We store hashes, not raw tokens.
fn hash_token(token: &str) -> String {
    blake3::hash(token.as_bytes()).to_hex().to_string()
}

/// Generate a fake SRP verifier (same length as real) for unknown emails.
fn fake_srp_verifier() -> String {
    use rand::RngCore;
    let mut bytes = vec![0u8; 256];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Generate a fake base64 salt for unknown emails.
fn fake_salt() -> String {
    use base64ct::{Base64, Encoding};
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    Base64::encode_string(&bytes)
}

/// Issue a JWT + refresh token pair for a successfully authenticated user.
/// Returns (access_token_jwt, raw_refresh_token).
/// The raw refresh token is returned ONCE — store BLAKE3 hash in DB.
async fn issue_token_pair(
    state: &AppState,
    user_id: Uuid,
    email_verified: bool,
) -> Result<(String, String), AppError> {
    let session_id = Uuid::new_v4();

    // Issue JWT access token
    let access_token = state
        .jwt
        .issue(user_id, session_id, email_verified)
        .map_err(|e| AppError::Internal(format!("JWT issue failed: {e}")))?;

    // Generate random 32-byte refresh token
    let mut raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let raw_refresh = hex::encode(raw);
    let refresh_hash = blake3::hash(raw_refresh.as_bytes()).to_hex().to_string();

    // Store hashed refresh token in DB
    db_tokens::create_refresh_token(
        &state.db,
        user_id,
        session_id,
        &refresh_hash,
        state.config.refresh_token_expiry_days,
    )
    .await?;

    Ok((access_token, raw_refresh))
}

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Serialize)]
pub struct RefreshResponse {
    pub access_token: String,
    pub refresh_token: String,
}

pub async fn refresh(
    State(state): State<AppState>,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<RefreshResponse>, AppError> {
    let token_hash = blake3::hash(req.refresh_token.as_bytes())
        .to_hex()
        .to_string();

    // 1. Find valid token
    let token = db_tokens::find_refresh_token(&state.db, &token_hash)
        .await?
        .ok_or(AppError::Unauthorized)?;

    // 2. Revoke old token (rotation — one-time use)
    db_tokens::revoke_refresh_token(&state.db, token.id).await?;

    // 3. Get user (check still active)
    let user = users::find_by_id(&state.db, token.user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    if !user.is_active {
        return Err(AppError::Unauthorized);
    }

    // 4. Issue new pair
    let (access_token, new_refresh) =
        issue_token_pair(&state, token.user_id, user.email_verified).await?;

    Ok(Json(RefreshResponse {
        access_token,
        refresh_token: new_refresh,
    }))
}

pub async fn logout(
    State(state): State<AppState>,
    // Extracted by auth middleware (Week 5 Step 6):
    axum::Extension(claims): axum::Extension<Claims>,
) -> Result<axum::http::StatusCode, AppError> {
    let session_id = claims.session_id().map_err(|_| AppError::Unauthorized)?;

    // 1. Add JWT sid to blocklist (TTL = remaining token lifetime)
    let remaining = JwtService::seconds_remaining(&claims).max(1) as u64;
    state
        .cache
        .set_flag(&format!("jwt_blocklist:{}", session_id), remaining)
        .await?;

    // 2. Revoke all refresh tokens for this session
    db_tokens::revoke_session_tokens(&state.db, session_id).await?;

    tracing::info!(
        user_id = %claims.sub,
        session_id = %session_id,
        "User logged out"
    );

    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// TOTP Setup — Step 1: generate secret, return QR URI.
/// Secret is stored in Redis (unconfirmed) until verify_totp_setup confirms it.
pub async fn totp_setup(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<Claims>,
) -> Result<Json<serde_json::Value>, AppError> {
    let user_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;
    let user = users::find_by_id(&state.db, user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    if user.totp_enabled {
        return Err(AppError::Conflict("TOTP is already enabled".into()));
    }

    // Generate random TOTP secret (20 bytes = 160 bits)
    let mut secret_bytes = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut secret_bytes);
    let secret_base32 = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &secret_bytes);

    // Build the otpauth URI for QR code
    let totp = TOTP::new(
        TotpAlgorithm::SHA1,
        6,
        1,
        30,
        Secret::Raw(secret_bytes.to_vec()).to_bytes().unwrap(),
        Some("evnx".to_string()), // issuer
        user.email.clone(),       // account_name (email)
    )
    .map_err(|e| AppError::Internal(format!("TOTP init failed: {e}")))?;

    // let totp_uri = totp.get_url(&user.email, "evnx");
    let totp_uri = totp.get_url();
    // let qr_code = totp.get_qr_base64()?; // Base64-encoded PNG data for QR code (optional, can be generated client-side)

    // Store unconfirmed secret in Redis (10-min TTL — user has time to scan QR)
    state
        .cache
        .set_json(&format!("totp_setup:{}", user_id), &secret_base32, 600)
        .await?;

    Ok(Json(serde_json::json!({
        "totp_uri": totp_uri,
        "secret_base32": secret_base32,
    })))
}

/// TOTP Setup — Step 2: user submits a code to confirm the secret works.
/// Writes the secret (encrypted) to DB and enables TOTP.
pub async fn totp_confirm(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<Claims>,
    Json(req): Json<serde_json::Value>,
) -> Result<axum::http::StatusCode, AppError> {
    let user_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;
    let code = req
        .get("totp_code")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Validation("totp_code required".into()))?;

    // Fetch unconfirmed secret from Redis
    let secret_base32: Option<String> = state
        .cache
        .get_json(&format!("totp_setup:{}", user_id))
        .await?;
    let secret_base32 = secret_base32.ok_or_else(|| {
        AppError::Validation("No pending TOTP setup. Call /auth/totp/setup first.".into())
    })?;

    // Verify the submitted code
    verify_totp_code(&secret_base32, code)?;

    // Write secret to DB (encrypt with pgcrypto — server-managed key)
    // For simplicity, store base32 directly. Production: encrypt with server key.
    sqlx::query!(
        "UPDATE users SET totp_secret_enc = $1, totp_enabled = true, updated_at = NOW() WHERE id = $2",
        secret_base32,
        user_id,
    )
    .execute(&state.db)
    .await
    .map_err(AppError::Database)?;

    // Remove the pending setup key
    state.cache.del(&format!("totp_setup:{}", user_id)).await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Verify TOTP code during login (when requires_totp = true).
pub async fn totp_verify_login(
    State(state): State<AppState>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    let totp_pending_token = req
        .get("totp_pending_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Validation("totp_pending_token required".into()))?;

    let code = req
        .get("totp_code")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Validation("totp_code required".into()))?;

    // Validate the pending token (a short-lived JWT with scope: "totp_pending")
    let claims = state
        .jwt
        .verify(totp_pending_token)
        .map_err(|_| AppError::Unauthorized)?;

    if claims.scope != "totp_pending" {
        return Err(AppError::Unauthorized);
    }

    let user_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;

    // Check lockout
    let lockout_key = format!("totp_lockout:{}", user_id);
    let failures: u64 = state
        .cache
        .get_json::<u64>(&lockout_key)
        .await?
        .unwrap_or(0);

    if failures >= 3 {
        return Err(AppError::AccountLocked);
    }

    // Fetch TOTP secret from DB
    let user = users::find_by_id(&state.db, user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let secret_base32 = user
        .totp_secret_enc
        .ok_or_else(|| AppError::Internal("TOTP enabled but no secret".into()))?;

    // Verify code
    match verify_totp_code(&secret_base32, code) {
        Ok(()) => {
            // Clear lockout counter
            state.cache.del(&lockout_key).await?;

            // Issue real tokens
            let (access_token, refresh_token) =
                issue_token_pair(&state, user_id, user.email_verified).await?;

            Ok(Json(serde_json::json!({
                "access_token": access_token,
                "refresh_token": refresh_token,
            })))
        }
        Err(_) => {
            // Increment lockout counter (15-min window)
            state.cache.incr_with_ttl(&lockout_key, 900).await?;
            Err(AppError::Unauthorized)
        }
    }
}

/// Validate a 6-digit TOTP code against a base32 secret.
/// Accepts ±1 step (30s window) to handle clock drift.
fn verify_totp_code(secret_base32: &str, code: &str) -> Result<(), AppError> {
    let secret_bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret_base32)
        .ok_or_else(|| AppError::Internal("Invalid stored TOTP secret".into()))?;

    let totp = TOTP::new(
        TotpAlgorithm::SHA1,
        6,
        1,
        30,
        Secret::Raw(secret_bytes).to_bytes().unwrap(),
        Some("evnx".to_string()), // ← issuer (can be None if not needed)
        "test_email@evnx.dev".to_string(), // ← account_name (required, no colons allowed)
    )
    .map_err(|_| AppError::Internal("TOTP init failed".into()))?;

    // check_current_with_step allows 1 step backward (handles 30s drift)
    if totp.check_current(code).unwrap_or(false) {
        Ok(())
    } else {
        Err(AppError::Unauthorized)
    }
}

pub async fn me(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<Claims>,
) -> Result<Json<serde_json::Value>, AppError> {
    let user_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;
    let user = users::find_by_id(&state.db, user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    Ok(Json(serde_json::json!({
        "user_id":               user.id,
        "email":                 user.email,
        "email_verified":        user.email_verified,
        "encrypted_private_key": user.encrypted_private_key,
        "argon2_salt":           user.argon2_salt,
        "totp_enabled":          user.totp_enabled,
    })))
}
