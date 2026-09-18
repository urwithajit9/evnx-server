// src/db/users.rs

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

/// Data needed to create a new user row.
/// Comes directly from the registration request body.
pub struct CreateUser {
    pub id: Uuid,
    pub email: String,
    pub srp_verifier: String,
    pub srp_salt: String,
    pub argon2_salt: String,
    pub ed25519_public_key: String,
    pub x25519_public_key: String,
    /// ML-KEM-768 public key, base64 — 1580 characters.
    pub mlkem_public_key: String,
    pub encrypted_private_key: String,
}

/// A full user row fetched from the DB.
pub struct UserRow {
    pub id: Uuid,
    pub email: String,
    pub email_verified: bool,
    pub srp_verifier: String,
    pub srp_salt: String,
    pub argon2_salt: String,
    pub ed25519_public_key: String,
    /// `None` for an account that predates F1. Clients check this after login and
    /// upload the key if it is missing — see `routes::users::backfill_public_keys`.
    pub mlkem_public_key: Option<String>,
    pub encrypted_private_key: String,
    pub totp_secret_enc: Option<String>,
    pub totp_enabled: bool,
    pub is_active: bool,
    pub last_login_at: Option<chrono::DateTime<Utc>>,
    pub created_at: chrono::DateTime<Utc>,
}

/// SRP lookup result — only the fields needed for SRP init.
pub struct SrpUserData {
    pub id: Uuid,
    pub srp_verifier: String,
    pub srp_salt: String,
    pub argon2_salt: String,
    pub totp_enabled: bool,
}

// Add to src/db/users.rs

pub struct UserPublicProfile {
    pub id: Uuid,
    pub email: String,
    pub email_verified: bool,
    pub x25519_public_key: String,
    pub ed25519_public_key: String,
    /// ⚠️ `None` for accounts that registered before F1 and have not signed in
    /// with a client that derives the key. **Such a user cannot be shared with**
    /// — see `routes::members::add_member`, which refuses rather than falling
    /// back to an X25519-only wrap.
    pub mlkem_public_key: Option<String>,
}

pub async fn find_by_email(
    pool: &PgPool,
    email: &str,
) -> Result<Option<UserPublicProfile>, sqlx::Error> {
    sqlx::query_as!(
        UserPublicProfile,
        r#"
        SELECT id, email, email_verified,
            ed25519_public_key AS "ed25519_public_key!",
            x25519_public_key AS "x25519_public_key!",
            mlkem_public_key
        FROM users
        WHERE email = $1 AND is_active = true
        "#,
        // NOTE: we store ed25519_public_key in the users table.
        // x25519_public_key is derived from ed25519 seed — but for sharing,
        // we need the x25519 public key which must ALSO be stored separately.
        // See 2.2 below.
        email,
    )
    .fetch_optional(pool)
    .await
}

/// Check if an email is already registered.
pub async fn exists_by_email(pool: &PgPool, email: &str) -> Result<bool, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1) AS exists",
        email
    )
    .fetch_one(pool)
    .await?;
    Ok(row.exists.unwrap_or(false))
}

/// Insert a new user row.
pub async fn create(pool: &PgPool, input: CreateUser) -> Result<Uuid, sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO users (
            id, email, srp_verifier, srp_salt, argon2_salt,
            ed25519_public_key, x25519_public_key, mlkem_public_key,
            encrypted_private_key, email_verified
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, false)
        "#,
        input.id,
        input.email,
        input.srp_verifier,
        input.srp_salt,
        input.argon2_salt,
        input.ed25519_public_key,
        input.x25519_public_key,
        input.mlkem_public_key,
        input.encrypted_private_key,
    )
    .execute(pool)
    .await?;
    Ok(input.id)
}

/// Fetch SRP auth data for a known email.
/// Returns None if email not found (caller must handle this as a constant-time fake).
pub async fn find_srp_data(pool: &PgPool, email: &str) -> Result<Option<SrpUserData>, sqlx::Error> {
    sqlx::query_as!(
        SrpUserData,
        r#"
        SELECT id, srp_verifier, srp_salt, argon2_salt, totp_enabled
        FROM users
        WHERE email = $1 AND is_active = true
        "#,
        email
    )
    .fetch_optional(pool)
    .await
}

/// Update last_login_at timestamp after successful login.
pub async fn update_last_login(pool: &PgPool, user_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE users SET last_login_at = NOW(), updated_at = NOW() WHERE id = $1",
        user_id
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Look up a user by ID (used after JWT auth to get full user data).
pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<UserRow>, sqlx::Error> {
    sqlx::query_as!(
        UserRow,
        r#"
        SELECT id, email, email_verified, srp_verifier, srp_salt,
               argon2_salt, ed25519_public_key, mlkem_public_key, encrypted_private_key,
               totp_secret_enc, totp_enabled, is_active, last_login_at, created_at
        FROM users WHERE id = $1
        "#,
        id
    )
    .fetch_optional(pool)
    .await
}

/// Outcome of a public-key backfill attempt.
pub enum PublicKeyBackfill {
    /// The row had no ML-KEM key and now has this one.
    Stored,
    /// The row already held exactly this key. Nothing changed.
    AlreadyMatches,
    /// ⚠️ The row already held a *different* key.
    ///
    /// This should be impossible for an honest client: the ML-KEM key is
    /// derived deterministically from the Ed25519 seed, and that seed does not
    /// change — not even when the master password does, since a password change
    /// re-seals the seed rather than replacing it. So a mismatch is either a
    /// client bug or someone with a stolen session substituting their own key so
    /// that future shares to this account come to them.
    Conflict,
}

/// Store a user's ML-KEM public key, **write-once**.
///
/// Callable on every login — it is idempotent when the value matches, which is
/// what makes "upload it each time" a safe client strategy rather than a
/// repeated overwrite.
///
/// ⚠️ **Write-once is a security property, not caution.** An open update would
/// let anyone holding a session swap the account's public key for their own; the
/// victim would notice nothing, and every vault shared with them afterwards
/// would be wrapped to the attacker. There is no legitimate reason to change a
/// derived key, so the endpoint does not offer it.
pub async fn backfill_mlkem_public_key(
    pool: &PgPool,
    user_id: Uuid,
    mlkem_public_key: &str,
) -> Result<PublicKeyBackfill, sqlx::Error> {
    let updated = sqlx::query!(
        r#"
        UPDATE users
        SET mlkem_public_key = $2
        WHERE id = $1 AND mlkem_public_key IS NULL
        "#,
        user_id,
        mlkem_public_key,
    )
    .execute(pool)
    .await?;

    if updated.rows_affected() == 1 {
        return Ok(PublicKeyBackfill::Stored);
    }

    // Either the row already had a key, or it does not exist. Read it back to
    // tell an idempotent re-upload apart from a substitution attempt.
    let existing = sqlx::query!("SELECT mlkem_public_key FROM users WHERE id = $1", user_id)
        .fetch_optional(pool)
        .await?;

    Ok(match existing.and_then(|r| r.mlkem_public_key) {
        Some(k) if k == mlkem_public_key => PublicKeyBackfill::AlreadyMatches,
        _ => PublicKeyBackfill::Conflict,
    })
}
