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
            ed25519_public_key, encrypted_private_key, email_verified
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, false)
        "#,
        input.id,
        input.email,
        input.srp_verifier,
        input.srp_salt,
        input.argon2_salt,
        input.ed25519_public_key,
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
               argon2_salt, ed25519_public_key, encrypted_private_key,
               totp_secret_enc, totp_enabled, is_active, last_login_at, created_at
        FROM users WHERE id = $1
        "#,
        id
    )
    .fetch_optional(pool)
    .await
}
