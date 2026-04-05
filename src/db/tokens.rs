// src/db/tokens.rs

use sqlx::PgPool;
use uuid::Uuid;

pub async fn create_email_verification(
    pool: &PgPool,
    user_id: Uuid,
    token_hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO email_verifications (user_id, token_hash, expires_at)
        VALUES ($1, $2, NOW() + INTERVAL '24 hours')
        "#,
        user_id,
        token_hash,
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn verify_email_token(
    pool: &PgPool,
    token_hash: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    // Find valid, unused, unexpired token and return the user_id
    let row = sqlx::query!(
        r#"
        SELECT user_id FROM email_verifications
        WHERE token_hash = $1
          AND used_at IS NULL
          AND expires_at > NOW()
        "#,
        token_hash,
    )
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| r.user_id))
}

pub async fn mark_email_verification_used(
    pool: &PgPool,
    token_hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE email_verifications SET used_at = NOW() WHERE token_hash = $1",
        token_hash,
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn mark_email_verified(pool: &PgPool, user_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE users SET email_verified = true, updated_at = NOW() WHERE id = $1",
        user_id,
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub struct RefreshTokenRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub token_hash: String,
    pub expires_at: chrono::DateTime<Utc>,
}

/// Insert a new refresh token (after SRP verify or TOTP verify).
pub async fn create_refresh_token(
    pool: &PgPool,
    user_id: Uuid,
    session_id: Uuid,
    token_hash: &str,
    expiry_days: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO refresh_tokens (user_id, session_id, token_hash, expires_at)
        VALUES ($1, $2, $3, NOW() + ($4 || ' days')::INTERVAL)
        "#,
        user_id,
        session_id,
        token_hash,
        expiry_days.to_string(),
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Find a valid (not revoked, not expired) refresh token.
pub async fn find_refresh_token(
    pool: &PgPool,
    token_hash: &str,
) -> Result<Option<RefreshTokenRow>, sqlx::Error> {
    sqlx::query_as!(
        RefreshTokenRow,
        r#"
        SELECT id, user_id, session_id, token_hash, expires_at
        FROM refresh_tokens
        WHERE token_hash = $1
          AND revoked_at IS NULL
          AND expires_at > NOW()
        "#,
        token_hash,
    )
    .fetch_optional(pool)
    .await
}

/// Revoke a refresh token (called on use — rotation enforces single-use).
pub async fn revoke_refresh_token(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = $1",
        id,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Revoke all refresh tokens for a session (used on logout).
pub async fn revoke_session_tokens(pool: &PgPool, session_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE refresh_tokens SET revoked_at = NOW() WHERE session_id = $1 AND revoked_at IS NULL",
        session_id,
    )
    .execute(pool)
    .await?;
    Ok(())
}
