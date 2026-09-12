// src/db/members.rs

use sqlx::PgPool;
use uuid::Uuid;

pub struct WrappedKeyRow {
    pub encrypted_vault_key: String,
    pub eph_pub_key: Option<String>,
}

/// Grant a user access to a vault by storing their ECDH-wrapped vault key.
///
/// Generic over the executor so vault creation can insert the owner's row in the
/// same transaction as the vault itself.
pub async fn add_member<'e, E>(
    executor: E,
    vault_id: Uuid,
    user_id: Uuid,
    role: &str,
    encrypted_vault_key: &str,
    eph_pub_key: &str,
    granted_by: Uuid,
) -> Result<(), sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query!(
        r#"
        INSERT INTO vault_members
            (vault_id, user_id, role, encrypted_vault_key, eph_pub_key, granted_by)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (vault_id, user_id) DO UPDATE
            SET role = EXCLUDED.role,
                encrypted_vault_key = EXCLUDED.encrypted_vault_key,
                eph_pub_key = EXCLUDED.eph_pub_key,
                granted_by = EXCLUDED.granted_by,
                granted_at = NOW()
        "#,
        vault_id,
        user_id,
        role,
        encrypted_vault_key,
        eph_pub_key,
        granted_by,
    )
    .execute(executor)
    .await?;
    Ok(())
}

pub async fn get_wrapped_key(
    pool: &PgPool,
    vault_id: Uuid,
    user_id: Uuid,
) -> Result<Option<WrappedKeyRow>, sqlx::Error> {
    sqlx::query_as!(
        WrappedKeyRow,
        r#"
        SELECT encrypted_vault_key, eph_pub_key
        FROM vault_members
        WHERE vault_id = $1 AND user_id = $2
        "#,
        vault_id,
        user_id,
    )
    .fetch_optional(pool)
    .await
}

pub async fn remove_member(
    pool: &PgPool,
    vault_id: Uuid,
    user_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let r = sqlx::query!(
        "DELETE FROM vault_members WHERE vault_id = $1 AND user_id = $2",
        vault_id,
        user_id,
    )
    .execute(pool)
    .await?;
    Ok(r.rows_affected() > 0)
}
