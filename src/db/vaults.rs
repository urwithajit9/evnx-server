// src/db/vaults.rs

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

pub struct VaultRow {
    pub id: Uuid,
    pub name: String,
    pub environment: String,
    pub owner_id: Uuid,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
}

/// A vault row joined with the requesting user's member info.
pub struct VaultWithRole {
    pub id: Uuid,
    pub name: String,
    pub environment: String,
    pub owner_id: Uuid,
    pub role: String,
    pub version_count: i64,
    pub updated_at: chrono::DateTime<Utc>,
}

pub async fn create(
    pool: &PgPool,
    owner_id: Uuid,
    name: &str,
    environment: &str,
) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::new_v4();
    sqlx::query!(
        r#"
        INSERT INTO vaults (id, name, environment, owner_id)
        VALUES ($1, $2, $3, $4)
        "#,
        id,
        name,
        environment,
        owner_id,
    )
    .execute(pool)
    .await?;
    Ok(id)
}

pub async fn list_for_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<VaultWithRole>, sqlx::Error> {
    sqlx::query_as!(
        VaultWithRole,
        r#"
        SELECT
            v.id, v.name, v.environment, v.owner_id,
            vm.role,
            COUNT(vv.id)::BIGINT AS "version_count!",
            v.updated_at
        FROM vaults v
        JOIN vault_members vm ON vm.vault_id = v.id AND vm.user_id = $1
        LEFT JOIN vault_versions vv ON vv.vault_id = v.id
        WHERE v.deleted_at IS NULL
        GROUP BY v.id, vm.role
        ORDER BY v.updated_at DESC
        "#,
        user_id,
    )
    .fetch_all(pool)
    .await
}

pub async fn find_member_role(
    pool: &PgPool,
    vault_id: Uuid,
    user_id: Uuid,
) -> Result<Option<String>, sqlx::Error> {
    let row = sqlx::query!(
        r#"
        SELECT vm.role FROM vault_members vm
        JOIN vaults v ON v.id = vm.vault_id
        WHERE vm.vault_id = $1 AND vm.user_id = $2
          AND v.deleted_at IS NULL
        "#,
        vault_id,
        user_id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.role))
}

pub async fn soft_delete(
    pool: &PgPool,
    vault_id: Uuid,
    owner_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        r#"
        UPDATE vaults SET deleted_at = NOW(), updated_at = NOW()
        WHERE id = $1 AND owner_id = $2 AND deleted_at IS NULL
        "#,
        vault_id,
        owner_id,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}
