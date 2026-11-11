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
#[derive(sqlx::FromRow)]
pub struct VaultWithRole {
    pub id: Uuid,
    pub name: String,
    pub environment: String,
    pub owner_id: Uuid,
    pub role: String,
    pub version_count: i64,
    pub updated_at: chrono::DateTime<Utc>,
    /// `pushed_at` of the newest version, or `None` when nothing was ever pushed.
    /// Unlike `updated_at`, rename / member changes / rekey never move it.
    pub last_pushed_at: Option<chrono::DateTime<Utc>>,
}

/// Insert a vault row.
///
/// Generic over the executor so it can run inside a transaction: a vault without
/// an owner row in `vault_members` is invisible to `list_for_user` (which inner
/// joins that table) while still holding its unique (owner, name, environment),
/// so the owner can neither see it nor recreate the name. Callers creating a new
/// vault must pair this with `members::add_member` in one transaction.
pub async fn create<'e, E>(
    executor: E,
    owner_id: Uuid,
    name: &str,
    environment: &str,
) -> Result<Uuid, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
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
    .execute(executor)
    .await?;
    Ok(id)
}

pub async fn list_for_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<VaultWithRole>, sqlx::Error> {
    // Runtime query (not `query_as!`) so the `.sqlx` offline cache needs no
    // regeneration. The LATERAL subquery reads the newest version through
    // `idx_vault_versions_vault (vault_id, version_num DESC)`: one index probe per
    // vault, no N+1. `version_num` rises with every push, so the newest number is
    // the latest push.
    sqlx::query_as::<_, VaultWithRole>(
        r#"
        SELECT
            v.id, v.name, v.environment, v.owner_id,
            vm.role,
            COUNT(vv.id)::BIGINT AS version_count,
            v.updated_at,
            lp.pushed_at AS last_pushed_at
        FROM vaults v
        JOIN vault_members vm ON vm.vault_id = v.id AND vm.user_id = $1
        LEFT JOIN vault_versions vv ON vv.vault_id = v.id
        LEFT JOIN LATERAL (
            SELECT pushed_at
            FROM vault_versions
            WHERE vault_id = v.id
            ORDER BY version_num DESC
            LIMIT 1
        ) lp ON TRUE
        WHERE v.deleted_at IS NULL
        GROUP BY v.id, vm.role, lp.pushed_at
        ORDER BY v.updated_at DESC
        "#,
    )
    .bind(user_id)
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
