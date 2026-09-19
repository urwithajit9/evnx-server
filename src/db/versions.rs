// src/db/versions.rs

use sqlx::PgPool;
use uuid::Uuid;

pub struct VersionRow {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub version_num: i32,
    pub blob_key: String,
    pub blob_size_bytes: i32,
    pub blob_hash: String,
    pub key_count: i32,
    pub key_names: Option<Vec<String>>,
    pub pushed_by: Uuid,
    pub pushed_at: chrono::DateTime<chrono::Utc>,
}

pub struct CreateVersion {
    pub vault_id: Uuid,
    pub version_num: i32,
    pub blob_key: String,
    pub blob_size_bytes: i32,
    pub blob_hash: String,
    pub key_count: i32,
    pub key_names: Vec<String>,
    pub pushed_by: Uuid,
}

pub async fn get_latest_version_num(
    pool: &PgPool,
    vault_id: Uuid,
) -> Result<Option<i32>, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT MAX(version_num) AS max FROM vault_versions WHERE vault_id = $1",
        vault_id,
    )
    .fetch_one(pool)
    .await?;
    Ok(row.max)
}

pub async fn create(pool: &PgPool, input: CreateVersion) -> Result<VersionRow, sqlx::Error> {
    sqlx::query_as!(
        VersionRow,
        r#"
        INSERT INTO vault_versions
            (vault_id, version_num, blob_key, blob_size_bytes, blob_hash,
             key_count, key_names, pushed_by)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING *
        "#,
        input.vault_id,
        input.version_num,
        input.blob_key,
        input.blob_size_bytes,
        input.blob_hash,
        input.key_count,
        &input.key_names,
        input.pushed_by,
    )
    .fetch_one(pool)
    .await
}

pub async fn get_latest(pool: &PgPool, vault_id: Uuid) -> Result<Option<VersionRow>, sqlx::Error> {
    sqlx::query_as!(
        VersionRow,
        r#"
        SELECT * FROM vault_versions
        WHERE vault_id = $1
        ORDER BY version_num DESC
        LIMIT 1
        "#,
        vault_id,
    )
    .fetch_optional(pool)
    .await
}

pub async fn get_by_num(
    pool: &PgPool,
    vault_id: Uuid,
    version_num: i32,
) -> Result<Option<VersionRow>, sqlx::Error> {
    sqlx::query_as!(
        VersionRow,
        "SELECT * FROM vault_versions WHERE vault_id = $1 AND version_num = $2",
        vault_id,
        version_num,
    )
    .fetch_optional(pool)
    .await
}

pub async fn list(pool: &PgPool, vault_id: Uuid) -> Result<Vec<VersionRow>, sqlx::Error> {
    sqlx::query_as!(
        VersionRow,
        "SELECT * FROM vault_versions WHERE vault_id = $1 ORDER BY version_num DESC",
        vault_id,
    )
    .fetch_all(pool)
    .await
}

/// Point a version at a new blob, as part of a re-key.
///
/// Executor-generic so every version in a vault can move inside one transaction
/// with the member re-wraps. A re-key that committed version by version would
/// leave a vault whose history is split across two keys, which no client can
/// open — see `routes::versions::rekey`.
///
/// `version_num`, `key_names` and `key_count` are untouched: re-keying changes
/// how the bytes are encrypted, never what they say.
pub async fn repoint_blob<'e, E>(
    executor: E,
    vault_id: Uuid,
    version_num: i32,
    blob_key: &str,
    blob_hash: &str,
    blob_size_bytes: i32,
) -> Result<bool, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let r = sqlx::query!(
        r#"
        UPDATE vault_versions
           SET blob_key = $3, blob_hash = $4, blob_size_bytes = $5
         WHERE vault_id = $1 AND version_num = $2
        "#,
        vault_id,
        version_num,
        blob_key,
        blob_hash,
        blob_size_bytes,
    )
    .execute(executor)
    .await?;
    Ok(r.rows_affected() == 1)
}

/// Every version number a vault currently has, ascending.
pub async fn all_version_nums(pool: &PgPool, vault_id: Uuid) -> Result<Vec<i32>, sqlx::Error> {
    let rows = sqlx::query!(
        "SELECT version_num FROM vault_versions WHERE vault_id = $1 ORDER BY version_num ASC",
        vault_id,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.version_num).collect())
}
