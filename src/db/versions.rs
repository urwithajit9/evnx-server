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
