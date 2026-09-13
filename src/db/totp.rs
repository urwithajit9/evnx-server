//! TOTP backup (recovery) codes.
//!
//! Codes are stored only as BLAKE3 hashes. The plaintext is shown to the user
//! once, at generation, and is unrecoverable afterwards — the same rule the API
//! tokens follow.

use uuid::Uuid;

/// How many recovery codes are issued at a time.
///
/// Ten is the common choice (GitHub, AWS): enough that a user is unlikely to
/// exhaust them before noticing, few enough to print on one line each.
pub const BACKUP_CODE_COUNT: usize = 10;

/// Replace a user's recovery codes with a fresh set.
///
/// Runs in one transaction: a half-applied regeneration would leave the user with
/// codes they were never shown, which is the lockout this whole feature exists to
/// prevent.
pub async fn replace_all(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    code_hashes: &[String],
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;

    sqlx::query!("DELETE FROM totp_backup_codes WHERE user_id = $1", user_id)
        .execute(&mut *tx)
        .await?;

    for hash in code_hashes {
        sqlx::query!(
            "INSERT INTO totp_backup_codes (user_id, code_hash) VALUES ($1, $2)",
            user_id,
            hash,
        )
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await
}

/// Redeem a recovery code, returning true if it was valid and unused.
///
/// The check and the consumption are one statement, so two concurrent logins
/// cannot both spend the same code.
pub async fn redeem(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    code_hash: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        r#"
        UPDATE totp_backup_codes
        SET used_at = NOW()
        WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL
        "#,
        user_id,
        code_hash,
    )
    .execute(pool)
    .await?;

    Ok(result.rows_affected() == 1)
}

/// How many unused codes the user has left, so a client can warn before zero.
pub async fn remaining(pool: &sqlx::PgPool, user_id: Uuid) -> Result<i64, sqlx::Error> {
    let row = sqlx::query!(
        r#"SELECT COUNT(*) AS "count!" FROM totp_backup_codes
           WHERE user_id = $1 AND used_at IS NULL"#,
        user_id,
    )
    .fetch_one(pool)
    .await?;
    Ok(row.count)
}

/// Discard every code for a user. Called when TOTP is disabled.
pub async fn delete_all(pool: &sqlx::PgPool, user_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!("DELETE FROM totp_backup_codes WHERE user_id = $1", user_id)
        .execute(pool)
        .await?;
    Ok(())
}
