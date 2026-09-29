// src/db/rotation.rs

//! Master-key rotation — the rows it reads, locks and replaces.
//!
//! Every function here is executor-generic so the route can compose them inside
//! one transaction. That is not a style preference: a rotation that half-applies
//! leaves an account whose password no longer matches its wraps, and nothing can
//! open it again. See `routes/master_key.rs` for the ordering and why.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// One vault key wrapped under the account's own master key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WrapSnapshot {
    pub vault_id: Uuid,
    pub encrypted_vault_key: String,
}

/// The account material a rotation replaces, as it stands right now.
pub struct AccountMaterial {
    pub email: String,
    pub totp_enabled: bool,
    pub srp_salt: String,
    pub srp_verifier: String,
    pub argon2_salt: String,
    pub encrypted_private_key: String,
}

/// Read the account's current material and **lock the row**.
///
/// The lock is what makes the exact-set check below sound: without it, a share
/// or a vault creation landing between the check and the writes would leave one
/// wrap under the old key, and a vault whose key is under a password nobody has
/// any more is simply lost.
pub async fn lock_account<'e, E>(
    executor: E,
    user_id: Uuid,
) -> Result<Option<AccountMaterial>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let row = sqlx::query!(
        r#"
        SELECT email, totp_enabled, srp_salt, srp_verifier, argon2_salt,
               encrypted_private_key
          FROM users
         WHERE id = $1
           FOR UPDATE
        "#,
        user_id
    )
    .fetch_optional(executor)
    .await?;

    Ok(row.map(|r| AccountMaterial {
        email: r.email,
        totp_enabled: r.totp_enabled,
        srp_salt: r.srp_salt,
        srp_verifier: r.srp_verifier,
        argon2_salt: r.argon2_salt,
        encrypted_private_key: r.encrypted_private_key,
    }))
}

/// Every vault key this account holds **wrapped under its own master key**, locked.
///
/// ⚠️ `eph_pub_key IS NULL` is the whole filter, and it is the difference between
/// the two wrap modes. A row with `eph_pub_key` set is a vault key shared *to*
/// this account, wrapped to its X25519 + ML-KEM keypair — and rotation does not
/// change that keypair, it re-seals the seed it is derived from. Those rows are
/// untouched by a rotation and must stay that way: writing a master-key wrap into
/// one would produce half a hybrid wrap, which migration 004's
/// `vault_members_wrap_is_whole` CHECK refuses anyway.
pub async fn own_wraps_for_update<'e, E>(
    executor: E,
    user_id: Uuid,
) -> Result<Vec<WrapSnapshot>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let rows = sqlx::query!(
        r#"
        SELECT vault_id, encrypted_vault_key
          FROM vault_members
         WHERE user_id = $1
           AND eph_pub_key IS NULL
         ORDER BY vault_id
           FOR UPDATE
        "#,
        user_id
    )
    .fetch_all(executor)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| WrapSnapshot {
            vault_id: r.vault_id,
            encrypted_vault_key: r.encrypted_vault_key,
        })
        .collect())
}

/// Replace the four columns a new master password changes.
///
/// ⚠️ The public keys are deliberately absent. The identity keypair is derived
/// from a seed this operation re-seals rather than replaces, and
/// `backfill_public_keys` is write-once precisely because a mutable public key
/// lets whoever holds a session intercept every future share. Rotation must not
/// become a second route to that.
pub async fn apply_new_material<'e, E>(
    executor: E,
    user_id: Uuid,
    srp_salt: &str,
    srp_verifier: &str,
    argon2_salt: &str,
    encrypted_private_key: &str,
) -> Result<bool, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let r = sqlx::query!(
        r#"
        UPDATE users
           SET srp_salt = $2, srp_verifier = $3, argon2_salt = $4,
               encrypted_private_key = $5
         WHERE id = $1
        "#,
        user_id,
        srp_salt,
        srp_verifier,
        argon2_salt,
        encrypted_private_key,
    )
    .execute(executor)
    .await?;
    Ok(r.rows_affected() == 1)
}

/// Re-wrap one own-copy vault key.
///
/// `eph_pub_key IS NULL` is repeated in the WHERE even though the rows are
/// already locked — belt and braces, so this can never clobber a share into a
/// broken half-wrap even if it is called from somewhere that forgot the lock.
pub async fn set_own_wrap<'e, E>(
    executor: E,
    user_id: Uuid,
    vault_id: Uuid,
    encrypted_vault_key: &str,
) -> Result<bool, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let r = sqlx::query!(
        r#"
        UPDATE vault_members
           SET encrypted_vault_key = $3
         WHERE user_id = $1
           AND vault_id = $2
           AND eph_pub_key IS NULL
        "#,
        user_id,
        vault_id,
        encrypted_vault_key,
    )
    .execute(executor)
    .await?;
    Ok(r.rows_affected() == 1)
}

// ─── The undo window ──────────────────────────────────────────────────────────

/// Close any snapshot whose window has run out, so it stops blocking a new one.
///
/// The unique index allows one live snapshot per account, which is what stops a
/// chain of rotations erasing the owner's real material — but it would also stop
/// a legitimate rotation months later if expired rows were left open. Closing
/// them here keeps both properties.
pub async fn expire_stale_snapshots<'e, E>(executor: E, user_id: Uuid) -> Result<u64, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let r = sqlx::query!(
        r#"
        UPDATE master_key_rotations
           SET consumed_at = NOW(), outcome = 'expired'
         WHERE user_id = $1
           AND consumed_at IS NULL
           AND expires_at <= NOW()
        "#,
        user_id
    )
    .execute(executor)
    .await?;
    Ok(r.rows_affected())
}

/// Record the material this rotation is about to replace.
///
/// ⚠️ **`ON CONFLICT DO NOTHING` keeps the FIRST snapshot in a window, not the
/// newest, and that is the point.** An attacker who has already rotated the
/// account knows the current password, so nothing stops them rotating again. If
/// a second rotation overwrote the snapshot, the stored "previous" material would
/// be the attacker's own garbage and the owner's real material would be gone —
/// the undo would restore them into the same locked-out account.
///
/// Returns whether a snapshot was stored. `false` means one was already open,
/// which is not an error: the older one is the more valuable.
pub async fn store_snapshot<'e, E>(
    executor: E,
    user_id: Uuid,
    prev: &AccountMaterial,
    prev_wraps: &[WrapSnapshot],
    window_hours: i64,
) -> Result<bool, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let wraps = serde_json::to_value(prev_wraps).unwrap_or(serde_json::Value::Array(vec![]));

    let r = sqlx::query!(
        r#"
        INSERT INTO master_key_rotations
            (user_id, expires_at, prev_srp_salt, prev_srp_verifier,
             prev_argon2_salt, prev_encrypted_private_key, prev_wraps)
        VALUES ($1, NOW() + make_interval(hours => $2::int), $3, $4, $5, $6, $7)
        ON CONFLICT DO NOTHING
        "#,
        user_id,
        window_hours as i32,
        prev.srp_salt,
        prev.srp_verifier,
        prev.argon2_salt,
        prev.encrypted_private_key,
        wraps,
    )
    .execute(executor)
    .await?;
    Ok(r.rows_affected() == 1)
}

/// A snapshot that can still be restored.
pub struct LiveSnapshot {
    pub id: Uuid,
    pub user_id: Uuid,
    pub prev_srp_salt: String,
    pub prev_srp_verifier: String,
    pub prev_argon2_salt: String,
    pub prev_encrypted_private_key: String,
    pub prev_wraps: Vec<WrapSnapshot>,
}

/// The live snapshot for an address, if there is one.
///
/// Looked up by email rather than by session on purpose: the person who needs it
/// is by definition the person who can no longer log in. The endpoint that calls
/// this answers identically when there is nothing to find — see
/// `routes/master_key.rs`.
pub async fn live_snapshot_for_email(
    pool: &sqlx::PgPool,
    email: &str,
) -> Result<Option<LiveSnapshot>, sqlx::Error> {
    let row = sqlx::query!(
        r#"
        SELECT r.id, r.user_id, r.prev_srp_salt, r.prev_srp_verifier,
               r.prev_argon2_salt, r.prev_encrypted_private_key, r.prev_wraps
          FROM master_key_rotations r
          JOIN users u ON u.id = r.user_id
         WHERE LOWER(u.email) = LOWER($1)
           AND r.consumed_at IS NULL
           AND r.expires_at > NOW()
         ORDER BY r.rotated_at ASC
         LIMIT 1
        "#,
        email
    )
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| LiveSnapshot {
        id: r.id,
        user_id: r.user_id,
        prev_srp_salt: r.prev_srp_salt,
        prev_srp_verifier: r.prev_srp_verifier,
        prev_argon2_salt: r.prev_argon2_salt,
        prev_encrypted_private_key: r.prev_encrypted_private_key,
        // A snapshot that cannot be parsed is a snapshot that cannot be
        // restored, and an empty list would silently restore the account
        // material while leaving every vault under the new key. Treated as
        // "no wraps" here and caught by the restore's own count check.
        prev_wraps: serde_json::from_value(r.prev_wraps).unwrap_or_default(),
    }))
}

/// Close a snapshot once it has been restored.
pub async fn consume<'e, E>(executor: E, id: Uuid, outcome: &str) -> Result<bool, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let r = sqlx::query!(
        r#"
        UPDATE master_key_rotations
           SET consumed_at = NOW(), outcome = $2
         WHERE id = $1
           AND consumed_at IS NULL
        "#,
        id,
        outcome,
    )
    .execute(executor)
    .await?;
    Ok(r.rows_affected() == 1)
}
