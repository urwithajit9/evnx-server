// src/db/members.rs

use sqlx::PgPool;
use uuid::Uuid;

pub struct WrappedKeyRow {
    pub encrypted_vault_key: String,
    pub eph_pub_key: Option<String>,
    /// ML-KEM-768 ciphertext, base64 — 1452 characters.
    ///
    /// `None` only for the vault creator's own copy, which is wrapped under
    /// their master key and involves no key agreement at all. A CHECK constraint
    /// (migration 004) makes "one present, one absent" unrepresentable.
    pub mlkem_ciphertext: Option<String>,
}

/// How a member's copy of the vault key was wrapped.
///
/// ─── Why this is an enum and not three `Option`s ─────────────────────────────
///
/// There are exactly two legitimate shapes, and the difference is not a detail:
///
/// * **`OwnMasterKey`** — the vault creator's own copy, wrapped under an HKDF
///   subkey of their master key. Symmetric, no key agreement, already
///   post-quantum safe.
/// * **`Hybrid`** — a copy wrapped *for someone else*, by X25519 ECDH and
///   ML-KEM-768 together.
///
/// A row carrying an ephemeral X25519 key but no ML-KEM ciphertext is neither.
/// It is a wrap that Shor opens, and it stays that way for as long as the row
/// exists — an adversary recording it does not care that a later version fixed
/// the algorithm.
///
/// `vault_members_wrap_is_whole` (migration 004) refuses that shape at the
/// database. This enum refuses it one layer earlier, in the type system: there is
/// no way to *construct* half a wrap, so no handler can forget the rule and no
/// future argument gets dropped at a call site. The CHECK constraint remains as
/// the backstop for anything reaching the table by another route.
pub enum MemberKeyWrap {
    /// The creator's own copy. Both key-agreement columns are NULL.
    OwnMasterKey {
        /// base64 — `[24-byte nonce || ciphertext || tag]`.
        encrypted_vault_key: String,
    },
    /// Wrapped for another member — hybrid X25519 + ML-KEM-768.
    Hybrid {
        /// base64.
        encrypted_vault_key: String,
        /// base64, 44 characters — the sender's ephemeral X25519 public key.
        eph_pub_key: String,
        /// base64, 1452 characters — the ML-KEM-768 ciphertext.
        mlkem_ciphertext: String,
    },
}

impl MemberKeyWrap {
    /// The three column values, in the shape the INSERT wants.
    fn columns(&self) -> (&str, Option<&str>, Option<&str>) {
        match self {
            Self::OwnMasterKey {
                encrypted_vault_key,
            } => (encrypted_vault_key, None, None),
            Self::Hybrid {
                encrypted_vault_key,
                eph_pub_key,
                mlkem_ciphertext,
            } => (
                encrypted_vault_key,
                Some(eph_pub_key),
                Some(mlkem_ciphertext),
            ),
        }
    }
}

/// Grant a user access to a vault by storing their wrapped vault key.
///
/// Generic over the executor so vault creation can insert the owner's row in the
/// same transaction as the vault itself.
pub async fn add_member<'e, E>(
    executor: E,
    vault_id: Uuid,
    user_id: Uuid,
    role: &str,
    wrap: &MemberKeyWrap,
    granted_by: Uuid,
) -> Result<(), sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let (encrypted_vault_key, eph_pub_key, mlkem_ciphertext) = wrap.columns();

    sqlx::query!(
        r#"
        INSERT INTO vault_members
            (vault_id, user_id, role, encrypted_vault_key, eph_pub_key,
             mlkem_ciphertext, granted_by)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (vault_id, user_id) DO UPDATE
            SET role = EXCLUDED.role,
                encrypted_vault_key = EXCLUDED.encrypted_vault_key,
                eph_pub_key = EXCLUDED.eph_pub_key,
                mlkem_ciphertext = EXCLUDED.mlkem_ciphertext,
                granted_by = EXCLUDED.granted_by,
                granted_at = NOW()
        "#,
        vault_id,
        user_id,
        role,
        encrypted_vault_key,
        eph_pub_key,
        mlkem_ciphertext,
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
        SELECT encrypted_vault_key, eph_pub_key, mlkem_ciphertext
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

/// One row of a vault's member list.
///
/// ⚠️ Deliberately carries **no key material**. `encrypted_vault_key`,
/// `eph_pub_key` and `mlkem_ciphertext` are each wrapped to one specific member
/// and are useless to anyone else — but "useless to an attacker" is not a reason
/// to hand them out, and a listing endpoint is exactly where that kind of field
/// gets copied into a response by accident.
pub struct MemberRow {
    pub user_id: Uuid,
    pub email: String,
    pub role: String,
    pub granted_at: chrono::DateTime<chrono::Utc>,
    /// Who granted this access. `None` only if that account has since been
    /// deleted — the column is a nullable FK.
    pub granted_by: Option<Uuid>,
    /// Whether this member has a post-quantum public key on file.
    ///
    /// `false` means an account that predates F1 and has not signed in since.
    /// Surfaced here so a client can explain *why* a re-key or a re-share will
    /// refuse them, rather than failing at the point of action with no warning.
    pub has_mlkem_key: bool,
}

/// Everyone who can reach a vault, oldest grant first.
///
/// The owner sorts first regardless, because a member list whose first row moves
/// around as people are added reads as unstable.
pub async fn list_members(pool: &PgPool, vault_id: Uuid) -> Result<Vec<MemberRow>, sqlx::Error> {
    sqlx::query_as!(
        MemberRow,
        r#"
        SELECT
            u.id AS "user_id!",
            u.email AS "email!",
            m.role AS "role!",
            m.granted_at AS "granted_at!",
            m.granted_by,
            (u.mlkem_public_key IS NOT NULL) AS "has_mlkem_key!"
        FROM vault_members m
        JOIN users u ON u.id = m.user_id
        WHERE m.vault_id = $1
        ORDER BY (m.role = 'owner') DESC, m.granted_at ASC
        "#,
        vault_id,
    )
    .fetch_all(pool)
    .await
}
