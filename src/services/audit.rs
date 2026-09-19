// src/services/audit.rs

use sqlx::PgPool;
use uuid::Uuid;

pub struct AuditEvent {
    pub vault_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub event_type: String,
    pub ip_hash: Option<String>,
    pub user_agent_hash: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

/// Insert an audit event. Called via `tokio::spawn` — non-blocking.
/// Errors are logged but not propagated (audit failures shouldn't break operations).
pub async fn record(pool: &PgPool, event: AuditEvent) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO audit_events
            (vault_id, user_id, event_type, ip_hash, user_agent_hash, metadata)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
        event.vault_id,
        event.user_id,
        event.event_type,
        event.ip_hash,
        event.user_agent_hash,
        event.metadata,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Record a membership change, fire-and-forget.
///
/// ─── Why these events exist ──────────────────────────────────────────────────
///
/// `push` and `pull` were already recorded; **who was granted access, and by
/// whom, was not.** That is the more important of the two for a secrets vault:
/// a surprising pull tells you someone read something, and a surprising grant
/// tells you *why they could*.
///
/// ─── What must never appear in here ──────────────────────────────────────────
///
/// ⚠️ No key material, ever. `encrypted_vault_key`, `eph_pub_key` and
/// `mlkem_ciphertext` are all wrapped to one member and useless to anyone else,
/// which is exactly the reasoning that makes people relax about copying them into
/// a log line. `audit_events` is append-only and read by humans; the metadata
/// here is ids, roles and counts.
///
/// Raw IP addresses are likewise absent — the column is `ip_hash` for a reason.
///
/// Spawned by the caller, like every other audit write: a failure to record must
/// not fail the operation it describes.
pub fn record_membership_event(
    pool: &PgPool,
    vault_id: Uuid,
    actor_id: Uuid,
    event_type: &'static str,
    metadata: serde_json::Value,
) {
    let pool = pool.clone();
    tokio::spawn(async move {
        if let Err(e) = record(
            &pool,
            AuditEvent {
                vault_id: Some(vault_id),
                user_id: Some(actor_id),
                event_type: event_type.into(),
                ip_hash: None,
                user_agent_hash: None,
                metadata: Some(metadata),
            },
        )
        .await
        {
            // Logged, never propagated, and deliberately without the metadata —
            // a failing insert is not a reason to print its contents.
            tracing::warn!(%vault_id, event_type, "failed to record audit event: {e}");
        }
    });
}

/// One event, as the vault audit view returns it.
pub struct AuditRow {
    pub id: Uuid,
    pub event_type: String,
    pub user_id: Option<Uuid>,
    pub actor_email: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// A vault's audit trail, newest first.
///
/// ⚠️ Returns `ip_hash` and `user_agent_hash` to **nobody**. They are BLAKE3
/// digests, so they identify a device across events without naming it — which is
/// exactly what makes them worth having and exactly why they should not be
/// handed to every vault member. Correlating them is an operator's job, against
/// the database, not a feature of the member-facing view.
///
/// `actor_email` is resolved by join rather than stored on the event: an email
/// copied into `metadata` at write time would go stale, and stale is worse than
/// absent in an audit log. `None` means the account has since been deleted — the
/// FK is ON DELETE SET NULL, and migration 006's trigger permits exactly that
/// one mutation.
pub async fn list_for_vault(
    pool: &PgPool,
    vault_id: Uuid,
    limit: i64,
) -> Result<Vec<AuditRow>, sqlx::Error> {
    sqlx::query_as!(
        AuditRow,
        r#"
        SELECT
            a.id          AS "id!",
            a.event_type  AS "event_type!",
            a.user_id,
            u.email       AS "actor_email?",
            a.metadata,
            a.created_at  AS "created_at!"
        FROM audit_events a
        LEFT JOIN users u ON u.id = a.user_id
        WHERE a.vault_id = $1
        ORDER BY a.created_at DESC
        LIMIT $2
        "#,
        vault_id,
        limit,
    )
    .fetch_all(pool)
    .await
}
