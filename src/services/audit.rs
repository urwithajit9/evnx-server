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
