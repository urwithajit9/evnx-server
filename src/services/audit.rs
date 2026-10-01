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
    client: &crate::middleware::client_ip::ClientContext,
    metadata: serde_json::Value,
) {
    let pool = pool.clone();
    let ip_hash = client.ip_hash.clone();
    let user_agent_hash = client.user_agent_hash.clone();
    tokio::spawn(async move {
        if let Err(e) = record(
            &pool,
            AuditEvent {
                vault_id: Some(vault_id),
                user_id: Some(actor_id),
                event_type: event_type.into(),
                ip_hash,
                user_agent_hash,
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

/// Whether this account has signed in from this origin before.
///
/// # What "recognised" means here, and what it does not
///
/// Two keyed digests — the client address and the user agent — compared against
/// every prior `login` row for this user. Nothing else. There is no location in
/// this, there cannot be, and the wording that reaches a person must not imply
/// one: `ip_hash` is a keyed BLAKE3 digest and **a hash cannot be geolocated**.
///
/// ⚠️ **A `None` digest is not "new".** A request with no peer address and no
/// user-agent header produces `None`, and treating absence as novelty would
/// alarm people over a missing header. Absence is "cannot tell", and a device
/// is only called unrecognised when there is something to compare.
///
/// ⚠️ **Rotating the hash key makes every device new.** The digests are keyed,
/// so a rotation makes old rows incomparable and this returns "unrecognised"
/// for everyone at once. That is why the key is `AUDIT_HASH_KEY` rather than
/// `JWT_SECRET` — see `middleware::client_ip`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginFamiliarity {
    /// This address digest has appeared on a prior `login` for this user.
    pub known_ip: bool,
    /// This user-agent digest has appeared on a prior `login` for this user.
    pub known_agent: bool,
    /// There was something to compare at all.
    pub comparable: bool,
}

impl LoginFamiliarity {
    /// Worth telling the user about.
    ///
    /// Deliberately **both** signals, not either. A user agent alone changes on
    /// every browser update, and alerting on that trains people to ignore the
    /// alert — which is the failure this whole feature exists to undo, since the
    /// alert already fires on every single login.
    pub fn is_unrecognised(&self) -> bool {
        self.comparable && !self.known_ip && !self.known_agent
    }
}

/// Look up whether this origin has been seen for this user before.
///
/// Runs on `idx_audit_events_user`, which already exists —
/// `(user_id, created_at DESC)` — with an equality filter on top. Two `EXISTS`
/// probes rather than one scan, because either column may be `NULL`.
///
/// ⚠️ **Called before the row for *this* login is written.** `record_login` is
/// spawned, so ordering is not guaranteed — the caller must do this lookup
/// first, or the current login matches itself and nothing is ever new.
pub async fn login_familiarity(
    pool: &PgPool,
    user_id: Uuid,
    ip_hash: Option<&str>,
    user_agent_hash: Option<&str>,
) -> Result<LoginFamiliarity, sqlx::Error> {
    if ip_hash.is_none() && user_agent_hash.is_none() {
        return Ok(LoginFamiliarity {
            known_ip: false,
            known_agent: false,
            comparable: false,
        });
    }

    let row = sqlx::query!(
        r#"
        SELECT
            EXISTS (
                SELECT 1 FROM audit_events
                WHERE user_id = $1 AND event_type = 'login' AND ip_hash = $2
            ) AS "known_ip!",
            EXISTS (
                SELECT 1 FROM audit_events
                WHERE user_id = $1 AND event_type = 'login' AND user_agent_hash = $3
            ) AS "known_agent!"
        "#,
        user_id,
        ip_hash,
        user_agent_hash,
    )
    .fetch_one(pool)
    .await?;

    Ok(LoginFamiliarity {
        known_ip: row.known_ip,
        known_agent: row.known_agent,
        comparable: true,
    })
}

/// Record that an account was locked after repeated failed password proofs.
///
/// # Why a lockout, and not every failed attempt
///
/// Failed logins are the stronger signal and also the one **an attacker
/// generates at will**. `audit_events` is append-only by trigger since
/// migration 006 — *nothing prunes it and nothing can* — so a row written per
/// attempt hands an attacker unbounded, permanent control of the table's size.
///
/// One row per lockout keeps the thing worth knowing — *this account is being
/// attacked* — at a rate `srp_lockout` already bounds to one per fifteen
/// minutes per account.
///
/// ⚠️ The obvious middle option — one row per run, updated with a running
/// count — is **unrepresentable**, because the append-only trigger refuses
/// `UPDATE`. That is the trigger doing its job, not a limitation to work
/// around.
///
/// # ⚠️ Only for accounts that exist
///
/// `user_id` is `NonZero`-ish by intent here: the caller must pass a real id.
/// `/srp/init` fabricates a salt and verifier for an unknown address precisely
/// so the server is not an account oracle, and writing "someone tried to sign
/// in as this address and it does not exist" into an append-only table would
/// rebuild that oracle in the database, permanently.
pub fn record_lockout(
    pool: &PgPool,
    user_id: Uuid,
    client: &crate::middleware::client_ip::ClientContext,
    failures: u64,
    window_seconds: u64,
) {
    let pool = pool.clone();
    let ip_hash = client.ip_hash.clone();
    let user_agent_hash = client.user_agent_hash.clone();
    tokio::spawn(async move {
        if let Err(e) = record(
            &pool,
            AuditEvent {
                vault_id: None,
                user_id: Some(user_id),
                event_type: "login_locked".into(),
                ip_hash,
                user_agent_hash,
                // Counts and a duration. No address, no agent string, no email
                // — the digests are in their own columns and are not returned
                // to clients.
                metadata: Some(serde_json::json!({
                    "failures": failures,
                    "window_seconds": window_seconds,
                })),
            },
        )
        .await
        {
            tracing::warn!(error = %e, "could not record a lockout");
        }
    });
}

#[cfg(test)]
mod familiarity_tests {
    use super::*;

    fn f(known_ip: bool, known_agent: bool, comparable: bool) -> LoginFamiliarity {
        LoginFamiliarity {
            known_ip,
            known_agent,
            comparable,
        }
    }

    #[test]
    fn a_wholly_new_origin_is_unrecognised() {
        assert!(f(false, false, true).is_unrecognised());
    }

    #[test]
    fn a_known_origin_is_not() {
        assert!(!f(true, true, true).is_unrecognised());
    }

    /// ⚠️ The rule that keeps the alert worth reading.
    ///
    /// A user agent changes on every browser update. Alerting on that alone
    /// would fire for ordinary people doing ordinary things, and an alert that
    /// cries wolf is the exact failure this feature exists to undo — the alert
    /// already fires on every single login.
    #[test]
    fn a_browser_update_alone_does_not_alarm() {
        assert!(
            !f(true, false, true).is_unrecognised(),
            "same network, new agent — a browser update, not an intrusion"
        );
    }

    /// The mirror case: a known browser on a new network is a train, a café or
    /// a reconnected phone. Common, and not worth an alarm on its own.
    #[test]
    fn a_new_network_alone_does_not_alarm() {
        assert!(!f(false, true, true).is_unrecognised());
    }

    /// ⚠️ Absence is "cannot tell", never "new".
    ///
    /// A request with no peer address and no user-agent header yields two
    /// `None`s. Treating that as novelty would alarm someone over a missing
    /// header — and would fire on every login from any client that sends no
    /// user agent.
    #[test]
    fn nothing_to_compare_is_never_an_alarm() {
        assert!(
            !f(false, false, false).is_unrecognised(),
            "no digests at all must not read as a new device"
        );
    }
}
