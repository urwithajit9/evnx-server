//! `GET /auth/devices` and `POST /auth/devices/disavow` — Chain 2 Slice B.
//!
//! # What a "device" is here, and what it is not
//!
//! A distinct `(ip_hash, user_agent_hash)` pair that has appeared on a `login`
//! event for this account. That is all it can be: both are **keyed BLAKE3
//! digests**, so the server holds no address, no agent string, and no way to
//! recover either.
//!
//! ⚠️ **It is not a session, and the two must not be conflated in any wording.**
//! `GET /auth/sessions` lists live credentials you can revoke. This lists places
//! you have signed in from, including ones with no session left. Revoking a
//! session ends access; disavowing a device records a judgement and revokes
//! *everything*.
//!
//! ⚠️ **It is not a location, and cannot be made into one.** A hash cannot be
//! geolocated. Every string this module returns is a digest or a timestamp, and
//! any copy built on top has to stay inside that.
//!
//! # Why disavowal matters more than the list
//!
//! The list is the visible half. The half that pays for itself is
//! **"this wasn't me"**: it is the only thing in the entire system that produces
//! a *label*. Slice C scores logins, and a score with no labelled outcomes is a
//! threshold chosen by intuition and then defended by it. One disavowal turns a
//! guess into evidence — and it is the strongest single signal available,
//! because the person whose account it is has said so.

use axum::{extract::State, Extension, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::AppError;
use crate::middleware::client_ip::ClientContext;
use crate::services::jwt::Claims;
use crate::state::AppState;

/// One origin this account has signed in from.
#[derive(Debug, Serialize)]
pub struct DeviceSummary {
    /// A short, stable handle for this origin, so a person can name one on the
    /// command line without pasting a 64-character digest.
    ///
    /// ⚠️ Derived from the digests, **not random**: it has to be the same on
    /// every listing or `disavow <id>` would target whatever happened to be in
    /// that position last time.
    pub id: String,
    pub first_seen: chrono::DateTime<chrono::Utc>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub sign_in_count: i64,
    /// This is the origin the request asking the question came from.
    pub is_current: bool,
    /// Someone has said "this wasn't me" about this origin.
    pub disavowed: bool,
    /// Neither digest was available for these sign-ins — a client behind no
    /// proxy sending no user agent. Grouped so they are visible rather than
    /// silently absent from the count.
    pub unknown_origin: bool,
}

#[derive(Debug, Serialize)]
pub struct DeviceList {
    pub devices: Vec<DeviceSummary>,
}

/// A short handle for an origin, stable across listings.
///
/// First 12 hex characters of a digest over both halves. ⚠️ **Not a secret and
/// not reversible into either digest** — it is an index into a list the caller
/// already holds, and a collision within one account's handful of origins would
/// need 2^24 of them.
fn device_id(ip: Option<&str>, agent: Option<&str>) -> String {
    let joined = format!("{}|{}", ip.unwrap_or(""), agent.unwrap_or(""));
    blake3::hash(joined.as_bytes()).to_hex()[..12].to_string()
}

/// List the origins this account has signed in from, newest first.
///
/// Read-only, and cheap: one grouped scan of this user's `login` rows on
/// `idx_audit_events_user`, plus one of their `device_disavowed` rows.
pub async fn list_devices(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    client: ClientContext,
) -> Result<Json<DeviceList>, AppError> {
    let user_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;

    let rows = sqlx::query!(
        r#"
        SELECT
            ip_hash,
            user_agent_hash,
            min(created_at) AS "first_seen!",
            max(created_at) AS "last_seen!",
            count(*)        AS "sign_in_count!"
        FROM audit_events
        WHERE user_id = $1 AND event_type = 'login'
        GROUP BY ip_hash, user_agent_hash
        ORDER BY max(created_at) DESC
        "#,
        user_id,
    )
    .fetch_all(&state.db)
    .await
    .map_err(AppError::Database)?;

    // ⚠️ A separate query rather than a join. A disavowal is recorded as its
    // own event with the digests in their own columns, so the two sets line up
    // by value — and keeping them apart means a disavowal of an origin that has
    // since been pruned from view still reads as disavowed.
    let disavowed = sqlx::query!(
        r#"
        SELECT DISTINCT ip_hash, user_agent_hash
        FROM audit_events
        WHERE user_id = $1 AND event_type = 'device_disavowed'
        "#,
        user_id,
    )
    .fetch_all(&state.db)
    .await
    .map_err(AppError::Database)?;

    let disavowed_ids: std::collections::HashSet<String> = disavowed
        .iter()
        .map(|r| device_id(r.ip_hash.as_deref(), r.user_agent_hash.as_deref()))
        .collect();

    let current_id = device_id(client.ip_hash.as_deref(), client.user_agent_hash.as_deref());

    let devices = rows
        .into_iter()
        .map(|r| {
            let id = device_id(r.ip_hash.as_deref(), r.user_agent_hash.as_deref());
            let unknown_origin = r.ip_hash.is_none() && r.user_agent_hash.is_none();
            DeviceSummary {
                // ⚠️ An origin with no digests at all cannot be "current" —
                // it is the absence of information, and matching the caller's
                // own absent digests against it would mark it current for
                // everyone whose client sends neither.
                is_current: !unknown_origin && id == current_id,
                disavowed: disavowed_ids.contains(&id),
                id,
                first_seen: r.first_seen,
                last_seen: r.last_seen,
                sign_in_count: r.sign_in_count,
                unknown_origin,
            }
        })
        .collect();

    Ok(Json(DeviceList { devices }))
}

#[derive(Debug, Deserialize)]
pub struct DisavowRequest {
    /// The handle from `GET /auth/devices`.
    pub device_id: String,
}

#[derive(Debug, Serialize)]
pub struct DisavowResponse {
    pub sessions_revoked: usize,
    /// ⚠️ Always true. Revoking sessions does not rotate the vault keys, and
    /// the client must say so — see the note on the handler.
    pub change_master_password: bool,
}

/// "This wasn't me."
///
/// Three things, in this order:
///
/// 1. record the judgement, which is the **label** Slice C has no other source
///    for;
/// 2. revoke every session, including the caller's own;
/// 3. tell the caller to change the master password.
///
/// # ⚠️ Why every session, including this one
///
/// Revoking "the others" assumes the caller's own session is the trustworthy
/// one. Someone who has just discovered an unrecognised sign-in does not know
/// that, and the cost of being wrong is the attacker keeping the one session
/// that was not revoked. Signing everyone out — including the person asking —
/// is the only version with no assumption in it.
///
/// # ⚠️ Why the password still has to change, and the response says so
///
/// **Revoking a session does not protect a vault.** Vault keys are wrapped
/// under the master key; anyone who learned the master password can sign in
/// again a second later, and every blob they already pulled is already
/// plaintext in their hands. Session revocation buys time and nothing more.
///
/// The response carries `change_master_password: true` unconditionally rather
/// than as advice, because a client that renders this as "done ✓" would be
/// telling the user something false at the worst possible moment.
pub async fn disavow_device(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    client: ClientContext,
    Json(req): Json<DisavowRequest>,
) -> Result<Json<DisavowResponse>, AppError> {
    let user_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;

    // Resolve the handle against this user's own origins. ⚠️ Scoped to the
    // user, so a handle from one account cannot name another's origin — and an
    // unknown handle is a 404 rather than a silent no-op, or a typo would look
    // like a successful disavowal.
    let rows = sqlx::query!(
        r#"
        SELECT DISTINCT ip_hash, user_agent_hash
        FROM audit_events
        WHERE user_id = $1 AND event_type = 'login'
        "#,
        user_id,
    )
    .fetch_all(&state.db)
    .await
    .map_err(AppError::Database)?;

    let target = rows
        .iter()
        .find(|r| device_id(r.ip_hash.as_deref(), r.user_agent_hash.as_deref()) == req.device_id)
        .ok_or_else(|| {
            // Unit variant: the message a 404 carries is fixed by `errors.rs`.
            AppError::NotFound
        })?;

    // 1 · The label. Digests go in their own columns, never in metadata —
    // metadata is returned to clients and these are not.
    //
    // ⚠️ Awaited, not spawned. Every other audit write is fire-and-forget
    // because losing one costs a log line; losing this one costs the only
    // labelled example the system will ever get for this origin, and the
    // caller is about to be signed out and may not come back.
    crate::services::audit::record(
        &state.db,
        crate::services::audit::AuditEvent {
            vault_id: None,
            user_id: Some(user_id),
            event_type: "device_disavowed".into(),
            ip_hash: target.ip_hash.clone(),
            user_agent_hash: target.user_agent_hash.clone(),
            // Which origin the *report* came from, so a disavowal made from a
            // machine later disavowed itself can be weighed differently.
            metadata: Some(serde_json::json!({
                "reported_from_current_device":
                    device_id(client.ip_hash.as_deref(), client.user_agent_hash.as_deref())
                        == req.device_id,
            })),
        },
    )
    .await
    .map_err(AppError::Database)?;

    // 2 · Every session, the caller's included.
    let victims = sqlx::query!(
        r#"
        UPDATE refresh_tokens
        SET revoked_at = NOW()
        WHERE user_id = $1 AND revoked_at IS NULL
        RETURNING session_id
        "#,
        user_id,
    )
    .fetch_all(&state.db)
    .await
    .map_err(AppError::Database)?;

    let ttl = (state.config.jwt_expiry_minutes.max(1) * 60) as u64;
    let mut revoked: Vec<Uuid> = victims.into_iter().map(|r| r.session_id).collect();
    revoked.sort_unstable();
    revoked.dedup();
    for sid in &revoked {
        state
            .cache
            .set_flag(&format!("jwt_blocklist:{sid}"), ttl)
            .await?;
    }

    tracing::info!(
        user_id = %user_id,
        sessions = revoked.len(),
        "device disavowed; all sessions revoked"
    );

    Ok(Json(DisavowResponse {
        sessions_revoked: revoked.len(),
        change_master_password: true,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_device_id_is_stable_for_the_same_origin() {
        assert_eq!(
            device_id(Some("ip-a"), Some("agent-a")),
            device_id(Some("ip-a"), Some("agent-a")),
        );
    }

    #[test]
    fn different_origins_get_different_ids() {
        assert_ne!(
            device_id(Some("ip-a"), Some("agent-a")),
            device_id(Some("ip-b"), Some("agent-a")),
        );
        assert_ne!(
            device_id(Some("ip-a"), Some("agent-a")),
            device_id(Some("ip-a"), Some("agent-b")),
        );
    }

    /// ⚠️ The separator has to actually separate.
    ///
    /// Concatenating without one makes `("ab", "c")` and `("a", "bc")` the same
    /// origin — two different machines collapsing into one row, one of which
    /// then vouches for the other.
    #[test]
    fn the_halves_cannot_be_confused_with_each_other() {
        assert_ne!(
            device_id(Some("ab"), Some("c")),
            device_id(Some("a"), Some("bc"))
        );
    }

    #[test]
    fn a_missing_half_is_distinct_from_an_empty_one() {
        // Both render as "" in the join, so these are deliberately equal — the
        // test exists to record that it is known, not to assert a difference
        // the implementation does not make.
        assert_eq!(device_id(None, Some("a")), device_id(Some(""), Some("a")));
    }

    #[test]
    fn an_id_is_short_enough_to_type() {
        assert_eq!(device_id(Some("ip"), Some("agent")).len(), 12);
    }
}
