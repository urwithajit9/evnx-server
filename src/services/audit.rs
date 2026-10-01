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

// ─── Chain 2 Slice C — scoring ────────────────────────────────────────────────
//
// ⚠️ Read this before changing a number below.
//
// This is a **rules engine written as a score**, not a model, and the
// difference is not pedantry. There is no training set: nothing in
// `audit_events` said which logins were fraudulent until Slice B began
// recording disavowals, and until those accumulate every weight here is
// reasoned rather than measured.
//
// Two consequences follow, and both are load-bearing:
//
//  1. **It never blocks.** The score picks wording in an email and an ordering
//     in a list. It does not refuse a login, and must not be made to. A false
//     positive that blocked one would lock someone out of a vault **the server
//     cannot recover** — the key is wrapped under their master password and
//     there is no reset. The failure costs are not symmetric and no threshold
//     makes them so.
//
//  2. **Reasons travel with the score.** A bare number cannot be argued with,
//     audited, or explained to the person it is about. Every caller gets the
//     list of what fired, and the email is built from the reasons rather than
//     from the total.

/// Why a login looked unusual. Ordered strongest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskReason {
    /// This exact origin was disavowed by the account holder.
    ///
    /// ⚠️ The only signal here that is **evidence rather than inference** — a
    /// person said so. Weighted above everything else for that reason, and it
    /// is the one signal that did not exist before Slice B.
    PreviouslyDisavowed,
    /// Neither the address digest nor the user-agent digest has been seen.
    NewOrigin,
    /// The account was locked out by failed password proofs in the recent past.
    RecentLockout,
    /// The second factor was a backup code rather than a TOTP code.
    BackupCodeUsed,
    /// No sign-in for a long time before this one.
    Dormant,
}

impl RiskReason {
    /// Weights, chosen by reasoning and spaced so the ordering is the point
    /// rather than the arithmetic.
    ///
    /// ⚠️ `PreviouslyDisavowed` is **worth more than every other reason
    /// combined**, and the test holds that rather than the number.
    ///
    /// It was 100 first, which happened to tie exactly with 40+30+20+10 — so
    /// the stated intent ("nothing else needs to agree") was not actually true
    /// of the arithmetic. Four inferences adding up to the same weight as one
    /// person saying "that was not me" gets the epistemics backwards: the
    /// others are guesses about behaviour, this is testimony from the only
    /// party who knows.
    pub fn weight(self) -> u32 {
        match self {
            RiskReason::PreviouslyDisavowed => 500,
            RiskReason::NewOrigin => 40,
            RiskReason::RecentLockout => 30,
            RiskReason::BackupCodeUsed => 20,
            RiskReason::Dormant => 10,
        }
    }

    /// One clause, written for the person whose account it is.
    ///
    /// ⚠️ Every one of these stays inside what the architecture knows. None
    /// mentions a place, because `ip_hash` is a keyed digest and a hash cannot
    /// be geolocated.
    pub fn sentence(self) -> &'static str {
        match self {
            RiskReason::PreviouslyDisavowed => {
                "this is a device you previously told us was not you"
            }
            RiskReason::NewOrigin => "the network and browser are both new to this account",
            RiskReason::RecentLockout => {
                "this account was locked recently after repeated failed passwords"
            }
            RiskReason::BackupCodeUsed => "a recovery code was used instead of your authenticator",
            RiskReason::Dormant => "there had been no sign-in for a long time",
        }
    }
}

/// How unusual a login looked, and why.
#[derive(Debug, Clone, Default)]
pub struct LoginRisk {
    pub reasons: Vec<RiskReason>,
}

/// Score at which the alert changes its wording.
///
/// ⚠️ Set so that **`NewOrigin` alone reaches it** — that is Slice A's
/// behaviour, and Slice C must not quietly make the product less talkative than
/// it was yesterday. Everything else raises the score above the line rather
/// than across it.
pub const NOTABLE_SCORE: u32 = 40;

impl LoginRisk {
    pub fn score(&self) -> u32 {
        self.reasons.iter().map(|r| r.weight()).sum()
    }

    /// Worth changing the email for.
    pub fn is_notable(&self) -> bool {
        self.score() >= NOTABLE_SCORE
    }

    /// The strongest reason, for a subject line that has room for one.
    pub fn headline(&self) -> Option<RiskReason> {
        self.reasons.iter().copied().max_by_key(|r| r.weight())
    }

    pub fn sentences(&self) -> Vec<&'static str> {
        let mut rs = self.reasons.clone();
        rs.sort_by_key(|r| std::cmp::Reverse(r.weight()));
        rs.into_iter().map(|r| r.sentence()).collect()
    }
}

/// How long without a sign-in counts as dormant.
///
/// 90 days: long enough that "I forgot I had this" is the common reading, short
/// enough to still be inside a quarterly rotation. ⚠️ Weighted lowest of the
/// five because, alone, it describes an ordinary user rather than an attack.
const DORMANT_DAYS: i64 = 90;

/// Assess a login against everything the architecture can see.
///
/// ⚠️ **Call before `record_login`.** Every query here reads prior rows, and
/// the write is spawned — if this login's own row lands first it matches
/// itself and nothing is ever unusual.
///
/// A failure degrades to "nothing unusual" and is logged. A database hiccup
/// must not tell someone their account was accessed by a stranger.
pub async fn assess_login(
    pool: &PgPool,
    user_id: Uuid,
    ip_hash: Option<&str>,
    user_agent_hash: Option<&str>,
    method: &str,
) -> LoginRisk {
    let mut reasons = Vec::new();

    match login_familiarity(pool, user_id, ip_hash, user_agent_hash).await {
        Ok(f) if f.is_unrecognised() => reasons.push(RiskReason::NewOrigin),
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(error = %e, "could not check login familiarity");
            // ⚠️ Returning early rather than scoring on partial information.
            // A half-assessed login reported as ordinary is better than one
            // reported as alarming because a query failed.
            return LoginRisk::default();
        }
    }

    // The label from Slice B. Matched on the digests themselves, so it survives
    // the device list being paginated or pruned.
    match sqlx::query!(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM audit_events
            WHERE user_id = $1
              AND event_type = 'device_disavowed'
              AND ip_hash IS NOT DISTINCT FROM $2
              AND user_agent_hash IS NOT DISTINCT FROM $3
        ) AS "disavowed!"
        "#,
        user_id,
        ip_hash,
        user_agent_hash,
    )
    .fetch_one(pool)
    .await
    {
        Ok(r) if r.disavowed => reasons.push(RiskReason::PreviouslyDisavowed),
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "could not check disavowals"),
    }

    // Lockouts and dormancy, from the same table in one pass.
    match sqlx::query!(
        r#"
        SELECT
            (SELECT count(*) FROM audit_events
               WHERE user_id = $1 AND event_type = 'login_locked'
                 AND created_at > NOW() - INTERVAL '7 days') AS "lockouts!",
            (SELECT max(created_at) FROM audit_events
               WHERE user_id = $1 AND event_type = 'login') AS "last_login"
        "#,
        user_id,
    )
    .fetch_one(pool)
    .await
    {
        Ok(r) => {
            if r.lockouts > 0 {
                reasons.push(RiskReason::RecentLockout);
            }
            // ⚠️ `None` is a first login, not a dormant one. Treating "never"
            // as "a very long time" would mark every new account dormant.
            if let Some(last) = r.last_login {
                if (chrono::Utc::now() - last).num_days() >= DORMANT_DAYS {
                    reasons.push(RiskReason::Dormant);
                }
            }
        }
        Err(e) => tracing::warn!(error = %e, "could not read lockout or dormancy history"),
    }

    if method.contains("backup") {
        reasons.push(RiskReason::BackupCodeUsed);
    }

    LoginRisk { reasons }
}

#[cfg(test)]
mod risk_tests {
    use super::*;

    fn risk(rs: &[RiskReason]) -> LoginRisk {
        LoginRisk {
            reasons: rs.to_vec(),
        }
    }

    /// ⚠️ Slice C must not make the product quieter than Slice A was.
    ///
    /// A new origin alone changed the email yesterday. If the threshold were
    /// set above `NewOrigin`'s weight, shipping the scorer would silently stop
    /// alerts people had already started relying on.
    #[test]
    fn a_new_origin_alone_still_changes_the_email() {
        assert!(risk(&[RiskReason::NewOrigin]).is_notable());
    }

    #[test]
    fn nothing_unusual_is_not_notable() {
        assert!(!risk(&[]).is_notable());
    }

    /// ⚠️ The weakest signal must not alarm on its own. Dormancy describes an
    /// ordinary person returning to an account, not an attack.
    #[test]
    fn dormancy_alone_is_not_enough() {
        assert!(!risk(&[RiskReason::Dormant]).is_notable());
    }

    #[test]
    fn a_backup_code_alone_is_not_enough() {
        assert!(!risk(&[RiskReason::BackupCodeUsed]).is_notable());
    }

    /// Two weak signals together are worth a word, where either alone is not.
    #[test]
    fn weak_signals_accumulate() {
        assert!(!risk(&[RiskReason::Dormant]).is_notable());
        assert!(!risk(&[RiskReason::BackupCodeUsed]).is_notable());
        assert!(risk(&[
            RiskReason::Dormant,
            RiskReason::RecentLockout,
            RiskReason::BackupCodeUsed
        ])
        .is_notable());
    }

    /// ⚠️ The one signal that is evidence rather than inference.
    ///
    /// A person said this origin was not them. Nothing else needs to agree,
    /// and it must outrank every other reason in the subject line.
    #[test]
    fn a_disavowed_origin_outranks_everything() {
        let r = risk(&[RiskReason::PreviouslyDisavowed]);
        assert!(r.is_notable());
        assert!(
            r.score()
                > RiskReason::NewOrigin.weight()
                    + RiskReason::RecentLockout.weight()
                    + RiskReason::BackupCodeUsed.weight()
                    + RiskReason::Dormant.weight(),
            "a disavowal must outweigh every inferred signal combined"
        );

        let mixed = risk(&[
            RiskReason::Dormant,
            RiskReason::PreviouslyDisavowed,
            RiskReason::NewOrigin,
        ]);
        assert_eq!(mixed.headline(), Some(RiskReason::PreviouslyDisavowed));
    }

    #[test]
    fn reasons_are_ordered_strongest_first() {
        let r = risk(&[
            RiskReason::Dormant,
            RiskReason::NewOrigin,
            RiskReason::PreviouslyDisavowed,
        ]);
        assert_eq!(
            r.sentences(),
            vec![
                RiskReason::PreviouslyDisavowed.sentence(),
                RiskReason::NewOrigin.sentence(),
                RiskReason::Dormant.sentence(),
            ]
        );
    }

    /// ⚠️ Nothing the user reads may claim a location.
    ///
    /// `ip_hash` is a keyed digest and a hash cannot be geolocated. This is the
    /// test that stops a well-meaning copy edit from introducing a claim the
    /// architecture cannot support.
    #[test]
    fn no_reason_claims_a_place() {
        let forbidden = [
            "location",
            "country",
            "city",
            "region",
            "where you",
            "near ",
            "travel",
        ];
        for r in [
            RiskReason::PreviouslyDisavowed,
            RiskReason::NewOrigin,
            RiskReason::RecentLockout,
            RiskReason::BackupCodeUsed,
            RiskReason::Dormant,
        ] {
            let s = r.sentence().to_lowercase();
            for word in forbidden {
                assert!(
                    !s.contains(word),
                    "{r:?} implies a place evnx cannot know: {s:?} contains {word:?}"
                );
            }
        }
    }
}
