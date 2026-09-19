// src/services/email.rs

//! Transactional email.
//!
//! Two transports, chosen by configuration and never inferred:
//!
//! - [`Transport::Resend`] — the real thing, used everywhere but local dev.
//! - [`Transport::Log`] — writes the message to the log instead of sending it,
//!   so a developer without a mailbox can still follow a verification link.
//!
//! The log transport prints a **live verification token**. `Config::from_env()`
//! refuses it outside `ENVIRONMENT=development`, which is what keeps that token
//! out of staging and production logs.

use reqwest::Client;
use serde::Serialize;

use crate::config::{Config, EmailTransport};

enum Transport {
    Resend { client: Client, api_key: String },
    Log,
}

pub struct EmailService {
    transport: Transport,
    from: String,
    /// Public base URL of this API — the verification link is built from it.
    public_api_url: String,
    public_app_url: Option<String>,
}

#[derive(Serialize)]
struct ResendRequest<'a> {
    from: &'a str,
    to: Vec<&'a str>,
    subject: &'a str,
    html: String,
}

impl EmailService {
    pub fn from_config(config: &Config) -> Self {
        let transport = match config.email_transport {
            EmailTransport::Resend => Transport::Resend {
                client: Client::new(),
                api_key: config.resend_api_key.clone(),
            },
            EmailTransport::Log => Transport::Log,
        };

        Self {
            transport,
            from: config.email_from.clone(),
            public_api_url: config.public_api_url.trim_end_matches('/').to_string(),
            public_app_url: config.public_app_url.clone(),
        }
    }

    /// Name of the active transport, for startup logging.
    pub fn transport_name(&self) -> &'static str {
        match self.transport {
            Transport::Resend { .. } => "resend",
            Transport::Log => "log (development only)",
        }
    }

    /// The URL a user clicks to verify their address.
    ///
    /// Prefers the dashboard when `PUBLIC_APP_URL` is configured. The token is a
    /// bearer credential, and sending it to the API in a query string writes it
    /// into access logs and any proxy in front of them; the dashboard is a static
    /// export with no server-side logging at all, and it POSTs the token in a
    /// body from there.
    ///
    /// Falls back to the API link when unset, so a deployment without a dashboard
    /// keeps working unchanged. Both endpoints redeem through the same
    /// transactional path, so links already in inboxes stay valid either way.
    ///
    /// The trailing slash on `/verify-email/` matters: the dashboard is exported
    /// with `trailingSlash: true`, and the unslashed form costs a redirect that
    /// some mail clients will not follow.
    fn verification_link(&self, token: &str) -> String {
        match &self.public_app_url {
            Some(app) => format!("{app}/verify-email/?token={token}"),
            None => format!(
                "{}/api/v1/auth/verify-email?token={}",
                self.public_api_url, token
            ),
        }
    }

    pub async fn send_verification(&self, to: &str, token: &str) -> Result<(), EmailError> {
        let link = self.verification_link(token);
        let html = format!(
            r#"
            <div style="font-family:monospace;max-width:560px;margin:40px auto;padding:32px;background:#0f0f1a;color:#e6e6e6;border-radius:12px;border:1px solid #2a2a3e">
              <h1 style="color:#e94560;font-size:22px;margin-bottom:8px">evnx Cloud</h1>
              <p style="color:#a0a0b8;margin-bottom:24px">Verify your email to access your vaults.</p>
              <a href="{link}" style="display:inline-block;background:#e94560;color:white;padding:12px 28px;border-radius:6px;text-decoration:none;font-weight:bold">Verify Email</a>
              <p style="margin-top:24px;color:#666;font-size:12px">Expires in 24 hours.</p>
            </div>
        "#
        );
        self.send(to, "Verify your evnx account", &html, Some(&link))
            .await
    }

    /// Tell someone their account was just signed into.
    ///
    /// ─── Why this does not say where the login came from ─────────────────────
    ///
    /// ⚠️ The obvious content — a city, an IP — does not exist to send. evnx
    /// hashes client IPs deliberately (`audit_events.ip_hash`), and an earlier
    /// version of this function rendered that hash directly: `IP hash: a3f9c2…`.
    /// A BLAKE3 digest tells a person nothing and offers no action, so it was
    /// alarming and useless at once.
    ///
    /// What can honestly be offered instead is a **session id**, which the
    /// recipient can match against Settings → Sessions and revoke. That turns
    /// "something happened" into "here is the thing, here is the button".
    ///
    /// ─── Why it is sent at login and not at refresh ──────────────────────────
    ///
    /// `issue_token_pair` is shared with the token-refresh path, which runs every
    /// fifteen minutes. Hooking the helper would have emailed accordingly. The
    /// two real login handlers call this instead.
    pub async fn send_login_alert(
        &self,
        to: &str,
        session_id: &str,
        when: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), EmailError> {
        // First segment of the UUID: enough to match against the session list,
        // short enough to read in a notification.
        let short = session_id.split('-').next().unwrap_or(session_id);
        let sessions_link = self
            .public_app_url
            .as_deref()
            .map(|base| format!("{}/settings/", base.trim_end_matches('/')));

        let action = match &sessions_link {
            Some(link) => format!(
                r#"<p style="margin-top:20px"><a href="{link}" style="color:#E8652A">Review your sessions</a> — revoking one signs that device out immediately.</p>"#
            ),
            // No dashboard configured: name the CLI instead of linking nowhere.
            None => r#"<p style="margin-top:20px">Run <code>evnx auth sessions list</code> to review, and <code>evnx auth sessions revoke-others</code> if this was not you.</p>"#.to_string(),
        };

        let html = format!(
            r#"
            <div style="font-family:ui-monospace,monospace;max-width:560px;margin:40px auto;padding:32px;background:#0d1117;color:#E6EDF3;border-radius:12px;border:1px solid #30363d">
              <h2 style="color:#E8652A;margin-top:0">New sign-in to evnx</h2>
              <p>Your account was signed into on <strong>{when}</strong>.</p>
              <p style="color:#8B949E">Session <code>{short}</code></p>
              {action}
              <p style="margin-top:24px;color:#8B949E;font-size:12px">
                If this was you, nothing to do. evnx cannot see where a sign-in came
                from — client addresses are hashed before they are stored — so this
                notice carries the session rather than a location.
              </p>
            </div>
        "#,
            when = when.format("%d %b %Y at %H:%M UTC"),
        );

        self.send(to, "New sign-in to your evnx account", &html, None)
            .await
    }

    /// `dev_link` is surfaced by the log transport so a local developer can click
    /// through. It is never logged by the Resend transport.
    async fn send(
        &self,
        to: &str,
        subject: &str,
        html: &str,
        dev_link: Option<&str>,
    ) -> Result<(), EmailError> {
        match &self.transport {
            Transport::Log => {
                match dev_link {
                    Some(link) => tracing::info!(
                        recipient = %to,
                        subject = %subject,
                        "[dev email] {link}"
                    ),
                    None => tracing::info!(
                        recipient = %to,
                        subject = %subject,
                        "[dev email] (no link)"
                    ),
                }
                Ok(())
            }
            Transport::Resend { client, api_key } => {
                let res = client
                    .post("https://api.resend.com/emails")
                    .header("Authorization", format!("Bearer {api_key}"))
                    .json(&ResendRequest {
                        from: &self.from,
                        to: vec![to],
                        subject,
                        html: html.to_string(),
                    })
                    .send()
                    .await
                    .map_err(EmailError::Http)?;

                if !res.status().is_success() {
                    let status = res.status();
                    // Resend echoes the payload on some errors; keep only the status
                    // so a verification link can never reach the logs this way.
                    return Err(EmailError::Api(status.as_u16()));
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EmailError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Resend rejected the message with status {0}")]
    Api(u16),
}
