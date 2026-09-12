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
    fn verification_link(&self, token: &str) -> String {
        format!(
            "{}/api/v1/auth/verify-email?token={}",
            self.public_api_url, token
        )
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

    /// `ip` must already be a BLAKE3 hash — never a raw address.
    pub async fn send_login_alert(&self, to: &str, ip_hash: &str) -> Result<(), EmailError> {
        let html = format!(
            r#"
            <div style="font-family:monospace;max-width:560px;margin:40px auto;padding:32px;background:#0f0f1a;color:#e6e6e6;border-radius:12px;border:1px solid #f59e0b">
              <h2 style="color:#f59e0b">New Login Detected</h2>
              <p>IP hash: <code>{ip_hash}</code></p>
              <p>If this wasn't you, revoke all sessions from your account settings.</p>
            </div>
        "#
        );
        self.send(to, "New login to your evnx account", &html, None)
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
