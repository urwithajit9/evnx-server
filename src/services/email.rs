// src/services/email.rs

use reqwest::Client;
use serde::Serialize;

#[derive(Clone)]
pub struct EmailService {
    client: Client,
    api_key: String,
    from: String,
    base_url: String,
}

#[derive(Serialize)]
struct ResendRequest<'a> {
    from: &'a str,
    to: Vec<&'a str>,
    subject: &'a str,
    html: String,
}

impl EmailService {
    pub fn new(api_key: String, from: String, base_url: String) -> Self {
        Self {
            client: Client::new(),
            api_key,
            from,
            base_url,
        }
    }

    pub async fn send_verification(&self, to: &str, token: &str) -> Result<(), EmailError> {
        let link = format!("{}/auth/verify-email?token={}", self.base_url, token);
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
        self.send(to, "Verify your evnx account", &html).await
    }

    pub async fn send_login_alert(&self, to: &str, ip: &str) -> Result<(), EmailError> {
        let html = format!(
            r#"
            <div style="font-family:monospace;max-width:560px;margin:40px auto;padding:32px;background:#0f0f1a;color:#e6e6e6;border-radius:12px;border:1px solid #f59e0b">
              <h2 style="color:#f59e0b">New Login Detected</h2>
              <p>IP hash: <code>{ip}</code></p>
              <p>If this wasn't you, <a href="{}/settings/sessions" style="color:#e94560">revoke all sessions</a>.</p>
            </div>
        "#,
            self.base_url
        );
        self.send(to, "New login to your evnx account", &html).await
    }

    async fn send(&self, to: &str, subject: &str, html: &str) -> Result<(), EmailError> {
        let res = self
            .client
            .post("https://api.resend.com/emails")
            .header("Authorization", format!("Bearer {}", self.api_key))
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
            let body = res.text().await.unwrap_or_default();
            return Err(EmailError::Api(body));
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EmailError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Resend API error: {0}")]
    Api(String),
}
