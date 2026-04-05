// src/services/jwt.rs

use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Claims stored inside every JWT access token.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String, // user UUID
    pub sid: String, // session UUID (used for revocation)
    pub email_verified: bool,
    pub scope: String, // "user" | "ci_token"
    pub iat: i64,      // issued at (Unix timestamp)
    pub exp: i64,      // expiry (Unix timestamp)
}

impl Claims {
    pub fn user_id(&self) -> Result<Uuid, uuid::Error> {
        Uuid::parse_str(&self.sub)
    }

    pub fn session_id(&self) -> Result<Uuid, uuid::Error> {
        Uuid::parse_str(&self.sid)
    }
}

pub struct JwtService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    expiry_minutes: i64,
}

impl JwtService {
    /// Create from the raw JWT secret string.
    /// Secret must be ≥ 512 bits (64 hex chars / 32 bytes).
    pub fn new(secret: &str, expiry_minutes: i64) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            expiry_minutes,
        }
    }

    /// Issue a new access token for a user.
    pub fn issue(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        email_verified: bool,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let now = Utc::now().timestamp();
        let claims = Claims {
            sub: user_id.to_string(),
            sid: session_id.to_string(),
            email_verified,
            scope: "user".into(),
            iat: now,
            exp: now + (self.expiry_minutes * 60),
        };
        encode(&Header::default(), &claims, &self.encoding_key)
    }

    /// Validate and decode a JWT. Returns Err if expired, invalid signature, etc.
    pub fn verify(&self, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        let data = decode::<Claims>(token, &self.decoding_key, &validation)?;
        Ok(data.claims)
    }

    /// How many seconds remain until this token expires.
    pub fn seconds_remaining(claims: &Claims) -> i64 {
        let now = Utc::now().timestamp();
        (claims.exp - now).max(0)
    }

    /// Issue a short-lived TOTP-pending token (5 minutes).
    /// Used between SRP verify and TOTP verify when TOTP is enabled.
    pub fn issue_totp_pending(&self, user_id: Uuid) -> Result<String, jsonwebtoken::errors::Error> {
        let now = Utc::now().timestamp();
        let claims = Claims {
            sub: user_id.to_string(),
            sid: Uuid::new_v4().to_string(), // throwaway session
            email_verified: false,           // not yet fully authenticated
            scope: "totp_pending".into(),
            iat: now,
            exp: now + 300, // 5 minutes
        };
        encode(&Header::default(), &claims, &self.encoding_key)
    }
}
