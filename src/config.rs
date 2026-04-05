// src/config.rs

use std::env;

/// All configuration loaded from environment variables at startup.
/// Missing required variables cause `Config::from_env()` to return an error,
/// which terminates the server before it accepts any requests.
#[derive(Clone, Debug)]
pub struct Config {
    // Server
    pub host: String,
    pub port: u16,
    pub environment: Environment,

    // Database
    pub database_url: String,
    pub database_max_connections: u32,

    // Redis
    pub redis_url: String,

    // JWT (added Week 5 — placeholder now)
    pub jwt_secret: String,
    pub jwt_expiry_minutes: i64,
    pub refresh_token_expiry_days: i64,

    // Frontend (for CORS)
    pub frontend_url: String,

    // Email (Resend)
    pub resend_api_key: String,
    pub email_from: String,

    // S3 (blob storage)
    pub s3_bucket: String,
    pub s3_region: String,
    pub s3_endpoint: Option<String>, // None = AWS; Some = LocalStack/MinIO/R2

    // AWS credentials (used by S3 client)
    pub aws_access_key_id: String,
    pub aws_secret_access_key: String,

    // Security
    pub max_request_size_kb: u64,
}

/// Application environment — affects logging verbosity and some behaviors.
#[derive(Clone, Debug, PartialEq)]
pub enum Environment {
    Development,
    Staging,
    Production,
}

impl Environment {
    fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "staging"    => Self::Staging,
            "production" => Self::Production,
            _            => Self::Development,
        }
    }
}

impl Config {
    /// Load all configuration from environment variables.
    ///
    /// Call this ONCE at startup in `main()` — before creating any services.
    /// Returns an error listing ALL missing required variables (not just the first one).
    pub fn from_env() -> Result<Self, ConfigError> {
        // dotenvy::dotenv() loads .env file — call this before any env::var()
        // It's safe to call even if .env doesn't exist (returns Ok in that case)
        let _ = dotenvy::dotenv();

        let mut missing: Vec<&str> = Vec::new();

        macro_rules! require {
            ($key:expr) => {
                match env::var($key) {
                    Ok(v) if !v.is_empty() => v,
                    _ => {
                        missing.push($key);
                        String::new()
                    }
                }
            };
        }

        macro_rules! optional {
            ($key:expr, $default:expr) => {
                env::var($key).unwrap_or_else(|_| $default.to_string())
            };
        }

        let database_url = require!("DATABASE_URL");
        let redis_url    = require!("REDIS_URL");
        let jwt_secret   = require!("JWT_SECRET");
        let frontend_url = require!("FRONTEND_URL");
        let resend_api_key = require!("RESEND_API_KEY");
        let email_from   = require!("EMAIL_FROM");
        let s3_bucket    = require!("S3_BUCKET");
        let s3_region    = require!("S3_REGION");
        let aws_access_key_id     = require!("AWS_ACCESS_KEY_ID");
        let aws_secret_access_key = require!("AWS_SECRET_ACCESS_KEY");

        if !missing.is_empty() {
            return Err(ConfigError::MissingVariables(missing.iter().map(|s| s.to_string()).collect()));
        }

        Ok(Config {
            host: optional!("SERVER_HOST", "0.0.0.0"),
            port: optional!("SERVER_PORT", "8080").parse().unwrap_or(8080),
            environment: Environment::from_str(&optional!("ENVIRONMENT", "development")),
            database_url,
            database_max_connections: optional!("DATABASE_MAX_CONNECTIONS", "20")
                .parse().unwrap_or(20),
            redis_url,
            jwt_secret,
            jwt_expiry_minutes: optional!("JWT_EXPIRY_MINUTES", "15").parse().unwrap_or(15),
            refresh_token_expiry_days: optional!("REFRESH_TOKEN_EXPIRY_DAYS", "30").parse().unwrap_or(30),
            frontend_url,
            resend_api_key,
            email_from,
            s3_bucket,
            s3_region,
            s3_endpoint: env::var("S3_ENDPOINT").ok().filter(|s| !s.is_empty()),
            aws_access_key_id,
            aws_secret_access_key,
            max_request_size_kb: optional!("MAX_REQUEST_SIZE_KB", "64").parse().unwrap_or(64),
        })
    }

    pub fn is_production(&self) -> bool {
        self.environment == Environment::Production
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Missing required environment variables: {}", .0.join(", "))]
    MissingVariables(Vec<String>),
}