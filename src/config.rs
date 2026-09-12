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

    // Valkey (Redis-compatible; the `redis` crate is the client)
    pub valkey_url: String,

    // JWT (added Week 5 — placeholder now)
    pub jwt_secret: String,
    pub jwt_expiry_minutes: i64,
    pub refresh_token_expiry_days: i64,

    // Frontend (for CORS)
    pub frontend_url: String,

    // Email (Resend)
    pub resend_api_key: String,
    pub email_from: String,
    /// How mail is delivered. `Log` is a development-only transport.
    pub email_transport: EmailTransport,
    /// Public base URL of this API, used to build the email verification link.
    /// Production must set `PUBLIC_API_URL`; the default is only useful locally.
    pub public_api_url: String,

    // Object storage — provider-agnostic, see services/storage.rs
    pub storage_backend: StorageBackend,
    /// Bucket (S3/GCS) or container (Azure). Unused by the `local` backend.
    pub storage_bucket: String,
    /// Custom endpoint for S3-compatible providers (Hetzner, MinIO, R2, …).
    pub storage_endpoint: Option<String>,
    pub storage_region: Option<String>,
    /// Path-style addressing. Required by MinIO and LocalStack; AWS and Hetzner
    /// use virtual-hosted style.
    pub storage_path_style: bool,
    /// Directory used by the `local` backend.
    pub storage_local_path: String,
    /// Optional; when absent, object_store resolves credentials from the
    /// environment or the instance role.
    pub storage_access_key_id: Option<String>,
    pub storage_secret_access_key: Option<String>,

    // Security
    pub max_request_size_kb: u64,
}

/// Where encrypted vault blobs are stored. Named explicitly in configuration —
/// never guessed from an endpoint hostname.
#[derive(Clone, Debug, PartialEq)]
pub enum StorageBackend {
    /// AWS S3 or any S3-compatible service (Hetzner, MinIO, R2, Wasabi, B2).
    S3,
    /// Google Cloud Storage.
    Gcs,
    /// Azure Blob Storage.
    Azure,
    /// Local filesystem — development and tests only; not shared between instances.
    Local,
}

impl StorageBackend {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::S3 => "s3",
            Self::Gcs => "gcs",
            Self::Azure => "azure",
            Self::Local => "local",
        }
    }
}

/// How verification and alert email is delivered.
#[derive(Clone, Debug, PartialEq)]
pub enum EmailTransport {
    /// Send through the Resend API.
    Resend,
    /// **Development only.** Write the message to the log instead of sending it,
    /// so a local developer can follow the verification link without a real
    /// mailbox. `Config::from_env()` refuses this outside `development`, which is
    /// what keeps a live verification token out of staging and production logs.
    Log,
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
            "staging" => Self::Staging,
            "production" => Self::Production,
            _ => Self::Development,
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
        let valkey_url = require!("VALKEY_URL");
        let jwt_secret = require!("JWT_SECRET");
        let frontend_url = require!("FRONTEND_URL");
        let resend_api_key = require!("RESEND_API_KEY");
        let email_from = require!("EMAIL_FROM");

        if !missing.is_empty() {
            return Err(ConfigError::MissingVariables(
                missing.iter().map(|s| s.to_string()).collect(),
            ));
        }

        let environment = Environment::from_str(&optional!("ENVIRONMENT", "development"));

        let storage_backend = match optional!("STORAGE_BACKEND", "s3").to_lowercase().as_str() {
            "s3" => StorageBackend::S3,
            "gcs" => StorageBackend::Gcs,
            "azure" => StorageBackend::Azure,
            "local" => StorageBackend::Local,
            other => {
                return Err(ConfigError::Invalid(format!(
                    "STORAGE_BACKEND must be one of s3, gcs, azure, local — got '{other}'"
                )))
            }
        };

        // A bucket name is meaningless for the local backend and mandatory for
        // every other one.
        let storage_bucket = optional!("STORAGE_BUCKET", "");
        if storage_backend != StorageBackend::Local && storage_bucket.is_empty() {
            missing.push("STORAGE_BUCKET");
        }

        if storage_backend == StorageBackend::Local && environment != Environment::Development {
            return Err(ConfigError::Invalid(format!(
                "STORAGE_BACKEND=local is not shared between instances and is refused \
                 when ENVIRONMENT={environment:?}"
            )));
        }

        let port: u16 = optional!("SERVER_PORT", "8080").parse().unwrap_or(8080);

        // Default to the log transport only in development, where there is no
        // real mailbox. Anywhere else, mail must actually be sent.
        let email_transport = match env::var("EMAIL_TRANSPORT").ok().as_deref() {
            Some("log") => EmailTransport::Log,
            Some("resend") => EmailTransport::Resend,
            Some(other) => {
                return Err(ConfigError::Invalid(format!(
                    "EMAIL_TRANSPORT must be 'resend' or 'log', got '{other}'"
                )))
            }
            None if environment == Environment::Development => EmailTransport::Log,
            None => EmailTransport::Resend,
        };

        // The log transport writes a live verification token to the log. That is
        // an acceptable local-development affordance and nothing else.
        if email_transport == EmailTransport::Log && environment != Environment::Development {
            return Err(ConfigError::Invalid(format!(
                "EMAIL_TRANSPORT=log writes verification tokens to the log and is \
                 refused when ENVIRONMENT={environment:?}"
            )));
        }

        Ok(Config {
            host: optional!("SERVER_HOST", "0.0.0.0"),
            port,
            environment,
            database_url,
            database_max_connections: optional!("DATABASE_MAX_CONNECTIONS", "20")
                .parse()
                .unwrap_or(20),
            valkey_url,
            jwt_secret,
            jwt_expiry_minutes: optional!("JWT_EXPIRY_MINUTES", "15").parse().unwrap_or(15),
            refresh_token_expiry_days: optional!("REFRESH_TOKEN_EXPIRY_DAYS", "30")
                .parse()
                .unwrap_or(30),
            frontend_url,
            resend_api_key,
            email_from,
            email_transport,
            public_api_url: optional!("PUBLIC_API_URL", format!("http://localhost:{port}")),
            storage_backend,
            storage_bucket,
            storage_endpoint: env::var("STORAGE_ENDPOINT").ok().filter(|s| !s.is_empty()),
            storage_region: env::var("STORAGE_REGION").ok().filter(|s| !s.is_empty()),
            storage_path_style: optional!("STORAGE_PATH_STYLE", "false")
                .eq_ignore_ascii_case("true"),
            storage_local_path: optional!("STORAGE_LOCAL_PATH", "./data/blobs"),
            storage_access_key_id: env::var("AWS_ACCESS_KEY_ID").ok().filter(|s| !s.is_empty()),
            storage_secret_access_key: env::var("AWS_SECRET_ACCESS_KEY")
                .ok()
                .filter(|s| !s.is_empty()),
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
    #[error("Invalid configuration: {0}")]
    Invalid(String),
}
