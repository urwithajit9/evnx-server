// src/state.rs

use crate::config::Config;
use crate::services::cache::CacheService;
use crate::services::email::EmailService;
use crate::services::jwt::JwtService;
use crate::services::storage::StorageService;
// The `redis` crate speaks the Valkey wire protocol unchanged — only the
// server binary and the env var name differ.
use redis::aio::ConnectionManager;
use sqlx::PgPool;
use std::sync::Arc;

/// Shared application state — passed to every request handler via Axum's State extractor.
///
/// All fields must be cheaply cloneable. Use Arc<T> for anything expensive.
///
/// ## How Axum uses this:
/// ```text
/// async fn my_handler(State(state): State<AppState>) -> impl IntoResponse {
///     let result = state.db.fetch_one(...).await?;
/// }
/// ```
#[derive(Clone)]
pub struct AppState {
    /// PostgreSQL connection pool — shared across all requests.
    /// `PgPool` is already an Arc internally — safe to clone.
    pub db: PgPool,
    pub cache: CacheService,

    /// Application configuration loaded from environment variables.
    pub config: Arc<Config>,
    /// Valkey connection manager — shared across all requests.
    pub valkey: ConnectionManager,
    pub jwt: Arc<JwtService>,
    /// Transactional email (verification, login alerts).
    pub email: Arc<EmailService>,
    /// Object storage for encrypted blobs.
    pub storage: Arc<StorageService>,
}

impl AppState {
    pub fn new(
        db: PgPool,
        cache: CacheService,
        valkey: ConnectionManager,
        config: Config,
        jwt: JwtService,
        email: EmailService,
        storage: StorageService,
    ) -> Self {
        Self {
            db,
            cache,
            valkey,
            config: Arc::new(config),
            jwt: Arc::new(jwt),
            email: Arc::new(email),
            storage: Arc::new(storage),
        }
    }

    /// Build an `AppState` for integration tests from an existing pool + config.
    ///
    /// Connects to the same Valkey and object storage the binary would, so tests
    /// exercise real cache behaviour (rate limits, JWT blocklist, SRP sessions)
    /// rather than a stub. Not `#[cfg(test)]`: integration tests in `tests/` are
    /// separate crates and cannot see items behind that gate.
    ///
    /// # Panics
    /// If Valkey is unreachable — a test run without infrastructure should fail
    /// loudly rather than silently skip the paths it claims to cover.
    pub async fn new_for_test(db: PgPool, config: Config) -> Self {
        let valkey_client =
            redis::Client::open(config.valkey_url.as_str()).expect("test: invalid VALKEY_URL");
        let valkey = ConnectionManager::new(valkey_client)
            .await
            .expect("test: Valkey unreachable — run `docker compose up -d postgres valkey`");

        let cache = CacheService::new(valkey.clone());
        let jwt = JwtService::new(&config.jwt_secret, config.jwt_expiry_minutes);
        let email = EmailService::from_config(&config);
        let storage = StorageService::from_config(&config).expect("test: storage config");

        Self::new(db, cache, valkey, config, jwt, email, storage)
    }
}
