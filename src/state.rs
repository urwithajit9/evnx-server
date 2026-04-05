// src/state.rs

use crate::config::Config;
use crate::services::cache::CacheService;
use crate::services::storage;
use redis::aio::ConnectionManager;
use sqlx::PgPool;
use std::sync::Arc;

/// Shared application state — passed to every request handler via Axum's State extractor.
///
/// All fields must be cheaply cloneable. Use Arc<T> for anything expensive.
///
/// ## How Axum uses this:
/// ```
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
    /// Redis connection manager — shared across all requests.
    pub redis: ConnectionManager,
    pub jwt: Arc<JwtService>,
    // Email service added in Week 7
    /// Storage service for encrypted blobs. Need to migrate to Hetzner Spaces o
    pub storage: Arc<StorageService>,
}

impl AppState {
    pub fn new(
        db: PgPool,
        cache: CacheService,
        redis: ConnectionManager,
        config: Config,
        jwt: JwtService,
        storage: StorageService,
    ) -> Self {
        Self {
            db,
            cache: CacheService::new(redis.clone()),
            redis,
            config: Arc::new(config),
            jwt,
            storage,
        }
    }
}
