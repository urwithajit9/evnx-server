// src/state.rs

use sqlx::PgPool;
use std::sync::Arc;
use crate::config::Config;

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

    /// Application configuration loaded from environment variables.
    pub config: Arc<Config>,
    // Redis client added in Week 4
    // Email service added in Week 7
    // S3 storage service added in Week 7
}

impl AppState {
    pub fn new(db: PgPool, config: Config) -> Self {
        Self {
            db,
            config: Arc::new(config),
        }
    }
}