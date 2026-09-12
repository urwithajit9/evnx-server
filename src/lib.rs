// src/lib.rs

//! evnx-server — the cloud-sync backend for the evnx CLI.
//!
//! This crate builds as **both** a library and a binary. The library exists so
//! integration tests in `tests/` can construct an [`AppState`] and exercise the
//! real router; `src/main.rs` is a thin wrapper that loads config, connects to
//! Postgres and Valkey, and serves [`build_router`].
//!
//! ## Zero-knowledge boundary
//!
//! Nothing in this crate can decrypt user data. It stores SRP verifiers,
//! ciphertext blobs and wrapped vault keys. All plaintext handling lives in
//! `evnx-crypto` on the client.

use axum::Router;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

pub mod config;
pub mod db;
pub mod errors;
pub mod middleware;
pub mod routes;
pub mod services;
pub mod state;

pub use state::AppState;

/// Assemble the full application: routes, CORS, body-size limit, tracing.
///
/// Tests call this rather than [`routes::create_router`] so they exercise the
/// same middleware stack as production.
pub fn build_router(state: AppState) -> Router {
    // Read the limit before `state` is moved into the router.
    let request_size_limit = (state.config.max_request_size_kb * 1024) as usize;

    routes::create_router(state)
        // Reject oversized bodies before parsing them — guards against memory exhaustion.
        .layer(RequestBodyLimitLayer::new(request_size_limit))
        .layer(TraceLayer::new_for_http())
}

/// Liveness probe.
///
/// Deliberately does **not** touch Postgres or Valkey — it answers "is the
/// process up", so an infra blip never takes the container out of rotation.
/// Use a separate readiness probe for dependency health.
pub async fn health_check() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}
