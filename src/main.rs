// src/main.rs

use axum::Router;
use std::net::SocketAddr;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

mod config;
mod db;
mod errors;
mod middleware;
mod routes;
mod services;
mod state;

use config::Config;
use state::AppState;

use crate::services::cache::CacheService;
use crate::services::jwt::JwtService;
use crate::services::storage::StorageService;

#[tokio::main]
async fn main() {
    // Step 1: Initialize logging FIRST — before anything else.
    // RUST_LOG=evnx_server=debug,tower_http=debug controls verbosity.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_env("RUST_LOG")
                .add_directive("evnx_server=info".parse().unwrap()),
        )
        .init();

    tracing::info!("🚀 evnx-server starting up");

    // Step 2: Load config — fails fast if any required env var is missing.
    let config = Config::from_env().unwrap_or_else(|e| {
        tracing::error!("Configuration error: {}", e);
        std::process::exit(1);
    });

    tracing::info!(environment = ?config.environment, "Configuration loaded");

    // Step 3: Connect to PostgreSQL.
    // PgPoolOptions lets you set connection limits.
    let db = sqlx::postgres::PgPoolOptions::new()
        .max_connections(config.database_max_connections)
        .connect(&config.database_url)
        .await
        .unwrap_or_else(|e| {
            tracing::error!("Failed to connect to database: {}", e);
            std::process::exit(1);
        });

    tracing::info!("✓ Database connected");

    let redis_client = redis::Client::open(config.redis_url.as_str()).unwrap_or_else(|e| {
        tracing::error!("Failed to create Redis client: {}", e);
        std::process::exit(1);
    });

    let redis = redis::aio::ConnectionManager::new(redis_client)
        .await
        .unwrap_or_else(|e| {
            tracing::error!("Failed to connect to Redis: {}", e);
            std::process::exit(1);
        });

    tracing::info!("✓ Redis connected");

    // Step 4: Run pending migrations automatically on startup.
    // Safe to run repeatedly — sqlx tracks what's been applied.
    sqlx::migrate!("./migrations")
        .run(&db)
        .await
        .unwrap_or_else(|e| {
            tracing::error!("Migration failed: {}", e);
            std::process::exit(1);
        });

    tracing::info!("✓ Migrations applied");
    let jwt = JwtService::new(&config.jwt_secret, config.jwt_expiry_minutes);

    // let storage = StorageService::new(
    //     &config.aws_access_key_id,
    //     &config.aws_secret_access_key,
    //     &config.s3_region,
    //     config.s3_bucket.clone(),
    //     config.s3_endpoint.as_deref(),
    // )
    // .await;

    let storage = StorageService::from_config(
        &config.aws_access_key_id,
        &config.aws_secret_access_key,
        &config.s3_region,
        config.s3_bucket.clone(),
        config.s3_endpoint.as_deref(),
    )
    .await;

    tracing::info!(
        provider = storage.provider_name(),
        bucket = %config.s3_bucket,
        "✓ Object storage configured"
    );

    let cache = CacheService::new(redis.clone());

    // Step 5: Build shared application state.
    let state = AppState::new(db, cache, redis, config.clone(), jwt, storage);

    // Step 6: Build the router.
    let app = build_router(state);

    // Step 7: Bind and serve.
    let addr: SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .expect("Invalid server address");

    tracing::info!("✓ Listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| {
            tracing::error!("Failed to bind to {}: {}", addr, e);
            std::process::exit(1);
        });

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

// fn build_router(state: AppState) -> Router {
//     Router::new()
//         // Health check — no auth required
//         .route("/health", get(health_check))
//         // All API routes (added week by week)
//         .nest("/api/v1", Router::new())
//         // Request tracing — logs every request and response status
//         .layer(TraceLayer::new_for_http())
//         .with_state(state)
// }

fn build_router(state: AppState) -> Router {
    // Extract config value BEFORE moving state
    let request_size_limit = (state.config.max_request_size_kb * 1024) as usize;
    // Reject oversized request bodies before parsing (protect against memory exhaustion)
    routes::create_router(state)
        .layer(RequestBodyLimitLayer::new(request_size_limit))
        // Request tracing — logs every request and response status
        .layer(TraceLayer::new_for_http())
}

/// Health check endpoint.
///
/// Returns 200 OK if the server is running.
/// Does NOT check DB/Redis — use a readiness probe for that.
/// (We keep health simple so it never fails due to infra issues)
async fn health_check() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// Listen for Ctrl+C and SIGTERM for graceful shutdown.
/// Axum will stop accepting new requests and wait for in-flight requests to finish.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let sigterm = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let sigterm = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c  => { tracing::info!("Received Ctrl+C, shutting down"); }
        _ = sigterm => { tracing::info!("Received SIGTERM, shutting down"); }
    }
}
