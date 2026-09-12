// src/main.rs

//! Binary entry point. All application logic lives in the library
//! (`src/lib.rs`) so integration tests can exercise it; this file only wires
//! configuration to live infrastructure and serves the router.

use std::net::SocketAddr;

use evnx_server::config::Config;
use evnx_server::services::cache::CacheService;
use evnx_server::services::email::EmailService;
use evnx_server::services::jwt::JwtService;
use evnx_server::services::storage::StorageService;
use evnx_server::{build_router, AppState};

#[tokio::main]
async fn main() {
    // Logging first — before anything that might need to report a failure.
    // RUST_LOG=evnx_server=debug,tower_http=debug controls verbosity.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_env("RUST_LOG")
                .add_directive("evnx_server=info".parse().unwrap()),
        )
        .init();

    tracing::info!("🚀 evnx-server starting up");

    // Fails fast and lists every missing variable, not just the first.
    let config = Config::from_env().unwrap_or_else(|e| {
        tracing::error!("Configuration error: {}", e);
        std::process::exit(1);
    });

    tracing::info!(environment = ?config.environment, "Configuration loaded");

    let db = sqlx::postgres::PgPoolOptions::new()
        .max_connections(config.database_max_connections)
        .connect(&config.database_url)
        .await
        .unwrap_or_else(|e| {
            tracing::error!("Failed to connect to database: {}", e);
            std::process::exit(1);
        });

    tracing::info!("✓ Database connected");

    // Valkey. The `redis` crate is the client and the URL scheme is still
    // redis:// — Valkey is wire-compatible, so only VALKEY_URL differs.
    let valkey_client = redis::Client::open(config.valkey_url.as_str()).unwrap_or_else(|e| {
        tracing::error!("Failed to create Valkey client: {}", e);
        std::process::exit(1);
    });

    let valkey = redis::aio::ConnectionManager::new(valkey_client)
        .await
        .unwrap_or_else(|e| {
            tracing::error!("Failed to connect to Valkey: {}", e);
            std::process::exit(1);
        });

    tracing::info!("✓ Valkey connected");

    // Safe to run repeatedly — sqlx tracks what has already been applied.
    sqlx::migrate!("./migrations")
        .run(&db)
        .await
        .unwrap_or_else(|e| {
            tracing::error!("Migration failed: {}", e);
            std::process::exit(1);
        });

    tracing::info!("✓ Migrations applied");

    let jwt = JwtService::new(&config.jwt_secret, config.jwt_expiry_minutes);

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

    let email = EmailService::from_config(&config);
    tracing::info!(transport = email.transport_name(), "✓ Email configured");

    let cache = CacheService::new(valkey.clone());
    let state = AppState::new(db, cache, valkey, config.clone(), jwt, email, storage);
    let app = build_router(state);

    let addr: SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .expect("Invalid server address");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| {
            tracing::error!("Failed to bind to {}: {}", addr, e);
            std::process::exit(1);
        });

    tracing::info!("✓ Listening on http://{}", addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap_or_else(|e| {
            tracing::error!("Server error: {}", e);
            std::process::exit(1);
        });
}

/// Wait for Ctrl+C or SIGTERM, then let Axum drain in-flight requests.
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
