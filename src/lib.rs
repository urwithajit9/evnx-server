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

    routes::create_router(state.clone())
        // Reject oversized bodies before parsing them — guards against memory exhaustion.
        .layer(RequestBodyLimitLayer::new(request_size_limit))
        // Outermost so the headers land on every response, including rejections
        // produced by the layers below (413 from the body limit, 404, 405).
        .layer(axum::middleware::from_fn_with_state(
            state,
            middleware::security_headers::add_security_headers,
        ))
        .layer(TraceLayer::new_for_http())
}

/// Liveness probe.
///
/// Deliberately does **not** touch Postgres or Valkey — it answers "is the
/// process up", so an infra blip never takes the container out of rotation.
/// Use a separate readiness probe for dependency health.
/// Is the service actually able to serve a request?
///
/// ⚠️ **`/health` cannot answer this and was never meant to.** It is a static JSON
/// literal: it reports `ok` with Postgres unreachable and Valkey gone, because
/// nothing in it touches either. An uptime monitor pointed at `/health` therefore
/// reports a healthy service while every request that matters returns 500 — which
/// is the exact failure an uptime monitor exists to catch, and the reason this
/// endpoint was added rather than making `/health` heavier.
///
/// The two stay separate deliberately:
///
/// * `/health` is **liveness** — cheap, dependency-free, and read by
///   `deploy-drift.yml` for its `build` field. A transient database blip must not
///   make deploy drift unreadable.
/// * `/health/ready` is **readiness** — point external monitoring here.
///
/// ─── What it deliberately does not say ───────────────────────────────────────
///
/// Unauthenticated, because a monitor cannot sign in. So it returns subsystem
/// names and `ok`/`failed` and nothing else: no error text, no host, no timing, no
/// version. A driver's error string can carry a connection string, and this is the
/// one endpoint on the server that anyone on the internet can read at will.
///
/// `503` on failure, so a monitor sees a non-2xx rather than having to parse the
/// body — which is what every one of them checks by default.
pub async fn readiness_check(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    // A trivial round trip, not a pool-status read: a pool can report healthy
    // handles while the server behind it refuses queries.
    let database = sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.db)
        .await
        .is_ok();

    // Any read that reaches the server proves the connection; the key need not
    // exist, and its absence is a successful answer.
    let cache = state.cache.exists("readiness-probe").await.is_ok();

    let ok = database && cache;
    let code = if ok {
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    };

    (
        code,
        axum::Json(serde_json::json!({
            "status": if ok { "ok" } else { "degraded" },
            "checks": {
                "database": if database { "ok" } else { "failed" },
                "cache":    if cache    { "ok" } else { "failed" },
            },
        })),
    )
}

pub async fn health_check() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        // The commit this binary was built from — see `build.rs`.
        //
        // `version` cannot stand in for it: it has been 0.1.0 since the repo
        // began and does not move when code does. With images published on tags
        // rather than on every push, the deployed binary lags `main` by design,
        // and this is the only way to see by how much without guessing from
        // workflow history.
        "build": env!("EVNX_BUILD_SHA"),
    }))
}
