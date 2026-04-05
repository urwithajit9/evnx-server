// src/routes/mod.rs

use crate::{middleware::auth, state::AppState};
use axum::http::{HeaderName, Method};
use axum::{
    middleware,
    routing::{delete, get, post},
    Router,
};
use tower_http::cors::{AllowOrigin, CorsLayer};

// pub mod auth;
pub mod members;
pub mod tokens;
pub mod users;
pub mod vaults;
pub mod versions;

pub fn create_router(state: AppState) -> Router {
    let allowed_origin = state
        .config
        .frontend_url
        .parse::<axum::http::HeaderValue>()
        .expect("Invalid FRONTEND_URL");

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::exact(allowed_origin))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            HeaderName::from_static("content-type"),
            HeaderName::from_static("authorization"),
        ])
        .allow_credentials(true)
        .max_age(std::time::Duration::from_secs(3600));
    // Vault routes — require JWT + email verified
    let vault_routes = Router::new()
        .route("/", get(vaults::list_vaults).post(vaults::create_vault))
        .route("/:vault_id", delete(vaults::delete_vault))
        .route("/:vault_id/my-key", get(vaults::get_my_key))
        .route("/:vault_id/members", post(members::add_member))
        .route(
            "/:vault_id/members/:user_id",
            delete(members::remove_member),
        )
        // Week 7: .route("/:vault_id/versions", get(...).post(...))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_verified,
        ));

    // Auth routes — mostly public
    let auth_routes = Router::new()
        .route("/register", post(auth::register))
        .route("/srp/init", post(auth::srp_init))
        .route("/srp/verify", post(auth::srp_verify))
        .route("/totp/verify", post(auth::totp_verify_login))
        .route("/refresh", post(auth::refresh))
        .route("/verify-email", post(auth::verify_email))
        // Protected auth routes
        .route("/logout", post(auth::logout))
        .route("/totp/setup", post(auth::totp_setup))
        .route("/totp/confirm", post(auth::totp_confirm));

    Router::new()
        .route("/health", get(crate::health_check))
        .nest("/api/v1/auth", auth_routes)
        .nest("/api/v1/vaults", vault_routes)
        .with_state(state)
}
