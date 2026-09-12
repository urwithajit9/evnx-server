// src/routes/mod.rs

use crate::state::AppState;
use axum::http::{HeaderName, Method};
use axum::{
    middleware,
    routing::{delete, get, post},
    Router,
};
use tower_http::cors::{AllowOrigin, CorsLayer};

pub mod auth;
pub mod members;
pub mod tokens;
pub mod users;
pub mod vaults;
pub mod versions;
use crate::middleware::auth::{require_auth, require_user_session, require_verified};

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
        .route(
            "/:vault_id/versions",
            get(versions::list_versions).post(versions::push_version),
        )
        .route(
            "/:vault_id/versions/latest",
            get(versions::get_latest_version),
        )
        .route("/:vault_id/versions/:n/blob", get(versions::download_blob))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_verified,
        ));

    // Auth routes — unauthenticated. Each of these either establishes a session
    // or carries its own credential in the request body (refresh token, email
    // verification token, totp_pending token), so no guard applies.
    let public_auth_routes = Router::new()
        .route("/register", post(auth::register))
        .route("/srp/init", post(auth::srp_init))
        .route("/srp/verify", post(auth::srp_verify))
        .route("/totp/verify", post(auth::totp_verify_login))
        .route("/refresh", post(auth::refresh))
        .route("/verify-email", post(auth::verify_email));

    // Account management — a real user session only. An `evnx_tok_` CI token that
    // could reach these would be able to enrol its own authenticator on the
    // account, revoke the owner's sessions, or mint fresh tokens for itself.
    let account_routes = Router::new()
        .route("/logout", post(auth::logout))
        .route("/totp/setup", post(auth::totp_setup))
        .route("/totp/confirm", post(auth::totp_confirm))
        // CI/CD API tokens. Minting a token is a privilege-granting act, so it
        // requires a real login — a token must not be able to mint another.
        .route(
            "/tokens",
            get(tokens::list_tokens).post(tokens::create_token),
        )
        .route("/tokens/:token_id", delete(tokens::revoke_token))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_user_session,
        ));

    // `require_auth`, not `require_verified`: the CLI calls GET /auth/me
    // immediately after registration to fetch `encrypted_private_key` and
    // `argon2_salt`, before the user has clicked the verification email.
    // Requiring a verified email here would make first login impossible.
    let me_route = Router::new()
        .route("/me", get(auth::me))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));

    let auth_routes = public_auth_routes.merge(account_routes).merge(me_route);

    Router::new()
        .route("/health", get(crate::health_check))
        .nest("/api/v1/auth", auth_routes)
        .nest("/api/v1/vaults", vault_routes)
        .nest(
            "/api/v1/users",
            Router::new()
                .route("/:email/public-key", get(users::get_public_key))
                .route_layer(middleware::from_fn_with_state(state.clone(), require_auth)),
        )
        .layer(cors) // CORS middleware applied to all routes
        .with_state(state)
}
