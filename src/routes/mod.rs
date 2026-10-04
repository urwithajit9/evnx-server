// src/routes/mod.rs

use crate::state::AppState;
use axum::http::{HeaderName, Method};
use axum::{
    middleware,
    routing::{delete, get, patch, post, put},
    Router,
};
use tower_http::cors::{AllowOrigin, CorsLayer};

pub mod auth;
pub mod billing;
pub mod devices;
pub mod export;
pub mod master_key;
pub mod members;
pub mod orgs;
pub mod plans;
pub mod rekey;
pub mod sessions;
pub mod tokens;
pub mod usage;
pub mod users;
pub mod vaults;
pub mod versions;
use crate::middleware::auth::{require_auth, require_user_session, require_verified};

pub fn create_router(state: AppState) -> Router {
    // `AllowOrigin::list` rather than `exact`, so one deployment can serve
    // `https://app.evnx.dev` and a developer's `http://localhost:3000` at the
    // same time. Config has already rejected `*` and non-local plaintext http,
    // so anything reaching here is a deliberate, named origin.
    //
    // This still echoes back only a matching origin — it is not a wildcard, and
    // `allow_credentials(true)` stays safe.
    let allowed_origins: Vec<axum::http::HeaderValue> = state
        .config
        .frontend_origins
        .iter()
        .map(|o| {
            o.parse::<axum::http::HeaderValue>()
                .unwrap_or_else(|_| panic!("Invalid origin in FRONTEND_URL: {o}"))
        })
        .collect();

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(allowed_origins))
        // ⚠️ PATCH must be listed. A method missing here fails the browser's
        // preflight, and the symptom is a CORS error in the console rather than
        // anything resembling "this verb is not allowed" — so it reads as a
        // deployment problem. Added with the role-change endpoint in Phase 3.
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
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
        .route("/:vault_id/audit", get(vaults::vault_audit))
        .route(
            "/:vault_id/members",
            get(members::list_members).post(members::add_member),
        )
        .route(
            "/:vault_id/members/:user_id",
            patch(members::set_member_role).delete(members::remove_member),
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
        // ⚠️ Admin, not developer. A developer adds history; removing it — and the
        // blob with it, irrecoverably — takes an admin. The endpoint exists because
        // the version quota told people to delete old versions while there was no
        // way to do so; see routes::versions::delete_version.
        .route("/:vault_id/versions/:n", delete(versions::delete_version))
        // Re-keying. Blobs are staged one at a time, then one atomic swap —
        // see routes::rekey for why it cannot be a single request.
        .route("/:vault_id/rekey/blobs", post(rekey::stage_blob))
        .route("/:vault_id/rekey", post(rekey::rekey))
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
        // POST takes the token in a JSON body (CLI / frontend).
        // GET is what the emailed link points at — a browser click.
        .route(
            "/verify-email",
            post(auth::verify_email).get(auth::verify_email_link),
        )
        // Unauthenticated by necessity: the caller cannot log in until verified.
        // Safe because it always answers 202 and is rate-limited per address, so
        // it reveals nothing about which emails are registered.
        .route("/resend-verification", post(auth::resend_verification))
        // ── Undoing a master-password change ────────────────────────────────
        //
        // ⚠️ Unauthenticated **by necessity**, not by oversight. The person who
        // needs this is the person a rotation has locked out, so a session is
        // exactly what they do not have. The only credential it accepts is the
        // one an attacker lacks: the *old* password, proven by SRP against the
        // snapshot's verifier. It answers identically for an address with no
        // snapshot and one that does not exist — see `routes::master_key`.
        .route("/master-key/undo/init", post(master_key::undo_init))
        .route("/master-key/undo/verify", post(master_key::undo_verify));

    // Account management — a real user session only. An `evnx_tok_` CI token that
    // could reach these would be able to enrol its own authenticator on the
    // account, revoke the owner's sessions, or mint fresh tokens for itself.
    let account_routes = Router::new()
        .route("/logout", post(auth::logout))
        .route("/totp/setup", post(auth::totp_setup))
        .route("/totp/confirm", post(auth::totp_confirm))
        // Disabling TOTP or reissuing recovery codes needs a valid second factor,
        // not merely a live session — see the handlers.
        .route("/totp/disable", post(auth::totp_disable))
        .route(
            "/totp/backup-codes",
            post(auth::totp_regenerate_backup_codes),
        )
        // ⚠️ Here rather than under `require_auth`, so an API token cannot delete
        // the account that issued it. A leaked CI token is exactly the credential
        // that must not be able to erase the account it belongs to.
        .route("/account", delete(auth::delete_account))
        // ⚠️ Same guard as the delete above, and for the same reason: a CI
        // token must not be able to pull the account's entire metadata map.
        .route("/account/export", get(export::export_account))
        // Session-only too: it names every vault the account owns.
        .route("/usage", get(usage::usage))
        // ── Changing the master password ────────────────────────────────────
        //
        // Behind `require_user_session` like the rest of account management, and
        // then behind a *second* gate the others do not have: `/master-key`
        // refuses unless `/reauth/verify` has proven the current password within
        // the last five minutes.
        //
        // ⚠️ A recency check on the JWT's `iat` was considered and rejected —
        // `/auth/refresh` restamps it, so it measures something the attacker
        // controls. The reasoning is written out in full at the top of
        // `routes::master_key`.
        .route("/reauth/init", post(master_key::reauth_init))
        .route("/reauth/verify", post(master_key::reauth_verify))
        .route("/master-key", post(master_key::rotate_master_key))
        // CI/CD API tokens. Minting a token is a privilege-granting act, so it
        // requires a real login — a token must not be able to mint another.
        .route(
            "/tokens",
            get(tokens::list_tokens).post(tokens::create_token),
        )
        .route("/tokens/:token_id", delete(tokens::revoke_token))
        // Sessions. The login-alert email points users here.
        // ── Devices ─────────────────────────────────────────────────────────
        //
        // ⚠️ Beside sessions, and deliberately not merged with them. A session
        // is a live credential you can revoke; a device is an origin you have
        // signed in from, which may have no session left at all. Disavowing one
        // revokes *every* session and is a different act from revoking one.
        //
        // `require_user_session`, like the rest of account management: a CI
        // token must not be able to enumerate where its owner signs in from,
        // nor to sign them out everywhere.
        .route("/devices", get(devices::list_devices))
        .route("/devices/disavow", post(devices::disavow_device))
        .route("/sessions", get(sessions::list_sessions))
        .route("/sessions/others", delete(sessions::revoke_other_sessions))
        .route("/sessions/:session_id", delete(sessions::revoke_session))
        // F1 backfill: upload the ML-KEM public key for an account that predates
        // it. Behind a session rather than `require_auth` on purpose — an API
        // token that could rewrite the account's public key would turn a leaked
        // deploy credential into a way to intercept every future share.
        .route("/public-keys", put(users::backfill_public_keys))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_user_session,
        ));

    // ── Organisations ───────────────────────────────────────────────────────
    //
    // ⛔ None of these grants access to a vault. An organisation is billing plus a
    // directory; the server cannot wrap a vault key. See migration 010 and
    // `middleware::org_role`.
    //
    // `require_user_session`, not `require_verified`: an `evnx_tok_` CI token
    // reaching these could invite people, assign seats and change what the
    // account is billed. Same reasoning as `/auth/tokens` and `/auth/account`.
    let org_routes = Router::new()
        .route("/", get(orgs::list_orgs).post(orgs::create_org))
        // ⚠️ Static before dynamic. `/invites/accept` and `/:org_id/invites` are
        // both three segments, and matchit prefers the literal — the same shape as
        // `/sessions/others` beside `/sessions/:session_id` above. Redemption
        // cannot sit under `/:org_id` because the caller is not a member yet, so
        // there is no org role for `OrgAccess` to extract.
        .route("/invites/accept", post(orgs::accept_invite))
        .route("/:org_id", patch(orgs::patch_org).delete(orgs::delete_org))
        // ⚠️ Owner-only, and a separate route rather than a field on the PATCH
        // above, so the requirement sits in the handler signature where it
        // cannot be skipped. Seat *count* is billing; seat *assignment* is
        // administration.
        .route("/:org_id/seats", put(orgs::set_seats))
        .route("/:org_id/members", get(orgs::list_members))
        // Billing. ⚠️ The CHECKOUT is owner-only (buying is a billing act)
        // while reading the state is open to any member — whether the
        // organisation is paid up is not a secret from the people it covers,
        // and hiding it makes "why did my limits change?" unanswerable.
        .route("/:org_id/billing", get(billing::billing_state))
        .route("/:org_id/checkout", post(billing::checkout))
        .route(
            "/:org_id/members/:user_id",
            patch(orgs::patch_member).delete(orgs::remove_member),
        )
        .route(
            "/:org_id/invites",
            get(orgs::list_invites).post(orgs::create_invite),
        )
        .route("/:org_id/invites/:invite_id", delete(orgs::revoke_invite))
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
        // Readiness, for external uptime monitoring. `/health` answers `ok` with
        // every dependency down, so pointing a monitor at it watches nothing.
        .route("/health/ready", get(crate::readiness_check))
        // Public and unauthenticated: what each plan allows. The pricing page
        // reads this at build time instead of keeping its own copy, so a
        // `QUOTA_*` change in production can no longer leave the website
        // advertising a limit the server does not enforce.
        .route("/api/v1/plans", get(plans::plans))
        // ⚠️ THE ONLY UNAUTHENTICATED WRITE PATH IN THE SERVER.
        //
        // No guard layer, deliberately — Paddle cannot hold a JWT. Its credential
        // is the HMAC in the `Paddle-Signature` header, verified against
        // `PADDLE_WEBHOOK_SECRET` before a single byte of the body is parsed.
        // See `routes::billing` for what a forged event would be worth.
        //
        // ⚠️ Outside the `/api/v1/orgs` nest on purpose: nesting it would put it
        // behind `require_user_session`, which would reject every real webhook
        // with a 401 that looked like a Paddle misconfiguration.
        .route("/api/v1/billing/webhook", post(billing::webhook))
        .nest("/api/v1/auth", auth_routes)
        .nest("/api/v1/vaults", vault_routes)
        .nest("/api/v1/orgs", org_routes)
        .nest(
            "/api/v1/users",
            Router::new()
                .route("/:email/public-key", get(users::get_public_key))
                .route_layer(middleware::from_fn_with_state(state.clone(), require_auth)),
        )
        .layer(cors) // CORS middleware applied to all routes
        .with_state(state)
}
