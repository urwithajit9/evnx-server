//! Integration tests against the real router, Postgres and Valkey.
//!
//! Requires infrastructure: `docker compose -f docker/docker-compose.yml up -d postgres valkey`
//! and a `.env` (or exported env) that `Config::from_env()` accepts.
//!
//! Every test mints its own email and user id, so the suite is safe to re-run
//! and safe to run in parallel. The previous version used fixed addresses like
//! `test-register@example.com`, which passed once and then failed forever on the
//! duplicate-email 409.

use axum::http::{header::AUTHORIZATION, HeaderValue, StatusCode};
use axum_test::{TestRequest, TestServer};
use evnx_server::config::Config;
use evnx_server::services::jwt::JwtService;
use evnx_server::{build_router, AppState};
use uuid::Uuid;

// ─── Harness ───────────────────────────────────────────────────────────────────

async fn test_config() -> Config {
    Config::from_env().expect("test config — is .env present?")
}

async fn test_app() -> TestServer {
    let config = test_config().await;
    let db = sqlx::PgPool::connect(&config.database_url)
        .await
        .expect("test: Postgres unreachable — run `docker compose up -d postgres valkey`");
    sqlx::migrate!("./migrations").run(&db).await.unwrap();

    let state = AppState::new_for_test(db, config).await;
    // build_router, not routes::create_router — tests should exercise the same
    // middleware stack as production (body limit + tracing).
    TestServer::new(build_router(state)).unwrap()
}

/// axum-test 14 exposes only `add_header`, so bearer auth gets a small helper.
fn bearer(req: TestRequest, token: &str) -> TestRequest {
    req.add_header(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    )
}

fn unique_email(prefix: &str) -> String {
    format!("{prefix}-{}@example.test", Uuid::new_v4())
}

/// A registration body that satisfies every validator in `RegisterRequest`.
/// Values are filler of the correct length — the server never decodes them.
fn register_payload(email: &str) -> serde_json::Value {
    serde_json::json!({
        "email": email,
        "srp_verifier": "a".repeat(512),          // hex, 256..=1024
        "srp_salt": "A".repeat(44),               // base64, exactly 44
        "argon2_salt": "B".repeat(44),
        "ed25519_public_key": "C".repeat(44),
        "x25519_public_key": "D".repeat(44),      // required since migration 002
        "encrypted_private_key": "E".repeat(96),  // base64, 60..=300
    })
}

/// Register a user and return its id.
async fn register_user(server: &TestServer) -> Uuid {
    let resp = server
        .post("/api/v1/auth/register")
        .json(&register_payload(&unique_email("it")))
        .await;
    resp.assert_status(StatusCode::CREATED);
    let body = resp.json::<serde_json::Value>();
    Uuid::parse_str(body["user_id"].as_str().unwrap()).unwrap()
}

async fn jwt_service() -> JwtService {
    let config = test_config().await;
    JwtService::new(&config.jwt_secret, config.jwt_expiry_minutes)
}

// ─── Baseline ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn health_endpoint_reports_ok() {
    let server = test_app().await;
    let resp = server.get("/health").await;
    resp.assert_status_ok();
    assert_eq!(resp.json::<serde_json::Value>()["status"], "ok");
}

#[tokio::test]
async fn register_returns_201() {
    let server = test_app().await;
    let resp = server
        .post("/api/v1/auth/register")
        .json(&register_payload(&unique_email("reg")))
        .await;
    resp.assert_status(StatusCode::CREATED);
}

#[tokio::test]
async fn register_duplicate_email_returns_409() {
    let server = test_app().await;
    let payload = register_payload(&unique_email("dup"));
    server.post("/api/v1/auth/register").json(&payload).await;
    let resp = server.post("/api/v1/auth/register").json(&payload).await;
    resp.assert_status(StatusCode::CONFLICT);
}

#[tokio::test]
async fn register_without_x25519_key_returns_422() {
    // Guards migration 002: vault sharing cannot work without this key, so the
    // server must refuse a registration that omits it.
    let server = test_app().await;
    let mut payload = register_payload(&unique_email("nox25519"));
    payload.as_object_mut().unwrap().remove("x25519_public_key");
    let resp = server.post("/api/v1/auth/register").json(&payload).await;
    assert_ne!(
        resp.status_code(),
        StatusCode::CREATED,
        "registration without x25519_public_key must be rejected"
    );
}

// ─── B1 regression: protected auth routes ──────────────────────────────────────
//
// These four handlers take `Extension<Claims>`. Before B1 no middleware was
// applied to them, so Axum rejected every request with 500 instead of 401 and
// the endpoints were unreachable. /auth/me is how the CLI fetches
// encrypted_private_key, so login could never complete.

#[tokio::test]
async fn protected_auth_routes_reject_missing_credential_with_401_not_500() {
    let server = test_app().await;

    for (method, path) in [
        ("GET", "/api/v1/auth/me"),
        ("POST", "/api/v1/auth/logout"),
        ("POST", "/api/v1/auth/totp/setup"),
        ("POST", "/api/v1/auth/totp/confirm"),
    ] {
        let resp = match method {
            "GET" => server.get(path).await,
            _ => server.post(path).json(&serde_json::json!({})).await,
        };
        assert_eq!(
            resp.status_code(),
            StatusCode::UNAUTHORIZED,
            "{method} {path} must be 401 without a credential (500 means no guard is applied)"
        );
    }
}

#[tokio::test]
async fn auth_me_accepts_a_user_jwt() {
    let server = test_app().await;
    let user_id = register_user(&server).await;
    // email_verified = false: the CLI calls /auth/me before the verification
    // email is clicked, which is why this route uses require_auth.
    let token = jwt_service()
        .await
        .issue(user_id, Uuid::new_v4(), false)
        .unwrap();

    let resp = bearer(server.get("/api/v1/auth/me"), &token).await;

    resp.assert_status_ok();
    let body = resp.json::<serde_json::Value>();
    assert_eq!(body["user_id"].as_str().unwrap(), user_id.to_string());
    assert!(body["encrypted_private_key"].is_string());
    assert!(body["argon2_salt"].is_string());
}

#[tokio::test]
async fn unverified_email_cannot_reach_vault_routes() {
    let server = test_app().await;
    let user_id = register_user(&server).await;
    let token = jwt_service()
        .await
        .issue(user_id, Uuid::new_v4(), false)
        .unwrap();

    let resp = bearer(server.get("/api/v1/vaults"), &token).await;

    assert_eq!(resp.status_code(), StatusCode::FORBIDDEN);
}

// ─── B1 regression: JWT scope is validated, not just the signature ─────────────
//
// A totp_pending token is issued after SRP proves the password but BEFORE the
// second factor is checked. JwtService::verify() only validates signature and
// expiry, so without an explicit scope check such a token authenticated exactly
// like a completed session — a 2FA bypass.

#[tokio::test]
async fn totp_pending_token_is_rejected_everywhere() {
    let server = test_app().await;
    let user_id = register_user(&server).await;
    let pending = jwt_service().await.issue_totp_pending(user_id).unwrap();

    for path in [
        "/api/v1/auth/me",
        "/api/v1/vaults",
        "/api/v1/users/nobody@example.test/public-key",
    ] {
        let resp = bearer(server.get(path), &pending.clone()).await;
        assert_eq!(
            resp.status_code(),
            StatusCode::UNAUTHORIZED,
            "{path} accepted a half-authenticated totp_pending token — 2FA bypass"
        );
    }
}

#[tokio::test]
async fn api_token_cannot_reach_account_management() {
    // An evnx_tok_ CI token that could reach /totp/setup + /totp/confirm would
    // be able to enrol its own authenticator on the victim's account. 403
    // (wrong credential type) is deliberately distinct from 401 (unknown).
    let server = test_app().await;
    let fake = format!("evnx_tok_{}", "a".repeat(64));

    let resp = bearer(server.post("/api/v1/auth/totp/setup"), &fake.clone())
        .json(&serde_json::json!({}))
        .await;
    assert_eq!(resp.status_code(), StatusCode::FORBIDDEN);

    // /auth/me allows API tokens by design, so an unknown one is 401, not 403.
    let resp = bearer(server.get("/api/v1/auth/me"), &fake).await;
    assert_eq!(resp.status_code(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unauthenticated_vault_access_returns_401() {
    let server = test_app().await;
    server
        .get("/api/v1/vaults")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

// ─── B9 regression: Valkey-backed state ────────────────────────────────────────

#[tokio::test]
async fn logout_blocklists_the_session_via_valkey() {
    // Exercises SETEX (set_flag) + EXISTS through the real cache: after logout
    // the same token must stop working.
    let server = test_app().await;
    let user_id = register_user(&server).await;
    let token = jwt_service()
        .await
        .issue(user_id, Uuid::new_v4(), false)
        .unwrap();

    bearer(server.get("/api/v1/auth/me"), &token.clone())
        .await
        .assert_status_ok();

    bearer(server.post("/api/v1/auth/logout"), &token.clone())
        .json(&serde_json::json!({}))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let resp = bearer(server.get("/api/v1/auth/me"), &token).await;
    assert_eq!(
        resp.status_code(),
        StatusCode::UNAUTHORIZED,
        "token still valid after logout — Valkey blocklist not consulted"
    );
}

#[tokio::test]
async fn srp_init_rate_limit_triggers_after_5_attempts() {
    // Exercises INCR + EXPIRE. The key is per-email, so a unique address keeps
    // this test independent of previous runs (the counter lives 900s).
    let server = test_app().await;
    let email = unique_email("ratelimit");
    let body = serde_json::json!({ "email": email, "client_public": "a".repeat(512) });

    for i in 0..5 {
        let resp = server.post("/api/v1/auth/srp/init").json(&body).await;
        assert_ne!(
            resp.status_code(),
            StatusCode::TOO_MANY_REQUESTS,
            "rate limited early, on attempt {}",
            i + 1
        );
    }

    server
        .post("/api/v1/auth/srp/init")
        .json(&body)
        .await
        .assert_status(StatusCode::TOO_MANY_REQUESTS);
}
