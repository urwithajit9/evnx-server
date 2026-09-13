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

// ─── B4 regression: CI/CD API token routes ─────────────────────────────────────
//
// routes/tokens.rs was fully implemented but never added to the router, so there
// was no way to create an API token at all.

/// Register a user and mint a JWT that claims a verified email, so the test can
/// reach vault routes. The server only ever issues `email_verified: true` when the
/// database says so; minting one here with the real secret is test setup, not a
/// bypass under test.
async fn verified_user(server: &TestServer) -> (Uuid, String) {
    let user_id = register_user(server).await;
    let token = jwt_service()
        .await
        .issue(user_id, Uuid::new_v4(), true)
        .unwrap();
    (user_id, token)
}

async fn create_vault(server: &TestServer, jwt: &str) -> Uuid {
    let name = format!("v{}", Uuid::new_v4().simple()); // regex: ^[a-z0-9-]+$
    let resp = bearer(server.post("/api/v1/vaults"), jwt)
        .json(&serde_json::json!({
            "name": name,
            "environment": "development",
            "encrypted_vault_key": "Zm9v",
            "eph_pub_key": "YmFy",
        }))
        .await;
    resp.assert_status(StatusCode::CREATED);
    Uuid::parse_str(
        resp.json::<serde_json::Value>()["vault_id"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
}

/// Mint an API token. `vault_id: None` means unscoped.
async fn create_api_token(
    server: &TestServer,
    jwt: &str,
    scope: &str,
    vault_id: Option<Uuid>,
) -> String {
    let resp = bearer(server.post("/api/v1/auth/tokens"), jwt)
        .json(&serde_json::json!({
            "name": "ci",
            "scope": scope,
            "vault_id": vault_id,
        }))
        .await;
    resp.assert_status(StatusCode::CREATED);
    let body = resp.json::<serde_json::Value>();
    body["raw_token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn api_token_can_be_created_listed_and_revoked() {
    let server = test_app().await;
    let (_uid, jwt) = verified_user(&server).await;

    let resp = bearer(server.post("/api/v1/auth/tokens"), &jwt)
        .json(&serde_json::json!({ "name": "ci", "scope": "read" }))
        .await;
    resp.assert_status(StatusCode::CREATED);
    let created = resp.json::<serde_json::Value>();
    let raw = created["raw_token"].as_str().unwrap();
    assert!(
        raw.starts_with("evnx_tok_"),
        "token must carry the evnx_tok_ prefix so `evnx scan` can detect it"
    );
    let token_id = created["id"].as_str().unwrap().to_string();

    let listed = bearer(server.get("/api/v1/auth/tokens"), &jwt).await;
    listed.assert_status_ok();
    let tokens = listed.json::<serde_json::Value>();
    assert!(
        tokens["tokens"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["id"].as_str() == Some(token_id.as_str())),
        "created token missing from the list"
    );
    assert!(
        !listed.text().contains(raw),
        "the raw token must never be returned again after creation"
    );

    bearer(
        server.delete(&format!("/api/v1/auth/tokens/{token_id}")),
        &jwt,
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);

    // A revoked token must stop authenticating.
    let resp = bearer(server.get("/api/v1/vaults"), raw).await;
    assert_eq!(resp.status_code(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn api_token_cannot_mint_another_token() {
    // Otherwise a leaked CI token could mint itself a longer-lived, wider-scoped
    // replacement and survive revocation of the original.
    let server = test_app().await;
    let (_uid, jwt) = verified_user(&server).await;
    let raw = create_api_token(&server, &jwt, "read_write", None).await;

    for resp in [
        bearer(server.post("/api/v1/auth/tokens"), &raw)
            .json(&serde_json::json!({ "name": "escalate", "scope": "read_write" }))
            .await,
        bearer(server.get("/api/v1/auth/tokens"), &raw).await,
    ] {
        assert_eq!(
            resp.status_code(),
            StatusCode::FORBIDDEN,
            "an API token reached /auth/tokens — privilege escalation"
        );
    }
}

// ─── B3 regression: API tokens on vault routes, scope enforced ─────────────────

#[tokio::test]
async fn unscoped_read_token_can_read_but_not_write() {
    let server = test_app().await;
    let (_uid, jwt) = verified_user(&server).await;
    let raw = create_api_token(&server, &jwt, "read", None).await;

    // Read is allowed — this is the whole point of B3 (CI `evnx cloud pull`).
    bearer(server.get("/api/v1/vaults"), &raw)
        .await
        .assert_status_ok();

    // Any mutation is refused for a read-only token.
    let resp = bearer(server.post("/api/v1/vaults"), &raw)
        .json(&serde_json::json!({
            "name": "nope", "environment": "development",
            "encrypted_vault_key": "Zm9v", "eph_pub_key": "YmFy",
        }))
        .await;
    assert_eq!(resp.status_code(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn read_write_token_may_mutate() {
    let server = test_app().await;
    let (_uid, jwt) = verified_user(&server).await;
    let vault = create_vault(&server, &jwt).await;
    let raw = create_api_token(&server, &jwt, "read_write", None).await;

    // Reaches the handler rather than being refused by the guard. The push body
    // is deliberately incomplete, so a 4xx from validation is fine — what matters
    // is that it is not 403 from the scope check.
    let resp = bearer(
        server.post(&format!("/api/v1/vaults/{vault}/versions")),
        &raw,
    )
    .json(&serde_json::json!({}))
    .await;
    assert_ne!(
        resp.status_code(),
        StatusCode::FORBIDDEN,
        "a read_write token was refused a write"
    );
}

#[tokio::test]
async fn vault_scoped_token_cannot_reach_another_vault() {
    let server = test_app().await;
    let (_uid, jwt) = verified_user(&server).await;
    let vault_a = create_vault(&server, &jwt).await;
    let vault_b = create_vault(&server, &jwt).await;

    // Scoped to A only — both vaults belong to the same user, so this proves the
    // guard enforces the token's scope and not merely vault membership.
    let raw = create_api_token(&server, &jwt, "read", Some(vault_a)).await;

    bearer(
        server.get(&format!("/api/v1/vaults/{vault_a}/versions")),
        &raw,
    )
    .await
    .assert_status_ok();

    let resp = bearer(
        server.get(&format!("/api/v1/vaults/{vault_b}/versions")),
        &raw,
    )
    .await;
    assert_eq!(
        resp.status_code(),
        StatusCode::FORBIDDEN,
        "a token scoped to vault A reached vault B"
    );
}

#[tokio::test]
async fn vault_scoped_token_cannot_list_all_vaults() {
    // GET /vaults has no :vault_id, so a vault-scoped token has no business
    // there — enumerating every vault is outside what it was issued for.
    let server = test_app().await;
    let (_uid, jwt) = verified_user(&server).await;
    let vault = create_vault(&server, &jwt).await;
    let raw = create_api_token(&server, &jwt, "read", Some(vault)).await;

    let resp = bearer(server.get("/api/v1/vaults"), &raw).await;
    assert_eq!(resp.status_code(), StatusCode::FORBIDDEN);
}

// ─── B6 regression: email wiring and the verification-token leak ───────────────
//
// EmailService was never constructed or called, and register logged the raw
// verification token unconditionally at info level — a bearer credential written
// to stdout on every signup. Nobody could verify an email either, which meant
// require_verified blocked every vault route: the product was unusable.

#[tokio::test]
async fn registration_no_longer_logs_the_verification_token() {
    // The guarantee is structural: the only place a token can now be surfaced is
    // the `log` email transport, which Config::from_env refuses outside
    // development. Assert the source itself carries no token-logging statement,
    // since a passing runtime check would not prove absence on other paths.
    let src = std::fs::read_to_string("src/routes/auth.rs").unwrap();
    assert!(
        !src.contains("Email verification token"),
        "register still logs the raw verification token"
    );
    assert!(
        !src.contains("raw_token\n    );"),
        "raw_token still appears in a tracing macro"
    );
}

#[tokio::test]
async fn log_email_transport_is_refused_outside_development() {
    // This is the guard that keeps a live verification token out of staging and
    // production logs. Env access is process-global, so this test is serial-safe
    // only because the suite runs with --test-threads=1.
    use evnx_server::config::Config;

    let previous = std::env::var("ENVIRONMENT").ok();
    let prev_backend = std::env::var("STORAGE_BACKEND").ok();
    std::env::set_var("ENVIRONMENT", "production");
    std::env::set_var("EMAIL_TRANSPORT", "log");
    // STORAGE_BACKEND=local is also refused in production and is validated
    // first, so neutralise it — otherwise this test would pass on the wrong error.
    std::env::set_var("STORAGE_BACKEND", "s3");
    std::env::set_var("STORAGE_BUCKET", "evnx-test");

    let result = Config::from_env();

    match previous {
        Some(v) => std::env::set_var("ENVIRONMENT", v),
        None => std::env::remove_var("ENVIRONMENT"),
    }
    match prev_backend {
        Some(v) => std::env::set_var("STORAGE_BACKEND", v),
        None => std::env::remove_var("STORAGE_BACKEND"),
    }
    std::env::set_var("EMAIL_TRANSPORT", "log");

    let err = result.expect_err("EMAIL_TRANSPORT=log must be refused in production");
    assert!(
        err.to_string().contains("EMAIL_TRANSPORT=log"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn emailed_link_verifies_the_account_and_is_single_use() {
    // End-to-end: register, redeem the token the way the emailed link does, and
    // confirm the account can then reach vault routes it was locked out of.
    let server = test_app().await;
    let email = unique_email("verify");

    let resp = server
        .post("/api/v1/auth/register")
        .json(&register_payload(&email))
        .await;
    resp.assert_status(StatusCode::CREATED);
    let user_id = Uuid::parse_str(
        resp.json::<serde_json::Value>()["user_id"]
            .as_str()
            .unwrap(),
    )
    .unwrap();

    // The token is hashed at rest, so the test mints its own verification row
    // rather than trying to recover the original — the redemption path is what
    // is under test.
    let config = test_config().await;
    let db = sqlx::PgPool::connect(&config.database_url).await.unwrap();
    let raw = "b6-test-token-".to_string() + &Uuid::new_v4().to_string();
    let hash = blake3::hash(raw.as_bytes()).to_hex().to_string();
    sqlx::query(
        "INSERT INTO email_verifications (user_id, token_hash, expires_at)
         VALUES ($1, $2, NOW() + INTERVAL '24 hours')",
    )
    .bind(user_id)
    .bind(&hash)
    .execute(&db)
    .await
    .unwrap();

    // Before verifying, vault routes are closed.
    let jwt = jwt_service()
        .await
        .issue(user_id, Uuid::new_v4(), false)
        .unwrap();
    assert_eq!(
        bearer(server.get("/api/v1/vaults"), &jwt)
            .await
            .status_code(),
        StatusCode::FORBIDDEN
    );

    // GET is what the emailed link hits — an HTML page, not JSON.
    let resp = server
        .get("/api/v1/auth/verify-email")
        .add_query_param("token", &raw)
        .await;
    resp.assert_status_ok();
    assert!(resp.text().contains("Email verified"));

    let verified: bool = sqlx::query_scalar("SELECT email_verified FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&db)
        .await
        .unwrap();
    assert!(verified, "email_verified was not set");

    // Single-use: the same link must not work twice.
    let resp = server
        .get("/api/v1/auth/verify-email")
        .add_query_param("token", &raw)
        .await;
    assert_eq!(resp.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn verify_email_rejects_an_unknown_token() {
    let server = test_app().await;
    let resp = server
        .get("/api/v1/auth/verify-email")
        .add_query_param("token", "not-a-real-token")
        .await;
    assert_eq!(resp.status_code(), StatusCode::BAD_REQUEST);

    let resp = server
        .post("/api/v1/auth/verify-email")
        .json(&serde_json::json!({ "token": "not-a-real-token" }))
        .await;
    assert_eq!(resp.status_code(), StatusCode::NOT_FOUND);
}

// ─── B2 regression: TOTP login ─────────────────────────────────────────────────
//
// srp_verify returned `totp_pending_token: Some("todo_week5")` — a literal
// placeholder — so any user with TOTP enabled could not log in at all.
//
// These tests drive the real SRP-6a exchange using evnx-crypto as the client,
// exactly as the CLI will. Nothing here is stubbed: the verifier, the ephemerals
// and the proofs are genuine.

use evnx_crypto::{
    compute_client_proof, compute_verifier, derive_srp_password, generate_client_ephemeral,
    generate_salt, salt_to_base64, verify_server_proof,
};

const TEST_PASSWORD: &[u8] = b"correct horse battery staple";

struct SrpAccount {
    email: String,
    user_id: Uuid,
    srp_salt: [u8; 32],
}

/// Register an account whose SRP verifier is genuinely derived from a password,
/// so `/auth/srp/*` can complete for real.
async fn register_srp_account(server: &TestServer) -> SrpAccount {
    let email = unique_email("srp");
    let srp_salt = generate_salt();
    let argon2_salt = generate_salt();

    let srp_password = derive_srp_password(TEST_PASSWORD, &srp_salt).unwrap();
    let verifier = compute_verifier(&email, srp_password, srp_salt).unwrap();

    let resp = server
        .post("/api/v1/auth/register")
        .json(&serde_json::json!({
            "email": email,
            "srp_verifier": verifier.verifier_hex(),
            "srp_salt": verifier.srp_salt_base64(),
            "argon2_salt": salt_to_base64(&argon2_salt),
            "ed25519_public_key": "C".repeat(44),
            "x25519_public_key": "D".repeat(44),
            "encrypted_private_key": "E".repeat(96),
        }))
        .await;
    resp.assert_status(StatusCode::CREATED);

    let user_id = Uuid::parse_str(
        resp.json::<serde_json::Value>()["user_id"]
            .as_str()
            .unwrap(),
    )
    .unwrap();

    SrpAccount {
        email,
        user_id,
        srp_salt,
    }
}

/// Run the full SRP-6a login and return the server's `/srp/verify` response,
/// after checking the server's proof M2 — so a wrong M2 fails the test rather
/// than passing silently.
async fn srp_login(server: &TestServer, account: &SrpAccount) -> serde_json::Value {
    let ephemeral = generate_client_ephemeral().unwrap();

    let init = server
        .post("/api/v1/auth/srp/init")
        .json(&serde_json::json!({
            "email": account.email,
            "client_public": hex::encode(&ephemeral.public_a),
        }))
        .await;
    init.assert_status_ok();
    let init = init.json::<serde_json::Value>();

    let session_id = init["session_id"].as_str().unwrap().to_string();
    let server_public = hex::decode(init["server_public"].as_str().unwrap()).unwrap();

    let srp_password = derive_srp_password(TEST_PASSWORD, &account.srp_salt).unwrap();
    let proof = compute_client_proof(
        &account.email,
        srp_password,
        &account.srp_salt,
        &server_public,
        &ephemeral,
    )
    .unwrap();

    let verify = server
        .post("/api/v1/auth/srp/verify")
        .json(&serde_json::json!({
            "session_id": session_id,
            "client_proof": hex::encode(&proof.client_proof),
        }))
        .await;
    verify.assert_status_ok();
    let body = verify.json::<serde_json::Value>();

    // The client must authenticate the server too, or SRP buys nothing.
    let server_proof = hex::decode(body["server_proof"].as_str().unwrap()).unwrap();
    verify_server_proof(&server_proof, &proof).expect("server proof M2 did not verify");

    body
}

#[tokio::test]
async fn full_srp_login_issues_tokens_without_totp() {
    let server = test_app().await;
    let account = register_srp_account(&server).await;

    let body = srp_login(&server, &account).await;

    assert_eq!(body["requires_totp"], false);
    let access = body["access_token"].as_str().expect("no access token");
    assert!(body["refresh_token"].as_str().is_some());

    // The issued token must actually work.
    bearer(server.get("/api/v1/auth/me"), access)
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn srp_login_with_wrong_password_is_rejected() {
    let server = test_app().await;
    let account = register_srp_account(&server).await;
    let ephemeral = generate_client_ephemeral().unwrap();

    let init = server
        .post("/api/v1/auth/srp/init")
        .json(&serde_json::json!({
            "email": account.email,
            "client_public": hex::encode(&ephemeral.public_a),
        }))
        .await
        .json::<serde_json::Value>();

    let server_public = hex::decode(init["server_public"].as_str().unwrap()).unwrap();
    let wrong = derive_srp_password(b"not the password", &account.srp_salt).unwrap();
    let proof = compute_client_proof(
        &account.email,
        wrong,
        &account.srp_salt,
        &server_public,
        &ephemeral,
    )
    .unwrap();

    let resp = server
        .post("/api/v1/auth/srp/verify")
        .json(&serde_json::json!({
            "session_id": init["session_id"].as_str().unwrap(),
            "client_proof": hex::encode(&proof.client_proof),
        }))
        .await;
    assert_eq!(resp.status_code(), StatusCode::UNAUTHORIZED);
}

/// Enable TOTP on an account and return its base32 secret.
async fn enable_totp(server: &TestServer, user_id: Uuid) -> String {
    let jwt = jwt_service()
        .await
        .issue(user_id, Uuid::new_v4(), true)
        .unwrap();

    let setup = bearer(server.post("/api/v1/auth/totp/setup"), &jwt).await;
    setup.assert_status_ok();
    let secret = setup.json::<serde_json::Value>()["secret_base32"]
        .as_str()
        .unwrap()
        .to_string();

    // 200, not 204 — confirm now returns the one-time recovery codes.
    let resp = bearer(server.post("/api/v1/auth/totp/confirm"), &jwt)
        .json(&serde_json::json!({ "totp_code": totp_code(&secret) }))
        .await;
    resp.assert_status_ok();

    secret
}

/// Generate the code an authenticator app would show right now.
fn totp_code(secret_base32: &str) -> String {
    use totp_rs::{Algorithm, Secret, TOTP};
    let bytes =
        base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret_base32).unwrap();
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Raw(bytes).to_bytes().unwrap(),
        Some("evnx".to_string()),
        "evnx".to_string(),
    )
    .unwrap()
    .generate_current()
    .unwrap()
}

#[tokio::test]
async fn totp_user_can_complete_login() {
    // The B2 regression: this was impossible, because srp_verify handed back the
    // string "todo_week5" instead of a token.
    let server = test_app().await;
    let account = register_srp_account(&server).await;
    let secret = enable_totp(&server, account.user_id).await;

    let body = srp_login(&server, &account).await;

    assert_eq!(body["requires_totp"], true);
    assert!(
        body["access_token"].is_null(),
        "no session may be issued before the second factor"
    );
    let pending = body["totp_pending_token"]
        .as_str()
        .expect("no pending token");
    assert_ne!(pending, "todo_week5");
    assert!(
        pending.split('.').count() == 3,
        "pending token is not a JWT: {pending}"
    );

    let resp = server
        .post("/api/v1/auth/totp/verify")
        .json(&serde_json::json!({
            "totp_pending_token": pending,
            "totp_code": totp_code(&secret),
        }))
        .await;
    resp.assert_status_ok();

    let access = resp.json::<serde_json::Value>()["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    bearer(server.get("/api/v1/auth/me"), &access)
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn totp_pending_token_is_single_use() {
    // A successful login must spend the token. Otherwise the same pending token
    // plus a still-valid 30-second code could mint further sessions for the rest
    // of its 5-minute lifetime.
    let server = test_app().await;
    let account = register_srp_account(&server).await;
    let secret = enable_totp(&server, account.user_id).await;

    let pending = srp_login(&server, &account).await["totp_pending_token"]
        .as_str()
        .unwrap()
        .to_string();

    let body = serde_json::json!({
        "totp_pending_token": pending,
        "totp_code": totp_code(&secret),
    });

    server
        .post("/api/v1/auth/totp/verify")
        .json(&body)
        .await
        .assert_status_ok();

    let replay = server.post("/api/v1/auth/totp/verify").json(&body).await;
    assert_eq!(
        replay.status_code(),
        StatusCode::UNAUTHORIZED,
        "pending token was accepted twice"
    );
}

#[tokio::test]
async fn totp_verify_rejects_a_wrong_code() {
    let server = test_app().await;
    let account = register_srp_account(&server).await;
    let _secret = enable_totp(&server, account.user_id).await;

    let pending = srp_login(&server, &account).await["totp_pending_token"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = server
        .post("/api/v1/auth/totp/verify")
        .json(&serde_json::json!({
            "totp_pending_token": pending,
            "totp_code": "000000",
        }))
        .await;
    assert_eq!(resp.status_code(), StatusCode::UNAUTHORIZED);
}

// ─── B7 regression: provider-agnostic storage ──────────────────────────────────
//
// storage.rs used aws-sdk-s3 and picked its "provider" by sniffing the endpoint
// hostname (endpoint.contains("your-objectstorage.com")), which silently
// misconfigured anything it did not recognise and could not reach GCS or Azure
// at all. It is now object_store, with the backend named in configuration.

#[tokio::test]
async fn storage_backend_must_be_named_explicitly() {
    use evnx_server::config::Config;

    let previous = std::env::var("STORAGE_BACKEND").ok();
    std::env::set_var("STORAGE_BACKEND", "hetzner"); // a provider, not a backend
    let result = Config::from_env();
    match previous {
        Some(v) => std::env::set_var("STORAGE_BACKEND", v),
        None => std::env::remove_var("STORAGE_BACKEND"),
    }

    let err = result.expect_err("an unknown STORAGE_BACKEND must be refused");
    assert!(
        err.to_string().contains("STORAGE_BACKEND"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn local_storage_backend_is_refused_outside_development() {
    // The local filesystem is not shared between instances, so a multi-instance
    // deployment would serve blobs that only exist on one node.
    use evnx_server::config::Config;

    let prev_env = std::env::var("ENVIRONMENT").ok();
    let prev_backend = std::env::var("STORAGE_BACKEND").ok();
    // EMAIL_TRANSPORT=log is also refused in production, so move it out of the
    // way to be sure the error under test is the storage one.
    std::env::set_var("ENVIRONMENT", "production");
    std::env::set_var("EMAIL_TRANSPORT", "resend");
    std::env::set_var("STORAGE_BACKEND", "local");

    let result = Config::from_env();

    match prev_env {
        Some(v) => std::env::set_var("ENVIRONMENT", v),
        None => std::env::remove_var("ENVIRONMENT"),
    }
    match prev_backend {
        Some(v) => std::env::set_var("STORAGE_BACKEND", v),
        None => std::env::remove_var("STORAGE_BACKEND"),
    }
    std::env::set_var("EMAIL_TRANSPORT", "log");

    let err = result.expect_err("STORAGE_BACKEND=local must be refused in production");
    assert!(err.to_string().contains("local"), "unexpected error: {err}");
}

#[tokio::test]
async fn blob_round_trips_through_the_configured_backend() {
    // Exercises the storage service itself: put, head, get, delete. Runs against
    // whatever backend .env names — `local` by default, so no cloud account is
    // needed, but pointing STORAGE_BACKEND at a real bucket runs the same checks.
    use evnx_server::services::storage::StorageService;

    let config = test_config().await;
    let storage = StorageService::from_config(&config).expect("storage config");

    let key = StorageService::blob_key(Uuid::new_v4(), 1);
    let payload = bytes::Bytes::from_static(b"ciphertext-not-plaintext");

    assert!(
        !storage.blob_exists(&key).await.unwrap(),
        "key already used"
    );

    storage.upload_blob(&key, payload.clone()).await.unwrap();
    assert!(storage.blob_exists(&key).await.unwrap());
    assert_eq!(storage.download_blob(&key).await.unwrap(), payload);

    storage.delete_blob(&key).await.unwrap();
    assert!(!storage.blob_exists(&key).await.unwrap());
    assert!(
        storage.download_blob(&key).await.is_err(),
        "a deleted blob must not be downloadable"
    );
}

#[tokio::test]
async fn blob_keys_are_unique_per_push() {
    // The trailing UUID means a retried push never overwrites an existing blob.
    use evnx_server::services::storage::StorageService;
    let vault = Uuid::new_v4();
    let a = StorageService::blob_key(vault, 7);
    let b = StorageService::blob_key(vault, 7);
    assert_ne!(a, b);
    assert!(a.starts_with(&format!("vaults/{vault}/00000007/")));
}

// ─── B10 regression: vault creation is atomic ──────────────────────────────────
//
// create_vault ran two inserts on separate pool connections. If the second
// failed, the vault row survived with no row in vault_members — and list_vaults
// inner joins that table, so the vault was invisible to its own owner while
// still holding its unique (owner, name, environment). The owner could neither
// see it nor reuse the name.

#[tokio::test]
async fn creating_a_vault_also_grants_the_owner_their_key() {
    let server = test_app().await;
    let (user_id, jwt) = verified_user(&server).await;
    let vault = create_vault(&server, &jwt).await;

    // Visible in the listing — which requires the vault_members row to exist.
    let listed = bearer(server.get("/api/v1/vaults"), &jwt).await;
    listed.assert_status_ok();
    let body = listed.json::<serde_json::Value>();
    let found = body["vaults"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"].as_str() == Some(&vault.to_string()))
        .expect("new vault missing from the owner's list");
    assert_eq!(found["role"], "owner");

    // And the owner's wrapped key is retrievable.
    let key = bearer(server.get(&format!("/api/v1/vaults/{vault}/my-key")), &jwt).await;
    key.assert_status_ok();
    assert!(key.json::<serde_json::Value>()["encrypted_vault_key"].is_string());

    let config = test_config().await;
    let db = sqlx::PgPool::connect(&config.database_url).await.unwrap();
    let members: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM vault_members WHERE vault_id = $1 AND user_id = $2",
    )
    .bind(vault)
    .bind(user_id)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(members, 1);
}

#[tokio::test]
async fn a_failed_member_insert_rolls_the_vault_back() {
    // Drives the two db functions the handler uses, in one transaction, and makes
    // the second fail on its foreign key. Before B10 these ran on separate pool
    // connections, so the vault row would have survived.
    use evnx_server::db::{members, vaults};

    let server = test_app().await;
    let (owner_id, _jwt) = verified_user(&server).await;

    let config = test_config().await;
    let db = sqlx::PgPool::connect(&config.database_url).await.unwrap();
    let name = format!("rollback{}", Uuid::new_v4().simple());

    let mut tx = db.begin().await.unwrap();
    let vault_id = vaults::create(&mut *tx, owner_id, &name, "development")
        .await
        .unwrap();

    // No such user — violates vault_members.user_id -> users(id).
    let result = members::add_member(
        &mut *tx,
        vault_id,
        Uuid::new_v4(),
        "owner",
        "Zm9v",
        "YmFy",
        owner_id,
    )
    .await;
    assert!(result.is_err(), "expected a foreign key violation");

    drop(tx); // rolls back

    let surviving: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vaults WHERE id = $1")
        .bind(vault_id)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(
        surviving, 0,
        "vault survived a failed member insert — it would be invisible to its owner \
         while still holding the name"
    );

    // The name is therefore free to use again.
    let resp = bearer(server.post("/api/v1/vaults"), &_jwt)
        .json(&serde_json::json!({
            "name": name, "environment": "development",
            "encrypted_vault_key": "Zm9v", "eph_pub_key": "YmFy",
        }))
        .await;
    resp.assert_status(StatusCode::CREATED);
}

#[tokio::test]
async fn create_vault_handler_uses_a_transaction() {
    // The behavioural test above proves the two db calls roll back when composed
    // in a transaction, but it drives them directly — it would still pass if the
    // handler went back to two separate pool connections. Forcing a mid-handler
    // failure is not possible from the outside (role and user_id are fixed by the
    // handler, and the key columns are unconstrained TEXT), so this pins the
    // handler to the transaction at the source level instead.
    let src = std::fs::read_to_string("src/routes/vaults.rs").unwrap();
    let body = src
        .split("pub async fn create_vault")
        .nth(1)
        .expect("create_vault not found");
    let body = &body[..body.find("\n// ─").unwrap_or(body.len())];

    assert!(
        body.contains("state.db.begin()") && body.contains("tx.commit()"),
        "create_vault must create the vault and the owner's member row in one transaction"
    );
    assert!(
        !body.contains("vaults::create(&state.db"),
        "create_vault is inserting outside the transaction"
    );
}

// ─── B15 regression: TOTP must never be a one-way door ─────────────────────────
//
// Before this, /totp/confirm returned 204 with no recovery codes and there was no
// disable or reset endpoint anywhere. A user who enabled TOTP and lost their
// authenticator could never log in again — and since the server holds only
// ciphertext, it could not recover their vaults either. That is data loss.

/// Enable TOTP and return (secret, backup codes).
async fn enable_totp_with_codes(server: &TestServer, jwt: &str) -> (String, Vec<String>) {
    let setup = bearer(server.post("/api/v1/auth/totp/setup"), jwt).await;
    setup.assert_status_ok();
    let secret = setup.json::<serde_json::Value>()["secret_base32"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = bearer(server.post("/api/v1/auth/totp/confirm"), jwt)
        .json(&serde_json::json!({ "totp_code": totp_code(&secret) }))
        .await;
    resp.assert_status_ok();

    let codes: Vec<String> = resp.json::<serde_json::Value>()["backup_codes"]
        .as_array()
        .expect("confirm must return backup codes")
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();
    (secret, codes)
}

#[tokio::test]
async fn totp_confirm_issues_recovery_codes() {
    let server = test_app().await;
    let (_uid, jwt) = verified_user(&server).await;
    let (_secret, codes) = enable_totp_with_codes(&server, &jwt).await;

    assert_eq!(codes.len(), 10, "expected a full set of recovery codes");
    let unique: std::collections::HashSet<_> = codes.iter().collect();
    assert_eq!(unique.len(), codes.len(), "recovery codes must be distinct");
    for c in &codes {
        assert!(
            c.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-'),
            "code should be transcribable by hand: {c}"
        );
        // Alphabet deliberately excludes 0/O and 1/l/I.
        assert!(
            !c.contains('0') && !c.contains('O') && !c.contains('1') && !c.contains('I'),
            "code contains an easily-misread character: {c}"
        );
    }
}

#[tokio::test]
async fn a_lost_authenticator_does_not_lock_the_user_out() {
    // The scenario in full: TOTP is on, the phone is gone, only the printed codes
    // remain. The user must still be able to log in.
    let server = test_app().await;
    let account = register_srp_account(&server).await;
    let jwt = jwt_service()
        .await
        .issue(account.user_id, Uuid::new_v4(), true)
        .unwrap();
    let (_secret, codes) = enable_totp_with_codes(&server, &jwt).await;

    let pending = srp_login(&server, &account).await["totp_pending_token"]
        .as_str()
        .unwrap()
        .to_string();

    // No authenticator — redeem a printed code instead.
    let resp = server
        .post("/api/v1/auth/totp/verify")
        .json(&serde_json::json!({
            "totp_pending_token": pending,
            "totp_code": codes[0],
        }))
        .await;
    resp.assert_status_ok();

    let body = resp.json::<serde_json::Value>();
    let access = body["access_token"].as_str().expect("no access token");
    assert_eq!(
        body["backup_codes_remaining"], 9,
        "a redeemed code must be spent, and the remainder reported"
    );

    bearer(server.get("/api/v1/auth/me"), access)
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn a_recovery_code_works_only_once() {
    let server = test_app().await;
    let account = register_srp_account(&server).await;
    let jwt = jwt_service()
        .await
        .issue(account.user_id, Uuid::new_v4(), true)
        .unwrap();
    let (_secret, codes) = enable_totp_with_codes(&server, &jwt).await;

    for attempt in 0..2 {
        let pending = srp_login(&server, &account).await["totp_pending_token"]
            .as_str()
            .unwrap()
            .to_string();
        let resp = server
            .post("/api/v1/auth/totp/verify")
            .json(&serde_json::json!({
                "totp_pending_token": pending,
                "totp_code": codes[0],
            }))
            .await;
        if attempt == 0 {
            resp.assert_status_ok();
        } else {
            assert_eq!(
                resp.status_code(),
                StatusCode::UNAUTHORIZED,
                "the same recovery code was accepted twice"
            );
        }
    }
}

#[tokio::test]
async fn totp_can_be_disabled_and_requires_a_second_factor() {
    let server = test_app().await;
    let (_uid, jwt) = verified_user(&server).await;
    let (secret, _codes) = enable_totp_with_codes(&server, &jwt).await;

    // A live session alone is not enough — stealing one must not strip 2FA.
    let resp = bearer(server.post("/api/v1/auth/totp/disable"), &jwt)
        .json(&serde_json::json!({ "totp_code": "000000" }))
        .await;
    assert_eq!(resp.status_code(), StatusCode::UNAUTHORIZED);

    // With a real code it works.
    bearer(server.post("/api/v1/auth/totp/disable"), &jwt)
        .json(&serde_json::json!({ "totp_code": totp_code(&secret) }))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    // And it is genuinely off — enabling again is allowed, which it would not be
    // if totp_enabled had been left set.
    bearer(server.post("/api/v1/auth/totp/setup"), &jwt)
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn recovery_codes_can_be_regenerated_and_the_old_set_dies() {
    // Codes are single-use, so a user who spends the last one would be back to a
    // lockout without this.
    let server = test_app().await;
    let (_uid, jwt) = verified_user(&server).await;
    let (secret, old_codes) = enable_totp_with_codes(&server, &jwt).await;

    let resp = bearer(server.post("/api/v1/auth/totp/backup-codes"), &jwt)
        .json(&serde_json::json!({ "totp_code": totp_code(&secret) }))
        .await;
    resp.assert_status_ok();
    let new_codes: Vec<String> = resp.json::<serde_json::Value>()["backup_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();

    assert_eq!(new_codes.len(), 10);
    let old: std::collections::HashSet<_> = old_codes.iter().collect();
    assert!(
        new_codes.iter().all(|c| !old.contains(c)),
        "regeneration returned a code from the old set"
    );

    // An old code must no longer redeem.
    let account_jwt = jwt.clone();
    let resp = bearer(server.post("/api/v1/auth/totp/disable"), &account_jwt)
        .json(&serde_json::json!({ "totp_code": old_codes[0] }))
        .await;
    assert_eq!(
        resp.status_code(),
        StatusCode::UNAUTHORIZED,
        "a superseded recovery code still worked"
    );
}

// ─── B5 regression: security headers ───────────────────────────────────────────

#[tokio::test]
async fn security_headers_are_served() {
    // middleware/security_headers.rs existed from early on but was never declared
    // in middleware/mod.rs, so it had never been compiled and none of these were
    // ever sent.
    let server = test_app().await;
    let resp = server.get("/health").await;
    resp.assert_status_ok();

    let h = resp.headers();
    assert_eq!(h.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(h.get("x-frame-options").unwrap(), "DENY");
    assert_eq!(h.get("referrer-policy").unwrap(), "no-referrer");
    assert!(h
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("default-src 'none'"));

    // HSTS is production-only: pinning localhost to HTTPS would be useless and
    // painful to undo.
    assert!(
        h.get("strict-transport-security").is_none(),
        "HSTS must not be sent in development"
    );

    // Obsolete and harmful in the browsers that honoured it.
    assert!(h.get("x-xss-protection").is_none());
}

// ─── B14 regression: sessions ──────────────────────────────────────────────────

#[tokio::test]
async fn sessions_can_be_listed_and_revoked() {
    // The login-alert email tells users to "revoke all sessions from your account
    // settings" — until now there was no endpoint behind that sentence.
    let server = test_app().await;
    let account = register_srp_account(&server).await;

    // Two real logins = two sessions.
    let first = srp_login(&server, &account).await;
    let second = srp_login(&server, &account).await;
    let second_access = second["access_token"].as_str().unwrap().to_string();

    let listed = bearer(server.get("/api/v1/auth/sessions"), &second_access).await;
    listed.assert_status_ok();
    let sessions = listed.json::<serde_json::Value>();
    let arr = sessions["sessions"].as_array().unwrap();
    assert!(
        arr.len() >= 2,
        "expected at least two sessions, got {}",
        arr.len()
    );
    assert_eq!(
        arr.iter().filter(|s| s["current"] == true).count(),
        1,
        "exactly one session must be marked current"
    );

    // Revoking the others must not sign the caller out.
    let resp = bearer(
        server.delete("/api/v1/auth/sessions/others"),
        &second_access,
    )
    .await;
    resp.assert_status_ok();
    assert!(
        resp.json::<serde_json::Value>()["revoked"]
            .as_i64()
            .unwrap()
            >= 1
    );

    bearer(server.get("/api/v1/auth/me"), &second_access)
        .await
        .assert_status_ok();

    // The other session's access token is dead immediately, not in 15 minutes.
    let first_access = first["access_token"].as_str().unwrap();
    assert_eq!(
        bearer(server.get("/api/v1/auth/me"), first_access)
            .await
            .status_code(),
        StatusCode::UNAUTHORIZED,
        "a revoked session's access token still worked"
    );
}

#[tokio::test]
async fn a_session_belonging_to_someone_else_cannot_be_revoked() {
    let server = test_app().await;
    let victim = register_srp_account(&server).await;
    let attacker = register_srp_account(&server).await;

    let victim_login = srp_login(&server, &victim).await;
    let victim_access = victim_login["access_token"].as_str().unwrap().to_string();
    let attacker_access = srp_login(&server, &attacker).await["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    let victim_session = bearer(server.get("/api/v1/auth/sessions"), &victim_access)
        .await
        .json::<serde_json::Value>()["sessions"][0]["session_id"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = bearer(
        server.delete(&format!("/api/v1/auth/sessions/{victim_session}")),
        &attacker_access,
    )
    .await;
    assert_eq!(resp.status_code(), StatusCode::NOT_FOUND);

    // And the victim is still signed in.
    bearer(server.get("/api/v1/auth/me"), &victim_access)
        .await
        .assert_status_ok();
}
