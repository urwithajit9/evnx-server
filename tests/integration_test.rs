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
        "mlkem_public_key": "F".repeat(1580),     // required since migration 004
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

#[tokio::test]
async fn register_without_mlkem_key_returns_422() {
    // Guards migration 004. An account with no ML-KEM public key cannot be shared
    // with at all — `add_member` refuses rather than falling back to an
    // X25519-only wrap — so a registration that omits it would silently create an
    // account that looks fine and cannot participate in a team.
    let server = test_app().await;
    let mut payload = register_payload(&unique_email("nomlkem"));
    payload.as_object_mut().unwrap().remove("mlkem_public_key");
    let resp = server.post("/api/v1/auth/register").json(&payload).await;
    assert_ne!(
        resp.status_code(),
        StatusCode::CREATED,
        "registration without mlkem_public_key must be rejected"
    );
}

#[tokio::test]
async fn register_with_wrong_length_mlkem_key_returns_422() {
    // 1580 characters exactly — 1184 bytes base64. A shorter value is either a
    // different parameter set (ML-KEM-512 is 800 bytes) or a truncated key, and
    // both must be caught at the edge rather than at the first share.
    let server = test_app().await;
    for len in [1579usize, 1581, 44] {
        let mut payload = register_payload(&unique_email("badmlkem"));
        payload["mlkem_public_key"] = serde_json::json!("F".repeat(len));
        let resp = server.post("/api/v1/auth/register").json(&payload).await;
        assert_ne!(
            resp.status_code(),
            StatusCode::CREATED,
            "a {len}-character mlkem_public_key must be rejected"
        );
    }
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
            // The creator's own copy carries NEITHER an ephemeral nor an ML-KEM
            // ciphertext: it is wrapped under an HKDF subkey of the master key,
            // which involves no key agreement of either kind. This helper used to
            // send `eph_pub_key: "YmFy"` — base64 for "bar" — which is how 140
            // rows in the development database ended up claiming to be ECDH
            // wraps. Migration 004's CHECK constraint refuses that shape now.
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

/// A vault's creator wraps their own key under their master key, which uses no
/// ECDH and so produces no ephemeral. Omitting `eph_pub_key` must be accepted.
///
/// This is not a shape preference. Solo vaults are post-quantum safe precisely
/// because that path is Argon2id + XChaCha20 and never touches X25519; requiring
/// an ephemeral would force the creator through ECDH and make every vault
/// vulnerable to harvest-now-decrypt-later.
#[tokio::test]
async fn create_vault_accepts_a_master_key_wrap_with_no_ephemeral() {
    let server = test_app().await;
    let (_user_id, token) = verified_user(&server).await;

    let resp = bearer(server.post("/api/v1/vaults"), &token)
        .json(&serde_json::json!({
            "name": format!("solo-{}", Uuid::new_v4().simple()),
            "environment": "development",
            "encrypted_vault_key": "d3JhcHBlZC11bmRlci10aGUtbWFzdGVyLWtleQ==",
            // eph_pub_key deliberately absent
        }))
        .await;

    resp.assert_status(StatusCode::CREATED);
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
            "mlkem_public_key": "F".repeat(1580),
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
        // The creator's own copy: no ephemeral, no ML-KEM ciphertext.
        &members::MemberKeyWrap::OwnMasterKey {
            encrypted_vault_key: "Zm9v".into(),
        },
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
            "encrypted_vault_key": "Zm9v",
        }))
        .await;
    resp.assert_status(StatusCode::CREATED);
}

#[tokio::test]
async fn a_failed_member_insert_rolls_the_vault_back_through_the_handler() {
    // The test above drives the db layer directly, which is why the source-level
    // check below exists at all — there was no way to force a mid-handler failure
    // from outside, because the key columns were unconstrained TEXT.
    //
    // Migration 004 changed that. `eph_pub_key` without `mlkem_ciphertext`
    // violates `vault_members_wrap_is_whole`, and that violation happens on the
    // member insert — AFTER the vault insert, inside the same handler. So this is
    // now a genuine black-box test of the transaction: the request fails, and the
    // vault must not survive holding its unique name.
    let server = test_app().await;
    let (_id, jwt) = verified_user(&server).await;
    let name = format!("v{}", Uuid::new_v4().simple());

    let resp = bearer(server.post("/api/v1/vaults"), &jwt)
        .json(&serde_json::json!({
            "name": name,
            "environment": "development",
            "encrypted_vault_key": "Zm9v",
            "eph_pub_key": "YmFy",
        }))
        .await;
    assert_ne!(resp.status_code(), StatusCode::CREATED);

    // The name must be free — if the vault row survived, this would be a 409 and
    // the owner would have a vault they cannot see (list_vaults inner-joins
    // vault_members, which is the row that failed).
    let retry = bearer(server.post("/api/v1/vaults"), &jwt)
        .json(&serde_json::json!({
            "name": name,
            "environment": "development",
            "encrypted_vault_key": "Zm9v",
        }))
        .await;
    retry.assert_status(StatusCode::CREATED);
}

#[tokio::test]
async fn create_vault_handler_uses_a_transaction() {
    // The behavioural test above proves the two db calls roll back when composed
    // in a transaction, but it drives them directly — it would still pass if the
    // handler went back to two separate pool connections. Forcing a mid-handler
    // failure is not possible from the outside (role and user_id are fixed by the
    // handler, and the key columns were unconstrained TEXT), so this pins the
    // handler to the transaction at the source level instead.
    //
    // ⚠️ Migration 004 made a black-box version possible — see
    // `a_failed_member_insert_rolls_the_vault_back_through_the_handler`. This one
    // is kept because it fails for a different reason: it catches the handler
    // being rewritten to two pool connections even in a future where no CHECK
    // constraint happens to be violable.
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

// ─── resend-verification ───────────────────────────────────────────────────────
//
// The security property here is that the response is identical whether or not the
// address exists. If these three tests ever disagree, the endpoint has become an
// account-enumeration oracle.

#[tokio::test]
async fn resend_verification_accepts_a_pending_address() {
    let server = test_app().await;
    let email = unique_email("resend-pending");
    server
        .post("/api/v1/auth/register")
        .json(&register_payload(&email))
        .await
        .assert_status(StatusCode::CREATED);

    server
        .post("/api/v1/auth/resend-verification")
        .json(&serde_json::json!({ "email": email }))
        .await
        .assert_status(StatusCode::ACCEPTED);
}

#[tokio::test]
async fn resend_verification_gives_an_unknown_address_the_same_answer() {
    let server = test_app().await;
    // Never registered. Must be indistinguishable from the case above.
    let res = server
        .post("/api/v1/auth/resend-verification")
        .json(&serde_json::json!({ "email": unique_email("resend-ghost") }))
        .await;
    res.assert_status(StatusCode::ACCEPTED);
    assert!(
        res.text().is_empty(),
        "202 body must stay empty — any detail here leaks whether the account exists"
    );
}

#[tokio::test]
async fn resend_verification_rejects_a_malformed_address() {
    let server = test_app().await;
    server
        .post("/api/v1/auth/resend-verification")
        .json(&serde_json::json!({ "email": "not-an-email" }))
        .await
        // 422, not 400: the JSON parsed fine, the content failed validation.
        // Matches every other validated endpoint on this server.
        .assert_status(StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn resend_verification_rate_limits_repeated_requests() {
    let server = test_app().await;
    let email = unique_email("resend-flood");
    server
        .post("/api/v1/auth/register")
        .json(&register_payload(&email))
        .await
        .assert_status(StatusCode::CREATED);

    // 3 per hour are allowed; the 4th must be refused. Without this the endpoint
    // is an open relay for sending mail to a third party's inbox.
    for i in 1..=3 {
        server
            .post("/api/v1/auth/resend-verification")
            .json(&serde_json::json!({ "email": email }))
            .await
            .assert_status_success();
        let _ = i;
    }
    server
        .post("/api/v1/auth/resend-verification")
        .json(&serde_json::json!({ "email": email }))
        .await
        .assert_status(StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn resend_verification_is_case_insensitive_about_the_address() {
    let server = test_app().await;
    let email = unique_email("resend-case");
    server
        .post("/api/v1/auth/register")
        .json(&register_payload(&email))
        .await
        .assert_status(StatusCode::CREATED);

    // The server lowercases on both register and resend. If it did not, the
    // rate-limit key would differ by case and the limit would be trivially
    // bypassed by varying capitalisation.
    server
        .post("/api/v1/auth/resend-verification")
        .json(&serde_json::json!({ "email": email.to_uppercase() }))
        .await
        .assert_status(StatusCode::ACCEPTED);
}

// ─── F1: hybrid X25519 + ML-KEM-768 wrapping ──────────────────────────────────
//
// The server never performs the wrap — it stores what the client computed. What
// it can enforce, and what these cover, is that a *half* wrap is unrepresentable
// and that an account without a post-quantum key cannot be shared with.

#[tokio::test]
async fn my_key_returns_both_wrap_fields() {
    let server = test_app().await;
    let (_id, jwt) = verified_user(&server).await;
    let vault_id = create_vault(&server, &jwt).await;

    let resp = bearer(
        server.get(&format!("/api/v1/vaults/{vault_id}/my-key")),
        &jwt,
    )
    .await;
    resp.assert_status_ok();
    let body = resp.json::<serde_json::Value>();

    // The creator's own copy: both null together. That pair is what tells a
    // client to unwrap with the master key rather than the hybrid path.
    assert!(body["eph_pub_key"].is_null());
    assert!(body["mlkem_ciphertext"].is_null());
    assert_eq!(body["encrypted_vault_key"], "Zm9v");
}

#[tokio::test]
async fn creating_a_vault_with_half_a_wrap_is_refused() {
    // ⚠️ The downgrade this whole feature exists to prevent: an ephemeral X25519
    // key with no ML-KEM ciphertext beside it is a wrap that Shor opens. The
    // CHECK constraint from migration 004 makes it unstorable, so a client bug
    // — or a deliberate strip — surfaces as an error rather than a weak key.
    let server = test_app().await;
    let (_id, jwt) = verified_user(&server).await;
    let name = format!("v{}", Uuid::new_v4().simple());

    let resp = bearer(server.post("/api/v1/vaults"), &jwt)
        .json(&serde_json::json!({
            "name": name,
            "environment": "development",
            "encrypted_vault_key": "Zm9v",
            "eph_pub_key": "YmFy",
            // mlkem_ciphertext deliberately absent
        }))
        .await;

    assert_ne!(
        resp.status_code(),
        StatusCode::CREATED,
        "a vault key wrapped by ECDH with no ML-KEM ciphertext must not be stored"
    );
}

#[tokio::test]
async fn public_key_lookup_includes_the_mlkem_key() {
    let server = test_app().await;
    let (_id, jwt) = verified_user(&server).await;

    let email = unique_email("pklookup");
    server
        .post("/api/v1/auth/register")
        .json(&register_payload(&email))
        .await
        .assert_status(StatusCode::CREATED);

    let resp = bearer(
        server.get(&format!("/api/v1/users/{email}/public-key")),
        &jwt,
    )
    .await;
    resp.assert_status_ok();
    let body = resp.json::<serde_json::Value>();

    assert_eq!(body["mlkem_public_key"].as_str().unwrap().len(), 1580);
    assert_eq!(body["x25519_public_key"].as_str().unwrap().len(), 44);
}

#[tokio::test]
async fn backfilling_a_public_key_is_idempotent_then_refuses_a_different_one() {
    // The endpoint exists because the server cannot derive the ML-KEM key — only
    // a client holding the master password can. Clients call it on every login,
    // so the same value arriving repeatedly must be fine.
    let server = test_app().await;

    // A row with no ML-KEM key, as a pre-F1 account would be.
    let user_id = register_user(&server).await;
    let config = test_config().await;
    let db = sqlx::PgPool::connect(&config.database_url).await.unwrap();
    sqlx::query("UPDATE users SET mlkem_public_key = NULL WHERE id = $1")
        .bind(user_id)
        .execute(&db)
        .await
        .unwrap();

    let jwt = jwt_service()
        .await
        .issue(user_id, Uuid::new_v4(), true)
        .unwrap();
    let key = "G".repeat(1580);

    let first = bearer(server.put("/api/v1/auth/public-keys"), &jwt)
        .json(&serde_json::json!({ "mlkem_public_key": key }))
        .await;
    first.assert_status_ok();
    assert_eq!(first.json::<serde_json::Value>()["status"], "stored");

    // Same key again — what every subsequent login sends.
    let second = bearer(server.put("/api/v1/auth/public-keys"), &jwt)
        .json(&serde_json::json!({ "mlkem_public_key": key }))
        .await;
    second.assert_status_ok();
    assert_eq!(second.json::<serde_json::Value>()["status"], "unchanged");

    // ⚠️ A DIFFERENT key must be refused. An open update would be a
    // key-substitution primitive: anyone holding a session could point the
    // account at their own key, and every vault shared with it afterwards would
    // be wrapped to them.
    let hijack = bearer(server.put("/api/v1/auth/public-keys"), &jwt)
        .json(&serde_json::json!({ "mlkem_public_key": "H".repeat(1580) }))
        .await;
    assert_eq!(
        hijack.status_code(),
        StatusCode::CONFLICT,
        "overwriting an existing ML-KEM public key must be refused"
    );
}

#[tokio::test]
async fn sharing_with_an_account_that_has_no_mlkem_key_is_refused() {
    // ⚠️ The alternative would be an X25519-only wrap, and a vault key wrapped
    // that way stays wrapped that way for as long as the row exists. An adversary
    // recording it does not care that a later version fixed the algorithm, so
    // there is no "share now, upgrade later".
    let server = test_app().await;
    let (_owner, jwt) = verified_user(&server).await;
    let vault_id = create_vault(&server, &jwt).await;

    let email = unique_email("nopq");
    server
        .post("/api/v1/auth/register")
        .json(&register_payload(&email))
        .await
        .assert_status(StatusCode::CREATED);

    let config = test_config().await;
    let db = sqlx::PgPool::connect(&config.database_url).await.unwrap();
    sqlx::query("UPDATE users SET mlkem_public_key = NULL WHERE email = $1")
        .bind(&email)
        .execute(&db)
        .await
        .unwrap();

    let resp = bearer(
        server.post(&format!("/api/v1/vaults/{vault_id}/members")),
        &jwt,
    )
    .json(&serde_json::json!({
        "user_email": email,
        "role": "developer",
        "encrypted_vault_key": "Zm9v",
        "eph_pub_key": "YmFy",
        "mlkem_ciphertext": "Y".repeat(1452),
    }))
    .await;

    assert_eq!(
        resp.status_code(),
        StatusCode::CONFLICT,
        "sharing with an account that has no post-quantum key must be refused"
    );
}

#[tokio::test]
async fn sharing_stores_both_halves_and_returns_them() {
    let server = test_app().await;
    let (_owner, jwt) = verified_user(&server).await;
    let vault_id = create_vault(&server, &jwt).await;

    let email = unique_email("share");
    let recipient = server
        .post("/api/v1/auth/register")
        .json(&register_payload(&email))
        .await;
    recipient.assert_status(StatusCode::CREATED);
    let recipient_id = Uuid::parse_str(
        recipient.json::<serde_json::Value>()["user_id"]
            .as_str()
            .unwrap(),
    )
    .unwrap();

    let ct = "Y".repeat(1452);
    bearer(
        server.post(&format!("/api/v1/vaults/{vault_id}/members")),
        &jwt,
    )
    .json(&serde_json::json!({
        "user_email": email,
        "role": "developer",
        "encrypted_vault_key": "c2hhcmVk",
        "eph_pub_key": "YmFy",
        "mlkem_ciphertext": ct,
    }))
    .await
    .assert_status(StatusCode::CREATED);

    // The recipient reads back exactly what was stored — all three fields, since
    // all three are needed to unwrap.
    let their_jwt = jwt_service()
        .await
        .issue(recipient_id, Uuid::new_v4(), true)
        .unwrap();
    let resp = bearer(
        server.get(&format!("/api/v1/vaults/{vault_id}/my-key")),
        &their_jwt,
    )
    .await;
    resp.assert_status_ok();
    let body = resp.json::<serde_json::Value>();

    assert_eq!(body["encrypted_vault_key"], "c2hhcmVk");
    assert_eq!(body["eph_pub_key"], "YmFy");
    assert_eq!(body["mlkem_ciphertext"], ct);
}

// ─── Phase 3 step 1: who can reach this vault ─────────────────────────────────

#[tokio::test]
async fn member_list_shows_the_owner_and_everyone_shared_with() {
    let server = test_app().await;
    let (owner_id, jwt) = verified_user(&server).await;
    let vault_id = create_vault(&server, &jwt).await;

    // Owner alone, before any sharing.
    let resp = bearer(
        server.get(&format!("/api/v1/vaults/{vault_id}/members")),
        &jwt,
    )
    .await;
    resp.assert_status_ok();
    let body = resp.json::<serde_json::Value>();
    let members = body["members"].as_array().unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0]["role"], "owner");
    assert_eq!(members[0]["user_id"], owner_id.to_string());
    assert_eq!(members[0]["is_you"], true);
    assert_eq!(members[0]["has_mlkem_key"], true);

    // Share, then the list grows.
    let email = unique_email("listed");
    server
        .post("/api/v1/auth/register")
        .json(&register_payload(&email))
        .await
        .assert_status(StatusCode::CREATED);

    bearer(
        server.post(&format!("/api/v1/vaults/{vault_id}/members")),
        &jwt,
    )
    .json(&serde_json::json!({
        "user_email": email,
        "role": "developer",
        "encrypted_vault_key": "c2hhcmVk",
        "eph_pub_key": "YmFy",
        "mlkem_ciphertext": "Y".repeat(1452),
    }))
    .await
    .assert_status(StatusCode::CREATED);

    let resp = bearer(
        server.get(&format!("/api/v1/vaults/{vault_id}/members")),
        &jwt,
    )
    .await;
    let body = resp.json::<serde_json::Value>();
    let members = body["members"].as_array().unwrap();
    assert_eq!(members.len(), 2);

    // The owner sorts first regardless of when anyone was added — a list whose
    // first row moves around as people join reads as unstable.
    assert_eq!(members[0]["role"], "owner");
    assert_eq!(members[1]["role"], "developer");
    assert_eq!(members[1]["email"], email);
    assert_eq!(members[1]["is_you"], false);
}

/// ⚠️ The listing must never carry another member's wrapped key.
///
/// Each one is wrapped to that member and useless to anyone else, so this is not
/// a break — but a listing endpoint is exactly where such a field gets copied
/// into a response by accident, and the test is cheaper than the review.
#[tokio::test]
async fn member_list_leaks_no_key_material() {
    let server = test_app().await;
    let (_owner, jwt) = verified_user(&server).await;
    let vault_id = create_vault(&server, &jwt).await;

    let email = unique_email("nokeys");
    server
        .post("/api/v1/auth/register")
        .json(&register_payload(&email))
        .await
        .assert_status(StatusCode::CREATED);

    let ct = "Y".repeat(1452);
    bearer(
        server.post(&format!("/api/v1/vaults/{vault_id}/members")),
        &jwt,
    )
    .json(&serde_json::json!({
        "user_email": email,
        "role": "viewer",
        "encrypted_vault_key": "c2VjcmV0d3JhcA==",
        "eph_pub_key": "YmFy",
        "mlkem_ciphertext": ct,
    }))
    .await
    .assert_status(StatusCode::CREATED);

    let raw = bearer(
        server.get(&format!("/api/v1/vaults/{vault_id}/members")),
        &jwt,
    )
    .await
    .text();

    for forbidden in [
        "encrypted_vault_key",
        "eph_pub_key",
        "mlkem_ciphertext",
        "c2VjcmV0d3JhcA==", // the wrapped key's actual value
        "mlkem_public_key",
        &ct,
    ] {
        assert!(
            !raw.contains(forbidden),
            "member listing leaked `{forbidden}`"
        );
    }
}

/// A non-member gets 404, not 403 — a distinct "exists but not yours" would let
/// anyone probe for vault ids.
#[tokio::test]
async fn member_list_is_404_for_a_non_member() {
    let server = test_app().await;
    let (_owner, owner_jwt) = verified_user(&server).await;
    let vault_id = create_vault(&server, &owner_jwt).await;

    let (_outsider, outsider_jwt) = verified_user(&server).await;
    let resp = bearer(
        server.get(&format!("/api/v1/vaults/{vault_id}/members")),
        &outsider_jwt,
    )
    .await;

    assert_eq!(resp.status_code(), StatusCode::NOT_FOUND);
}

/// A `viewer` may list members. Seeing who else holds a key to a vault you hold
/// a key to is the minimum needed to notice a wrong grant — restricting it to
/// admins would blind the people most likely to spot one.
#[tokio::test]
async fn a_viewer_may_list_members() {
    let server = test_app().await;
    let (_owner, owner_jwt) = verified_user(&server).await;
    let vault_id = create_vault(&server, &owner_jwt).await;

    let email = unique_email("viewer");
    let reg = server
        .post("/api/v1/auth/register")
        .json(&register_payload(&email))
        .await;
    reg.assert_status(StatusCode::CREATED);
    let viewer_id =
        Uuid::parse_str(reg.json::<serde_json::Value>()["user_id"].as_str().unwrap()).unwrap();

    bearer(
        server.post(&format!("/api/v1/vaults/{vault_id}/members")),
        &owner_jwt,
    )
    .json(&serde_json::json!({
        "user_email": email,
        "role": "viewer",
        "encrypted_vault_key": "Zm9v",
        "eph_pub_key": "YmFy",
        "mlkem_ciphertext": "Y".repeat(1452),
    }))
    .await
    .assert_status(StatusCode::CREATED);

    let viewer_jwt = jwt_service()
        .await
        .issue(viewer_id, Uuid::new_v4(), true)
        .unwrap();

    let resp = bearer(
        server.get(&format!("/api/v1/vaults/{vault_id}/members")),
        &viewer_jwt,
    )
    .await;
    resp.assert_status_ok();
    assert_eq!(
        resp.json::<serde_json::Value>()["members"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

/// `has_mlkem_key` is false for an account predating F1, so a client can say why
/// a re-share or re-key will refuse them rather than failing at the point of use.
#[tokio::test]
async fn member_list_flags_a_member_with_no_post_quantum_key() {
    let server = test_app().await;
    let (_owner, jwt) = verified_user(&server).await;
    let vault_id = create_vault(&server, &jwt).await;

    let email = unique_email("prepq");
    server
        .post("/api/v1/auth/register")
        .json(&register_payload(&email))
        .await
        .assert_status(StatusCode::CREATED);

    bearer(
        server.post(&format!("/api/v1/vaults/{vault_id}/members")),
        &jwt,
    )
    .json(&serde_json::json!({
        "user_email": email,
        "role": "developer",
        "encrypted_vault_key": "Zm9v",
        "eph_pub_key": "YmFy",
        "mlkem_ciphertext": "Y".repeat(1452),
    }))
    .await
    .assert_status(StatusCode::CREATED);

    // Simulate the pre-F1 account: the share already happened, the key is gone.
    let config = test_config().await;
    let db = sqlx::PgPool::connect(&config.database_url).await.unwrap();
    sqlx::query("UPDATE users SET mlkem_public_key = NULL WHERE email = $1")
        .bind(&email)
        .execute(&db)
        .await
        .unwrap();

    let body = bearer(
        server.get(&format!("/api/v1/vaults/{vault_id}/members")),
        &jwt,
    )
    .await
    .json::<serde_json::Value>();

    let them = body["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["email"] == email.as_str())
        .expect("the member should still be listed");

    assert_eq!(them["has_mlkem_key"], false);
}

// ─── Phase 3 step 2: the role ladder ──────────────────────────────────────────

/// Share a vault with a fresh account at `role`, returning their id and a JWT.
async fn member_at(
    server: &TestServer,
    owner_jwt: &str,
    vault_id: Uuid,
    role: &str,
) -> (Uuid, String) {
    let email = unique_email(role);
    let reg = server
        .post("/api/v1/auth/register")
        .json(&register_payload(&email))
        .await;
    reg.assert_status(StatusCode::CREATED);
    let id = Uuid::parse_str(reg.json::<serde_json::Value>()["user_id"].as_str().unwrap()).unwrap();

    bearer(
        server.post(&format!("/api/v1/vaults/{vault_id}/members")),
        owner_jwt,
    )
    .json(&serde_json::json!({
        "user_email": email,
        "role": role,
        "encrypted_vault_key": "Zm9v",
        "eph_pub_key": "YmFy",
        "mlkem_ciphertext": "Y".repeat(1452),
    }))
    .await
    .assert_status(StatusCode::CREATED);

    let jwt = jwt_service().await.issue(id, Uuid::new_v4(), true).unwrap();
    (id, jwt)
}

#[tokio::test]
async fn a_viewer_may_read_but_not_push() {
    let server = test_app().await;
    let (_owner, owner_jwt) = verified_user(&server).await;
    let vault_id = create_vault(&server, &owner_jwt).await;
    let (_vid, viewer_jwt) = member_at(&server, &owner_jwt, vault_id, "viewer").await;

    // Reads: allowed.
    bearer(
        server.get(&format!("/api/v1/vaults/{vault_id}/versions")),
        &viewer_jwt,
    )
    .await
    .assert_status_ok();

    // Push: refused with 403 — they are a member, so the vault's existence is
    // not a secret from them; only the action is refused.
    let resp = bearer(
        server.post(&format!("/api/v1/vaults/{vault_id}/versions")),
        &viewer_jwt,
    )
    .json(&serde_json::json!({
        "nonce": "AAAAAAAAAAAAAAAA",
        "ciphertext": "Zm9v",
        "blob_hash": "a".repeat(64),
        "key_names": ["A"],
        "key_count": 1,
        "base_version": 0,
    }))
    .await;
    assert_eq!(resp.status_code(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_developer_may_push_but_not_share_or_delete() {
    let server = test_app().await;
    let (_owner, owner_jwt) = verified_user(&server).await;
    let vault_id = create_vault(&server, &owner_jwt).await;
    let (_did, dev_jwt) = member_at(&server, &owner_jwt, vault_id, "developer").await;

    let outsider = unique_email("outsider");
    server
        .post("/api/v1/auth/register")
        .json(&register_payload(&outsider))
        .await
        .assert_status(StatusCode::CREATED);

    // Sharing hands out a key — not a developer-level act.
    let share = bearer(
        server.post(&format!("/api/v1/vaults/{vault_id}/members")),
        &dev_jwt,
    )
    .json(&serde_json::json!({
        "user_email": outsider,
        "role": "viewer",
        "encrypted_vault_key": "Zm9v",
        "eph_pub_key": "YmFy",
        "mlkem_ciphertext": "Y".repeat(1452),
    }))
    .await;
    assert_eq!(share.status_code(), StatusCode::FORBIDDEN);

    // Deleting the vault is owner-only.
    let del = bearer(
        server.delete(&format!("/api/v1/vaults/{vault_id}")),
        &dev_jwt,
    )
    .await;
    assert_eq!(del.status_code(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn an_admin_may_share_but_not_delete_the_vault() {
    let server = test_app().await;
    let (_owner, owner_jwt) = verified_user(&server).await;
    let vault_id = create_vault(&server, &owner_jwt).await;
    let (_aid, admin_jwt) = member_at(&server, &owner_jwt, vault_id, "admin").await;

    let target = unique_email("shared-by-admin");
    server
        .post("/api/v1/auth/register")
        .json(&register_payload(&target))
        .await
        .assert_status(StatusCode::CREATED);

    bearer(
        server.post(&format!("/api/v1/vaults/{vault_id}/members")),
        &admin_jwt,
    )
    .json(&serde_json::json!({
        "user_email": target,
        "role": "developer",
        "encrypted_vault_key": "Zm9v",
        "eph_pub_key": "YmFy",
        "mlkem_ciphertext": "Y".repeat(1452),
    }))
    .await
    .assert_status(StatusCode::CREATED);

    let del = bearer(
        server.delete(&format!("/api/v1/vaults/{vault_id}")),
        &admin_jwt,
    )
    .await;
    assert_eq!(del.status_code(), StatusCode::FORBIDDEN);
}

/// ⚠️ You may only grant a role you outrank.
///
/// An admin granting `admin` would create a peer neither could remove, leaving
/// only the owner able to clean up.
#[tokio::test]
async fn an_admin_cannot_grant_admin() {
    let server = test_app().await;
    let (_owner, owner_jwt) = verified_user(&server).await;
    let vault_id = create_vault(&server, &owner_jwt).await;
    let (_aid, admin_jwt) = member_at(&server, &owner_jwt, vault_id, "admin").await;

    let target = unique_email("would-be-admin");
    server
        .post("/api/v1/auth/register")
        .json(&register_payload(&target))
        .await
        .assert_status(StatusCode::CREATED);

    let resp = bearer(
        server.post(&format!("/api/v1/vaults/{vault_id}/members")),
        &admin_jwt,
    )
    .json(&serde_json::json!({
        "user_email": target,
        "role": "admin",
        "encrypted_vault_key": "Zm9v",
        "eph_pub_key": "YmFy",
        "mlkem_ciphertext": "Y".repeat(1452),
    }))
    .await;
    assert_eq!(resp.status_code(), StatusCode::FORBIDDEN);

    // The owner, who does outrank admin, may.
    bearer(
        server.post(&format!("/api/v1/vaults/{vault_id}/members")),
        &owner_jwt,
    )
    .json(&serde_json::json!({
        "user_email": target,
        "role": "admin",
        "encrypted_vault_key": "Zm9v",
        "eph_pub_key": "YmFy",
        "mlkem_ciphertext": "Y".repeat(1452),
    }))
    .await
    .assert_status(StatusCode::CREATED);
}

/// ⚠️ Removal requires **outranking**, which gets "admins cannot remove other
/// admins" for free — `Admin > Admin` is false. Two admins cannot evict each
/// other in a race; only the owner settles it.
#[tokio::test]
async fn an_admin_cannot_remove_another_admin_but_the_owner_can() {
    let server = test_app().await;
    let (_owner, owner_jwt) = verified_user(&server).await;
    let vault_id = create_vault(&server, &owner_jwt).await;

    let (_a1, admin1_jwt) = member_at(&server, &owner_jwt, vault_id, "admin").await;
    let (admin2_id, _a2jwt) = member_at(&server, &owner_jwt, vault_id, "admin").await;

    let peer = bearer(
        server.delete(&format!("/api/v1/vaults/{vault_id}/members/{admin2_id}")),
        &admin1_jwt,
    )
    .await;
    assert_eq!(peer.status_code(), StatusCode::FORBIDDEN);

    bearer(
        server.delete(&format!("/api/v1/vaults/{vault_id}/members/{admin2_id}")),
        &owner_jwt,
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);
}

/// Leaving is always allowed, whatever your rank.
#[tokio::test]
async fn any_member_may_remove_themselves() {
    let server = test_app().await;
    let (_owner, owner_jwt) = verified_user(&server).await;
    let vault_id = create_vault(&server, &owner_jwt).await;
    let (viewer_id, viewer_jwt) = member_at(&server, &owner_jwt, vault_id, "viewer").await;

    bearer(
        server.delete(&format!("/api/v1/vaults/{vault_id}/members/{viewer_id}")),
        &viewer_jwt,
    )
    .await
    .assert_status(StatusCode::NO_CONTENT);
}

/// ⚠️ An ownerless vault has nobody who can delete it or promote a replacement,
/// and there is no transfer-ownership endpoint. Refusing is recoverable.
#[tokio::test]
async fn the_owner_cannot_be_removed_even_by_themselves() {
    let server = test_app().await;
    let (owner_id, owner_jwt) = verified_user(&server).await;
    let vault_id = create_vault(&server, &owner_jwt).await;

    let resp = bearer(
        server.delete(&format!("/api/v1/vaults/{vault_id}/members/{owner_id}")),
        &owner_jwt,
    )
    .await;
    assert_eq!(resp.status_code(), StatusCode::CONFLICT);
}

/// A non-member gets 404 everywhere, never 403 — a distinct "exists but not
/// yours" would let anyone probe for vault ids.
#[tokio::test]
async fn a_non_member_gets_404_not_403_across_vault_routes() {
    let server = test_app().await;
    let (_owner, owner_jwt) = verified_user(&server).await;
    let vault_id = create_vault(&server, &owner_jwt).await;
    let (_out, outsider_jwt) = verified_user(&server).await;

    for path in [
        format!("/api/v1/vaults/{vault_id}/members"),
        format!("/api/v1/vaults/{vault_id}/versions"),
        format!("/api/v1/vaults/{vault_id}/versions/latest"),
        format!("/api/v1/vaults/{vault_id}/my-key"),
    ] {
        let resp = bearer(server.get(&path), &outsider_jwt).await;
        assert_eq!(
            resp.status_code(),
            StatusCode::NOT_FOUND,
            "{path} leaked the vault's existence to a non-member"
        );
    }
}

/// Migration 005: an unknown role is unstorable. A typo would otherwise read as
/// "this user has no permission" rather than "this row is corrupt".
#[tokio::test]
async fn an_unknown_role_cannot_be_stored() {
    let server = test_app().await;
    let (owner_id, jwt) = verified_user(&server).await;
    let vault_id = create_vault(&server, &jwt).await;

    let config = test_config().await;
    let db = sqlx::PgPool::connect(&config.database_url).await.unwrap();

    for bad in ["admni", "Admin", "god", ""] {
        let r =
            sqlx::query("UPDATE vault_members SET role = $1 WHERE vault_id = $2 AND user_id = $3")
                .bind(bad)
                .bind(vault_id)
                .bind(owner_id)
                .execute(&db)
                .await;
        assert!(r.is_err(), "the database accepted role {bad:?}");
    }
}

// ─── Phase 3 step 3: changing a role ──────────────────────────────────────────

#[tokio::test]
async fn an_owner_may_change_a_members_role() {
    let server = test_app().await;
    let (_owner, owner_jwt) = verified_user(&server).await;
    let vault_id = create_vault(&server, &owner_jwt).await;
    let (viewer_id, viewer_jwt) = member_at(&server, &owner_jwt, vault_id, "viewer").await;

    // As a viewer, pushing is refused.
    //
    // `blob_hash` is computed rather than filler here, unlike the pure-403 tests
    // above: those never reach the body, but this push has to actually succeed
    // after the promotion, and the server verifies the hash against the
    // ciphertext it was given.
    let push = serde_json::json!({
        "nonce": "AAAAAAAAAAAAAAAA",
        "ciphertext": "Zm9v",
        "blob_hash": blake3::hash(b"foo").to_hex().to_string(),
        "key_names": ["A"],
        "key_count": 1,
        "base_version": 0,
    });
    assert_eq!(
        bearer(
            server.post(&format!("/api/v1/vaults/{vault_id}/versions")),
            &viewer_jwt
        )
        .json(&push)
        .await
        .status_code(),
        StatusCode::FORBIDDEN
    );

    // Promote to developer.
    bearer(
        server.patch(&format!("/api/v1/vaults/{vault_id}/members/{viewer_id}")),
        &owner_jwt,
    )
    .json(&serde_json::json!({ "role": "developer" }))
    .await
    .assert_status(StatusCode::NO_CONTENT);

    // The same push now succeeds — the change took effect, not merely returned 204.
    bearer(
        server.post(&format!("/api/v1/vaults/{vault_id}/versions")),
        &viewer_jwt,
    )
    .json(&push)
    .await
    .assert_status(StatusCode::CREATED);
}

/// ⚠️ You must outrank both what they are and what you are making them.
/// Outranking only the current role would let an admin promote someone to admin,
/// which is the one-way door `add_member` already refuses.
#[tokio::test]
async fn an_admin_cannot_promote_anyone_to_admin() {
    let server = test_app().await;
    let (_owner, owner_jwt) = verified_user(&server).await;
    let vault_id = create_vault(&server, &owner_jwt).await;
    let (_aid, admin_jwt) = member_at(&server, &owner_jwt, vault_id, "admin").await;
    let (dev_id, _dj) = member_at(&server, &owner_jwt, vault_id, "developer").await;

    let resp = bearer(
        server.patch(&format!("/api/v1/vaults/{vault_id}/members/{dev_id}")),
        &admin_jwt,
    )
    .json(&serde_json::json!({ "role": "admin" }))
    .await;
    assert_eq!(resp.status_code(), StatusCode::FORBIDDEN);

    // Demoting a developer to viewer is fine — the admin outranks both.
    bearer(
        server.patch(&format!("/api/v1/vaults/{vault_id}/members/{dev_id}")),
        &admin_jwt,
    )
    .json(&serde_json::json!({ "role": "viewer" }))
    .await
    .assert_status(StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn an_admin_cannot_change_another_admins_role() {
    let server = test_app().await;
    let (_owner, owner_jwt) = verified_user(&server).await;
    let vault_id = create_vault(&server, &owner_jwt).await;
    let (_a1, admin1_jwt) = member_at(&server, &owner_jwt, vault_id, "admin").await;
    let (admin2_id, _a2) = member_at(&server, &owner_jwt, vault_id, "admin").await;

    let resp = bearer(
        server.patch(&format!("/api/v1/vaults/{vault_id}/members/{admin2_id}")),
        &admin1_jwt,
    )
    .json(&serde_json::json!({ "role": "viewer" }))
    .await;
    assert_eq!(resp.status_code(), StatusCode::FORBIDDEN);
}

/// Demoting the owner would leave the vault with nobody who can delete it or
/// promote a replacement.
#[tokio::test]
async fn the_owners_role_cannot_be_changed() {
    let server = test_app().await;
    let (owner_id, owner_jwt) = verified_user(&server).await;
    let vault_id = create_vault(&server, &owner_jwt).await;

    let resp = bearer(
        server.patch(&format!("/api/v1/vaults/{vault_id}/members/{owner_id}")),
        &owner_jwt,
    )
    .json(&serde_json::json!({ "role": "admin" }))
    .await;
    assert_eq!(resp.status_code(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn a_role_change_rejects_owner_and_unknown_roles() {
    let server = test_app().await;
    let (_owner, owner_jwt) = verified_user(&server).await;
    let vault_id = create_vault(&server, &owner_jwt).await;
    let (dev_id, _dj) = member_at(&server, &owner_jwt, vault_id, "developer").await;

    for bad in ["owner", "admni", "Admin", "", "god"] {
        let resp = bearer(
            server.patch(&format!("/api/v1/vaults/{vault_id}/members/{dev_id}")),
            &owner_jwt,
        )
        .json(&serde_json::json!({ "role": bad }))
        .await;
        assert_ne!(
            resp.status_code(),
            StatusCode::NO_CONTENT,
            "role {bad:?} should be refused"
        );
    }
}

/// A developer cannot change anyone's role — the route is admin-gated.
#[tokio::test]
async fn a_developer_cannot_change_roles() {
    let server = test_app().await;
    let (_owner, owner_jwt) = verified_user(&server).await;
    let vault_id = create_vault(&server, &owner_jwt).await;
    let (_did, dev_jwt) = member_at(&server, &owner_jwt, vault_id, "developer").await;
    let (viewer_id, _vj) = member_at(&server, &owner_jwt, vault_id, "viewer").await;

    let resp = bearer(
        server.patch(&format!("/api/v1/vaults/{vault_id}/members/{viewer_id}")),
        &dev_jwt,
    )
    .json(&serde_json::json!({ "role": "developer" }))
    .await;
    assert_eq!(resp.status_code(), StatusCode::FORBIDDEN);
}

// ─── Phase 3 step 5: re-keying ────────────────────────────────────────────────

/// Push `n` versions and return their numbers.
async fn push_versions(server: &TestServer, jwt: &str, vault_id: Uuid, n: i32) -> Vec<i32> {
    let mut nums = Vec::new();
    for i in 1..=n {
        // Encode real bytes rather than hand-writing base64: appending a digit
        // to a literal produces a string whose length is not a multiple of four,
        // which is not valid base64 and fails before reaching the server.
        let raw = format!("ciphertext-v{i}").into_bytes();
        let ct = {
            use base64ct::Encoding;
            base64ct::Base64::encode_string(&raw)
        };
        let resp = bearer(
            server.post(&format!("/api/v1/vaults/{vault_id}/versions")),
            jwt,
        )
        .json(&serde_json::json!({
            "nonce": "AAAAAAAAAAAAAAAA",
            "ciphertext": ct,
            "blob_hash": blake3::hash(&raw).to_hex().to_string(),
            "key_names": ["A"],
            "key_count": 1,
            "base_version": i - 1,
        }))
        .await;
        resp.assert_status(StatusCode::CREATED);
        nums.push(i);
    }
    nums
}

/// Stage one re-encrypted blob and return the `blob_key` the swap must quote.
async fn stage(
    server: &TestServer,
    jwt: &str,
    vault_id: Uuid,
    version_num: i32,
) -> (String, String, i32) {
    let raw = format!("rekeyed-v{version_num}").into_bytes();
    let ct = {
        use base64ct::Encoding;
        base64ct::Base64::encode_string(&raw)
    };
    let hash = blake3::hash(&raw).to_hex().to_string();
    let resp = bearer(
        server.post(&format!("/api/v1/vaults/{vault_id}/rekey/blobs")),
        jwt,
    )
    .json(&serde_json::json!({
        "version_num": version_num,
        "nonce": "AAAAAAAAAAAAAAAA",
        "ciphertext": ct,
        "blob_hash": hash,
    }))
    .await;
    resp.assert_status_ok();
    let body = resp.json::<serde_json::Value>();
    (
        body["blob_key"].as_str().unwrap().to_string(),
        hash,
        body["blob_size_bytes"].as_i64().unwrap() as i32,
    )
}

fn wrap_for(user_id: Uuid) -> serde_json::Value {
    serde_json::json!({
        "user_id": user_id,
        "encrypted_vault_key": "bmV3d3JhcA==",
        "eph_pub_key": "bmV3",
        "mlkem_ciphertext": "Z".repeat(1452),
    })
}

#[tokio::test]
async fn a_rekey_repoints_every_version_and_rewraps_every_member() {
    let server = test_app().await;
    let (owner_id, owner_jwt) = verified_user(&server).await;
    let vault_id = create_vault(&server, &owner_jwt).await;
    let (dev_id, _dj) = member_at(&server, &owner_jwt, vault_id, "developer").await;
    push_versions(&server, &owner_jwt, vault_id, 3).await;

    let mut versions = Vec::new();
    for v in 1..=3 {
        let (blob_key, blob_hash, size) = stage(&server, &owner_jwt, vault_id, v).await;
        versions.push(serde_json::json!({
            "version_num": v, "blob_key": blob_key,
            "blob_hash": blob_hash, "blob_size_bytes": size,
        }));
    }

    let resp = bearer(
        server.post(&format!("/api/v1/vaults/{vault_id}/rekey")),
        &owner_jwt,
    )
    .json(&serde_json::json!({
        "versions": versions,
        "members": [wrap_for(owner_id), wrap_for(dev_id)],
    }))
    .await;
    resp.assert_status_ok();
    let body = resp.json::<serde_json::Value>();
    assert_eq!(body["versions_rekeyed"], 3);
    assert_eq!(body["members_rewrapped"], 2);

    // The owner's stored key really did change.
    let mine = bearer(
        server.get(&format!("/api/v1/vaults/{vault_id}/my-key")),
        &owner_jwt,
    )
    .await
    .json::<serde_json::Value>();
    assert_eq!(mine["encrypted_vault_key"], "bmV3d3JhcA==");
    assert_eq!(mine["eph_pub_key"], "bmV3");
}

/// ⚠️ The invariant this endpoint exists to hold. A vault whose versions are
/// split across two keys cannot be opened by anyone — the old key fails on the
/// new blobs and the new key fails on the old ones.
#[tokio::test]
async fn a_rekey_missing_a_version_is_rejected_whole() {
    let server = test_app().await;
    let (owner_id, owner_jwt) = verified_user(&server).await;
    let vault_id = create_vault(&server, &owner_jwt).await;
    push_versions(&server, &owner_jwt, vault_id, 3).await;

    // Only two of the three.
    let mut versions = Vec::new();
    for v in 1..=2 {
        let (blob_key, blob_hash, size) = stage(&server, &owner_jwt, vault_id, v).await;
        versions.push(serde_json::json!({
            "version_num": v, "blob_key": blob_key,
            "blob_hash": blob_hash, "blob_size_bytes": size,
        }));
    }

    let resp = bearer(
        server.post(&format!("/api/v1/vaults/{vault_id}/rekey")),
        &owner_jwt,
    )
    .json(&serde_json::json!({ "versions": versions, "members": [wrap_for(owner_id)] }))
    .await;
    assert_eq!(resp.status_code(), StatusCode::CONFLICT);

    // And NOTHING moved — not even the two that were supplied.
    let mine = bearer(
        server.get(&format!("/api/v1/vaults/{vault_id}/my-key")),
        &owner_jwt,
    )
    .await
    .json::<serde_json::Value>();
    assert_eq!(
        mine["encrypted_vault_key"], "Zm9v",
        "a rejected re-key must leave the vault exactly as it was"
    );
}

/// A member left on the old key loses access to the whole vault.
#[tokio::test]
async fn a_rekey_missing_a_member_is_rejected_whole() {
    let server = test_app().await;
    let (owner_id, owner_jwt) = verified_user(&server).await;
    let vault_id = create_vault(&server, &owner_jwt).await;
    let (_dev_id, _dj) = member_at(&server, &owner_jwt, vault_id, "developer").await;
    push_versions(&server, &owner_jwt, vault_id, 1).await;

    let (blob_key, blob_hash, size) = stage(&server, &owner_jwt, vault_id, 1).await;

    let resp = bearer(
        server.post(&format!("/api/v1/vaults/{vault_id}/rekey")),
        &owner_jwt,
    )
    .json(&serde_json::json!({
        "versions": [{"version_num": 1, "blob_key": blob_key,
                      "blob_hash": blob_hash, "blob_size_bytes": size}],
        "members": [wrap_for(owner_id)],   // developer omitted
    }))
    .await;
    assert_eq!(resp.status_code(), StatusCode::CONFLICT);
}

/// Revocation and rotation in one transaction: no window where the member is
/// gone but the key has not moved, or the key has moved but they are still in.
#[tokio::test]
async fn a_rekey_can_revoke_a_member_atomically() {
    let server = test_app().await;
    let (owner_id, owner_jwt) = verified_user(&server).await;
    let vault_id = create_vault(&server, &owner_jwt).await;
    let (leaver_id, leaver_jwt) = member_at(&server, &owner_jwt, vault_id, "developer").await;
    push_versions(&server, &owner_jwt, vault_id, 2).await;

    let mut versions = Vec::new();
    for v in 1..=2 {
        let (blob_key, blob_hash, size) = stage(&server, &owner_jwt, vault_id, v).await;
        versions.push(serde_json::json!({
            "version_num": v, "blob_key": blob_key,
            "blob_hash": blob_hash, "blob_size_bytes": size,
        }));
    }

    bearer(
        server.post(&format!("/api/v1/vaults/{vault_id}/rekey")),
        &owner_jwt,
    )
    .json(&serde_json::json!({
        "versions": versions,
        "members": [wrap_for(owner_id)],
        "remove_user_id": leaver_id,
    }))
    .await
    .assert_status_ok();

    // They are out, and the vault reads as gone to them.
    assert_eq!(
        bearer(
            server.get(&format!("/api/v1/vaults/{vault_id}/my-key")),
            &leaver_jwt
        )
        .await
        .status_code(),
        StatusCode::NOT_FOUND
    );

    let members = bearer(
        server.get(&format!("/api/v1/vaults/{vault_id}/members")),
        &owner_jwt,
    )
    .await
    .json::<serde_json::Value>();
    assert_eq!(members["members"].as_array().unwrap().len(), 1);
}

/// ⚠️ Wrapping the new key for the person being removed would undo the whole
/// operation, silently.
#[tokio::test]
async fn a_rekey_cannot_hand_the_new_key_to_the_member_it_removes() {
    let server = test_app().await;
    let (owner_id, owner_jwt) = verified_user(&server).await;
    let vault_id = create_vault(&server, &owner_jwt).await;
    let (leaver_id, _lj) = member_at(&server, &owner_jwt, vault_id, "developer").await;
    push_versions(&server, &owner_jwt, vault_id, 1).await;

    let (blob_key, blob_hash, size) = stage(&server, &owner_jwt, vault_id, 1).await;

    let resp = bearer(
        server.post(&format!("/api/v1/vaults/{vault_id}/rekey")),
        &owner_jwt,
    )
    .json(&serde_json::json!({
        "versions": [{"version_num": 1, "blob_key": blob_key,
                      "blob_hash": blob_hash, "blob_size_bytes": size}],
        "members": [wrap_for(owner_id), wrap_for(leaver_id)],
        "remove_user_id": leaver_id,
    }))
    .await;
    assert_eq!(resp.status_code(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn a_developer_cannot_rekey_and_an_admin_can() {
    let server = test_app().await;
    let (owner_id, owner_jwt) = verified_user(&server).await;
    let vault_id = create_vault(&server, &owner_jwt).await;
    let (_did, dev_jwt) = member_at(&server, &owner_jwt, vault_id, "developer").await;
    let (admin_id, admin_jwt) = member_at(&server, &owner_jwt, vault_id, "admin").await;
    push_versions(&server, &owner_jwt, vault_id, 1).await;

    assert_eq!(
        bearer(
            server.post(&format!("/api/v1/vaults/{vault_id}/rekey/blobs")),
            &dev_jwt
        )
        .json(&serde_json::json!({
            "version_num": 1, "nonce": "AAAAAAAAAAAAAAAA",
            "ciphertext": "Zm9v", "blob_hash": blake3::hash(b"foo").to_hex().to_string(),
        }))
        .await
        .status_code(),
        StatusCode::FORBIDDEN
    );

    // An admin may — decided 2026-09-19, so a team whose owner is away can still
    // revoke someone.
    let (blob_key, blob_hash, size) = stage(&server, &admin_jwt, vault_id, 1).await;
    let dev_id = Uuid::parse_str(
        bearer(
            server.get(&format!("/api/v1/vaults/{vault_id}/members")),
            &owner_jwt,
        )
        .await
        .json::<serde_json::Value>()["members"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["role"] == "developer")
            .unwrap()["user_id"]
            .as_str()
            .unwrap(),
    )
    .unwrap();

    bearer(
        server.post(&format!("/api/v1/vaults/{vault_id}/rekey")),
        &admin_jwt,
    )
    .json(&serde_json::json!({
        "versions": [{"version_num": 1, "blob_key": blob_key,
                      "blob_hash": blob_hash, "blob_size_bytes": size}],
        "members": [wrap_for(owner_id), wrap_for(admin_id), wrap_for(dev_id)],
    }))
    .await
    .assert_status_ok();
}

/// Staging a blob for a version that does not exist would leave an object
/// nothing can ever reference.
#[tokio::test]
async fn staging_a_blob_for_an_unknown_version_is_refused() {
    let server = test_app().await;
    let (_owner, owner_jwt) = verified_user(&server).await;
    let vault_id = create_vault(&server, &owner_jwt).await;
    push_versions(&server, &owner_jwt, vault_id, 1).await;

    let resp = bearer(
        server.post(&format!("/api/v1/vaults/{vault_id}/rekey/blobs")),
        &owner_jwt,
    )
    .json(&serde_json::json!({
        "version_num": 99,
        "nonce": "AAAAAAAAAAAAAAAA",
        "ciphertext": "Zm9v",
        "blob_hash": blake3::hash(b"foo").to_hex().to_string(),
    }))
    .await;
    assert_eq!(resp.status_code(), StatusCode::NOT_FOUND);
}

/// Staging must verify the hash, so a corrupt upload fails immediately rather
/// than at the swap after everything else has been uploaded.
#[tokio::test]
async fn staging_verifies_the_blob_hash() {
    let server = test_app().await;
    let (_owner, owner_jwt) = verified_user(&server).await;
    let vault_id = create_vault(&server, &owner_jwt).await;
    push_versions(&server, &owner_jwt, vault_id, 1).await;

    let resp = bearer(
        server.post(&format!("/api/v1/vaults/{vault_id}/rekey/blobs")),
        &owner_jwt,
    )
    .json(&serde_json::json!({
        "version_num": 1,
        "nonce": "AAAAAAAAAAAAAAAA",
        "ciphertext": "Zm9v",
        "blob_hash": "a".repeat(64),
    }))
    .await;
    assert_eq!(resp.status_code(), StatusCode::UNPROCESSABLE_ENTITY);
}
