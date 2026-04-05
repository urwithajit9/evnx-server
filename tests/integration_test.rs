// tests/integration_test.rs

use axum_test::TestServer;

// Helper: start a test server with an in-memory state
async fn test_app() -> TestServer {
    // Use a separate test database (set TEST_DATABASE_URL env var)
    let config = evnx_server::config::Config::from_env()
        .expect("Test config");
    let db = sqlx::PgPool::connect(&config.database_url)
        .await.unwrap();
    sqlx::migrate!("./migrations").run(&db).await.unwrap();

    let state = evnx_server::state::AppState::new_for_test(db, config).await;
    let app = evnx_server::routes::create_router(state);
    TestServer::new(app).unwrap()
}

#[tokio::test]
async fn test_health_endpoint() {
    let server = test_app().await;
    let resp = server.get("/health").await;
    resp.assert_status_ok();
    let json = resp.json::<serde_json::Value>();
    assert_eq!(json["status"], "ok");
}

#[tokio::test]
async fn test_register_returns_201() {
    let server = test_app().await;
    let resp = server.post("/api/v1/auth/register")
        .json(&serde_json::json!({
            "email": "test-register@example.com",
            "srp_verifier": "a".repeat(512),
            "srp_salt": "A".repeat(44),
            "argon2_salt": "B".repeat(44),
            "ed25519_public_key": "C".repeat(44),
            "encrypted_private_key": "D".repeat(80),
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
}

#[tokio::test]
async fn test_register_duplicate_email_returns_409() {
    let server = test_app().await;
    let payload = serde_json::json!({
        "email": "duplicate@example.com",
        "srp_verifier": "a".repeat(512),
        "srp_salt": "A".repeat(44),
        "argon2_salt": "B".repeat(44),
        "ed25519_public_key": "C".repeat(44),
        "encrypted_private_key": "D".repeat(80),
    });
    server.post("/api/v1/auth/register").json(&payload).await;
    let resp = server.post("/api/v1/auth/register").json(&payload).await;
    resp.assert_status(axum::http::StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_unauthenticated_vault_returns_401() {
    let server = test_app().await;
    let resp = server.get("/api/v1/vaults").await;
    resp.assert_status(axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_rate_limit_triggers_after_5_attempts() {
    let server = test_app().await;
    for _ in 0..5 {
        server.post("/api/v1/auth/srp/init")
            .json(&serde_json::json!({ "email": "rl@example.com", "client_public": "a".repeat(512) }))
            .await;
    }
    let resp = server.post("/api/v1/auth/srp/init")
        .json(&serde_json::json!({ "email": "rl@example.com", "client_public": "a".repeat(512) }))
        .await;
    resp.assert_status(axum::http::StatusCode::TOO_MANY_REQUESTS);
}