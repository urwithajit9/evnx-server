// src/middleware/security_headers.rs

use axum::{extract::Request, middleware::Next, response::Response};

pub async fn add_security_headers(
    req: Request,
    next: Next,
) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    use axum::http::HeaderValue;

    headers.insert("X-Content-Type-Options",
        HeaderValue::from_static("nosniff"));
    headers.insert("X-Frame-Options",
        HeaderValue::from_static("DENY"));
    headers.insert("Referrer-Policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"));
    headers.insert("X-XSS-Protection",
        HeaderValue::from_static("1; mode=block"));
    // Only in production (requires HTTPS):
    // headers.insert("Strict-Transport-Security",
    //     HeaderValue::from_static("max-age=31536000; includeSubDomains"));

    response
}