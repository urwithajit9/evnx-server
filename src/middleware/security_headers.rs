// src/middleware/security_headers.rs

//! Response hardening headers.
//!
//! This file existed from early on but was never declared in `middleware/mod.rs`,
//! so it had never been compiled and the server shipped none of these headers.

use axum::{
    extract::Request, extract::State, http::HeaderValue, middleware::Next, response::Response,
};

use crate::state::AppState;

/// Attach security headers to every response.
///
/// Most of the API returns JSON, but `GET /auth/verify-email` returns a small HTML
/// page for a browser click, so the browser-facing headers are not redundant.
pub async fn add_security_headers(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();

    // Never let a browser second-guess a declared content type.
    headers.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );

    // No page of ours belongs in a frame. `frame-ancestors` in the CSP below is
    // the modern equivalent; this stays for older browsers that ignore it.
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));

    // An email-verification URL carries a single-use token in its query string.
    // `no-referrer` keeps that out of the Referer header if the page ever links
    // outward, which is stricter than the usual strict-origin-when-cross-origin.
    headers.insert("Referrer-Policy", HeaderValue::from_static("no-referrer"));

    // The API serves JSON and one static HTML page that uses inline `style`
    // attributes. Everything else is denied: no scripts, no images, no framing,
    // no base-tag rewriting.
    headers.insert(
        "Content-Security-Policy",
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
        ),
    );

    // HSTS only where TLS actually terminates. Sending it over plain HTTP in
    // development would pin localhost to HTTPS in the developer's browser, which
    // is both useless and irritating to undo.
    if state.config.is_production() {
        headers.insert(
            "Strict-Transport-Security",
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }

    // Deliberately NOT set: X-XSS-Protection. The header is obsolete, ignored by
    // current browsers, and its filter introduced vulnerabilities in the old ones
    // that honoured it. OWASP recommends omitting it rather than setting `1`.

    response
}
