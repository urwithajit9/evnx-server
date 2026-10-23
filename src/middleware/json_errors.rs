// src/middleware/json_errors.rs

//! Every error response carries the `{ "error", "code" }` envelope (I-305).
//!
//! Every [`crate::errors::AppError`] already does. What did not were the
//! responses produced **before** a handler runs: a body the `Json` extractor
//! rejects came back as `text/plain` (400, 415, 422), and an unknown route or a
//! wrong method as an **empty** 404 or 405. Clients branch on `code`, so the CLI
//! found none, fell back to the status, and printed "unexpected response from
//! server: HTTP 422" — losing the sentence that said what was wrong.
//!
//! One layer rather than a custom extractor in every handler: it also covers
//! path and query rejections, the 413 from the body limit, and the router's own
//! 404/405, none of which a handler ever sees.
//!
//! ⚠️ **Only plain-text and empty bodies are rewritten.** `GET
//! /auth/verify-email` answers a browser with an HTML page, on failure too
//! (400), and has to stay HTML. JSON passes through untouched, and so does
//! every success.
//!
//! ⚠️ **400, 415 and 422 become `VALIDATION_ERROR`, not a new code.** Every
//! installed CLI maps that code to the server's sentence; a new one would fall
//! through to "unexpected response" in all of them (the I-306 trap). The
//! status is left exactly as the framework set it.

use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// The most of a plain-text error body read back into the message. The
/// framework's rejections are one sentence; anything longer is not one of them.
const MAX_TEXT: usize = 4 * 1024;

pub async fn json_error_bodies(req: Request, next: Next) -> Response {
    let response = next.run(req).await;
    let status = response.status();
    if !(status.is_client_error() || status.is_server_error()) {
        return response;
    }

    let plain_or_empty = match response.headers().get(header::CONTENT_TYPE) {
        None => true,
        Some(ct) => ct
            .to_str()
            .map(|ct| ct.starts_with("text/plain"))
            .unwrap_or(false),
    };
    if !plain_or_empty {
        return response;
    }

    let (parts, body) = response.into_parts();
    let text = match axum::body::to_bytes(body, MAX_TEXT).await {
        Ok(bytes) => String::from_utf8_lossy(&bytes).trim().to_string(),
        Err(_) => String::new(),
    };
    let reason = status.canonical_reason().unwrap_or("Error");

    let (code, message) = match status {
        StatusCode::BAD_REQUEST
        | StatusCode::UNSUPPORTED_MEDIA_TYPE
        | StatusCode::UNPROCESSABLE_ENTITY => ("VALIDATION_ERROR".to_string(), or(text, reason)),
        // The same sentence the server's own `AppError::NotFound` sends.
        StatusCode::NOT_FOUND => ("NOT_FOUND".to_string(), "Resource not found".to_string()),
        StatusCode::METHOD_NOT_ALLOWED => (
            "METHOD_NOT_ALLOWED".to_string(),
            "Method not allowed".to_string(),
        ),
        // ⚠️ Never the body of a 5xx: it would be the one place an internal
        // detail could reach a client. The status name is enough.
        s if s.is_server_error() => (code_for(reason), reason.to_string()),
        _ => (code_for(reason), or(text, reason)),
    };

    let mut out = (status, Json(json!({ "error": message, "code": code }))).into_response();
    // Keep what the framework attached — `Allow` on a 405 above all — except
    // the two headers that described the old body.
    for (name, value) in parts.headers.iter() {
        if name != header::CONTENT_TYPE && name != header::CONTENT_LENGTH {
            out.headers_mut().append(name.clone(), value.clone());
        }
    }
    out
}

fn or(text: String, reason: &str) -> String {
    if text.is_empty() {
        reason.to_string()
    } else {
        text
    }
}

/// `"Payload Too Large"` → `"PAYLOAD_TOO_LARGE"`.
fn code_for(reason: &str) -> String {
    reason
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_status_reason_becomes_a_code() {
        assert_eq!(code_for("Payload Too Large"), "PAYLOAD_TOO_LARGE");
        assert_eq!(code_for("Request Timeout"), "REQUEST_TIMEOUT");
        assert_eq!(code_for("I'm a teapot"), "I_M_A_TEAPOT");
    }

    #[test]
    fn an_empty_body_falls_back_to_the_reason() {
        assert_eq!(or(String::new(), "Bad Request"), "Bad Request");
        assert_eq!(or("x".into(), "Bad Request"), "x");
    }
}
