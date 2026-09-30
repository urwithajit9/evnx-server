// src/middleware/client_ip.rs

//! Who the request came from, in a form that can be stored.
//!
//! ## What this produces, and what it deliberately does not
//!
//! `audit_events` has carried `ip_hash` and `user_agent_hash` columns since the
//! first migration and **neither has ever held a value** — every call site passed
//! `None`, because nothing plumbed the client's address to a handler. This is
//! that plumbing.
//!
//! What lands in the database is a **keyed** BLAKE3 digest, never an address.
//! Nothing here ever returns, logs or stores a raw IP.
//!
//! ## ⚠️ Why the hash is keyed, and why an unkeyed one would be theatre
//!
//! IPv4 is 32 bits. A plain `blake3(ip)` can be reversed by hashing all four
//! billion addresses — minutes of work on a laptop, once, for every address
//! forever. So an unkeyed digest of an IP is **not** anonymisation; it only looks
//! like it, which is worse than storing the address openly because it invites
//! everyone downstream to treat it as safe.
//!
//! The key is derived from `JWT_SECRET` with a domain-separated
//! `blake3::derive_key`, so no new secret has to be deployed and the digest is
//! not reversible without it. Two consequences worth knowing:
//!
//! * digests stay **stable and comparable**, which is what makes them useful for
//!   noticing that a session came from somewhere this account has not been before
//!   — the whole point of the column;
//! * **rotating `JWT_SECRET` re-keys them**, so old rows stop correlating with new
//!   ones. That is the right trade — it is a secret rotation, and losing the
//!   ability to link a year-old login to today's is a small price — but it should
//!   not come as a surprise to whoever rotates it.
//!
//! ## Where the address comes from
//!
//! Two sources, chosen by one explicit setting, never inferred:
//!
//! * `TRUST_PROXY_HEADER=true` — read `X-Forwarded-For`. Correct **only** behind a
//!   proxy that controls that header.
//! * anything else — the socket peer. Correct when the server is exposed directly.
//!
//! ⚠️ **It defaults to false, including in production.** Trusting the header when
//! nothing sanitises it lets any client name its own address, and every audit row
//! written afterwards is a value the attacker chose. The failure in the other
//! direction — a proxied deployment that forgot the setting — records the proxy's
//! own address: useless, uniform, and obviously so. Honest and useless beats
//! confidently wrong, so the unsafe direction is the one that has to be asked for.
//! `Config` logs a warning at startup in production when it is off.
//!
//! ## ⚠️ The header is only safe because of one line in the Caddyfile
//!
//! `docker/Caddyfile` carries `header_up X-Forwarded-For {remote_host}`, which
//! **replaces** the header with the real peer. Caddy's default is to *append*, and
//! an appended header is `<whatever the client sent>, <real peer>`.
//!
//! So this module takes the **rightmost** entry, not the first. With exactly one
//! trusted proxy that is correct under both behaviours, while `.first()` — the
//! obvious implementation, and the one most guides show — hands an attacker
//! control of the value the moment the header is appended rather than replaced.
//! Deleting that Caddyfile line would not break anything visibly; it would quietly
//! make the recorded address spoofable, and this comment is the only thing
//! connecting the two.

use axum::async_trait;
use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use std::net::SocketAddr;

use crate::errors::AppError;
use crate::state::AppState;

/// Domain separation for the IP-hash key. Changing this string re-keys every
/// future digest, exactly as rotating `JWT_SECRET` does.
const IP_HASH_CONTEXT: &str = "evnx-server 2026-09-30 audit ip-hash v1";

/// Stable, non-reversible identifiers for one request's origin.
///
/// Both are `None` when the source is unavailable — an absent header, or a test
/// harness that supplies no peer address. `None` is a truthful "not known" and is
/// stored as SQL `NULL`; it is never filled with a placeholder, because a
/// placeholder would be indistinguishable from a real repeated value.
#[derive(Debug, Clone, Default)]
pub struct ClientContext {
    pub ip_hash: Option<String>,
    pub user_agent_hash: Option<String>,
}

/// Keyed BLAKE3, hex. See the module note on why this is not `blake3::hash`.
fn keyed(jwt_secret: &str, input: &[u8]) -> String {
    let key = blake3::derive_key(IP_HASH_CONTEXT, jwt_secret.as_bytes());
    blake3::keyed_hash(&key, input).to_hex().to_string()
}

/// The client address, as far as this deployment can honestly tell.
fn client_addr(parts: &Parts, trust_proxy: bool) -> Option<String> {
    if trust_proxy {
        if let Some(raw) = parts
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
        {
            // ⚠️ Rightmost, not leftmost — see the module note. The last entry is
            // the one the nearest trusted proxy put there; everything to its left
            // may have come from the client.
            if let Some(last) = raw.rsplit(',').map(str::trim).find(|s| !s.is_empty()) {
                // Parsed rather than trusted as text, so a header carrying
                // something that is not an address is dropped instead of being
                // hashed and stored as though it meant something.
                if last.parse::<std::net::IpAddr>().is_ok() {
                    return Some(last.to_string());
                }
            }
        }
        // Trusting the header and not finding a usable one is a gap worth leaving
        // empty rather than silently falling back to the peer, which behind a
        // proxy is the proxy.
        return None;
    }

    parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip().to_string())
}

// `#[async_trait]`, matching `vault_role`: axum-core 0.4 still declares
// `FromRequestParts` with the macro, so a native async fn fails to match its
// lifetimes.
#[async_trait]
impl FromRequestParts<AppState> for ClientContext {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let secret = &state.config.jwt_secret;

        let ip_hash = client_addr(parts, state.config.trust_proxy_header)
            .map(|addr| keyed(secret, addr.as_bytes()));

        let user_agent_hash = parts
            .headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.trim().is_empty())
            .map(|ua| keyed(secret, ua.as_bytes()));

        Ok(Self {
            ip_hash,
            user_agent_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    fn parts_with(headers: &[(&str, &str)], peer: Option<&str>) -> Parts {
        let mut req = Request::builder();
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let mut req = req.body(()).unwrap();
        if let Some(p) = peer {
            req.extensions_mut()
                .insert(ConnectInfo(p.parse::<SocketAddr>().unwrap()));
        }
        req.into_parts().0
    }

    /// ⚠️ The mistake this module exists to avoid. Caddy is configured to replace
    /// the header, but if it ever appends instead, the client's own value sits on
    /// the left — and `.first()` would hash and store whatever they typed.
    #[test]
    fn a_spoofed_prefix_is_ignored_in_favour_of_the_rightmost_entry() {
        let parts = parts_with(&[("x-forwarded-for", "1.2.3.4, 203.0.113.9")], None);
        assert_eq!(
            client_addr(&parts, true).as_deref(),
            Some("203.0.113.9"),
            "took the client-supplied entry instead of the proxy's"
        );
    }

    #[test]
    fn a_single_entry_is_used_as_is() {
        let parts = parts_with(&[("x-forwarded-for", "203.0.113.9")], None);
        assert_eq!(client_addr(&parts, true).as_deref(), Some("203.0.113.9"));
    }

    /// Nothing that is not an address gets stored as though it were one.
    #[test]
    fn a_header_that_is_not_an_address_is_dropped() {
        let parts = parts_with(&[("x-forwarded-for", "not-an-ip")], None);
        assert_eq!(client_addr(&parts, true), None);
    }

    /// ⚠️ Without the setting the header is not read at all, however convincing
    /// it looks — that is the whole point of the setting.
    #[test]
    fn the_header_is_ignored_when_the_proxy_is_not_trusted() {
        let parts = parts_with(
            &[("x-forwarded-for", "203.0.113.9")],
            Some("10.0.0.5:54321"),
        );
        assert_eq!(client_addr(&parts, false).as_deref(), Some("10.0.0.5"));
    }

    /// A proxied deployment that forgot the setting records the proxy, not a
    /// client-chosen value. Useless, and not dangerous.
    #[test]
    fn trusting_the_proxy_without_a_header_yields_nothing() {
        let parts = parts_with(&[], Some("10.0.0.5:54321"));
        assert_eq!(client_addr(&parts, true), None);
    }

    /// The digest must not be the plain hash of the address: IPv4 is 32 bits and
    /// a table of every unkeyed digest is an afternoon's work.
    #[test]
    fn the_digest_is_keyed_not_a_plain_hash() {
        let plain = blake3::hash(b"203.0.113.9").to_hex().to_string();
        assert_ne!(keyed("a-secret", b"203.0.113.9"), plain);
    }

    #[test]
    fn a_different_secret_gives_a_different_digest() {
        assert_ne!(
            keyed("secret-one", b"203.0.113.9"),
            keyed("secret-two", b"203.0.113.9")
        );
    }

    /// Stable for the same input, which is what makes correlation possible at all.
    #[test]
    fn the_digest_is_stable() {
        assert_eq!(
            keyed("a-secret", b"203.0.113.9"),
            keyed("a-secret", b"203.0.113.9")
        );
    }

    /// No raw address may survive into anything stored.
    #[test]
    fn the_digest_does_not_contain_the_address() {
        let d = keyed("a-secret", b"203.0.113.9");
        assert!(!d.contains("203"), "{d}");
        assert_eq!(d.len(), 64);
    }
}
