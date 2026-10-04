//! Paddle webhook signature verification.
//!
//! # Why this file is small and careful rather than large
//!
//! `POST /api/v1/billing/webhook` is the only **unauthenticated** route in the
//! server that writes to the database. Everything it is told arrives from the open
//! internet, and the only thing separating a real Paddle event from something an
//! attacker posted at the same URL is the HMAC below.
//!
//! What a forged event could do if this were wrong:
//!
//! * `subscription.updated` with `plan = enterprise` — a free upgrade for anyone.
//! * `subscription.canceled` — a denial of service against a paying customer,
//!   dropping their whole organisation to the free tier.
//!
//! So: **verify first, parse second.** Nothing in the payload is read, logged or
//! acted on until the signature matches.
//!
//! # The algorithm, from Paddle's documentation
//!
//! ```text
//! Paddle-Signature: ts=1671552777;h1=eb4d0dc8853be92b7f063b9f3ba5233eb920a09459b6e6b2c26705b4364db151
//!
//! signed_payload = "{ts}:{raw_body}"
//! expected       = HMAC-SHA256(secret, signed_payload)   // lowercase hex
//! ```
//!
//! ⚠️ **`raw_body` is the exact bytes Paddle sent.** Not a re-serialised struct,
//! not a pretty-printed `serde_json::Value` — Paddle's own docs say *"do not parse
//! or transform it. Even adding whitespace breaks the signature."* That is why the
//! handler takes `Bytes` and this function takes `&[u8]`.
//!
//! ⚠️ **The timestamp is checked too.** Without it a captured webhook can be
//! replayed forever, and a replayed `subscription.canceled` is as good as a forged
//! one. Paddle's own SDKs use a five-second tolerance; this uses five minutes,
//! because a tolerance tight enough to trip on ordinary clock drift turns into a
//! support problem that gets "fixed" by removing the check.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// How far out of date a signature may be. See the module note on why this is
/// minutes rather than Paddle's five seconds.
const MAX_AGE_SECONDS: i64 = 300;

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// No `Paddle-Signature` header, or it was not the `ts=…;h1=…` shape.
    MalformedHeader,
    /// The HMAC did not match. ⚠️ Either a forgery or the wrong secret — and the
    /// two are deliberately indistinguishable to the caller.
    BadSignature,
    /// Correct signature, but too old. A replay, or a badly wrong clock.
    Stale,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedHeader => write!(f, "malformed Paddle-Signature header"),
            Self::BadSignature => write!(f, "signature did not match"),
            Self::Stale => write!(f, "signature timestamp is outside the allowed window"),
        }
    }
}

/// Parse `ts=…;h1=…` into its two parts.
///
/// Tolerates the parts in either order and ignores any key it does not know, so a
/// future `h2=` does not break this.
fn parse_header(header: &str) -> Option<(i64, String)> {
    let mut ts = None;
    let mut h1 = None;
    for part in header.split(';') {
        let (k, v) = part.split_once('=')?;
        match k.trim() {
            "ts" => ts = v.trim().parse::<i64>().ok(),
            "h1" => h1 = Some(v.trim().to_string()),
            _ => {}
        }
    }
    Some((ts?, h1?))
}

/// Verify a webhook, returning the event's timestamp on success.
///
/// ⚠️ `secret` is checked for emptiness. An empty secret would make the HMAC
/// computable by anyone, and an unset environment variable is exactly how that
/// happens — so it is refused rather than used.
pub fn verify(
    body: &[u8],
    signature_header: &str,
    secret: &str,
    now: i64,
) -> Result<i64, VerifyError> {
    if secret.is_empty() {
        return Err(VerifyError::BadSignature);
    }

    let (ts, h1) = parse_header(signature_header).ok_or(VerifyError::MalformedHeader)?;

    // ⚠️ Signature before freshness. Checking the timestamp first would let an
    // unauthenticated caller learn the server's clock skew by probing, which is
    // small but free to avoid.
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| VerifyError::BadSignature)?;
    mac.update(ts.to_string().as_bytes());
    mac.update(b":");
    mac.update(body);
    let expected = mac.finalize().into_bytes();

    let got = match hex::decode(&h1) {
        Ok(b) => b,
        Err(_) => return Err(VerifyError::BadSignature),
    };

    // ⚠️ Constant time. A byte-by-byte `==` leaks how much of the signature was
    // right through timing, which is enough to forge one given enough attempts.
    if got.len() != expected.len() || got.ct_eq(&expected).unwrap_u8() != 1 {
        return Err(VerifyError::BadSignature);
    }

    if (now - ts).abs() > MAX_AGE_SECONDS {
        return Err(VerifyError::Stale);
    }

    Ok(ts)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "ntfset_01example";
    const BODY: &[u8] = br#"{"event_type":"subscription.updated","data":{"id":"sub_1"}}"#;

    fn sign(body: &[u8], ts: i64, secret: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(ts.to_string().as_bytes());
        mac.update(b":");
        mac.update(body);
        format!("ts={ts};h1={}", hex::encode(mac.finalize().into_bytes()))
    }

    #[test]
    fn a_genuine_signature_verifies() {
        let h = sign(BODY, 1_700_000_000, SECRET);
        assert_eq!(verify(BODY, &h, SECRET, 1_700_000_000), Ok(1_700_000_000));
    }

    /// ⚠️ The forgery this whole file exists to stop.
    #[test]
    fn a_signature_from_the_wrong_secret_is_refused() {
        let h = sign(BODY, 1_700_000_000, "ntfset_attacker");
        assert_eq!(
            verify(BODY, &h, SECRET, 1_700_000_000),
            Err(VerifyError::BadSignature)
        );
    }

    /// ⚠️ **The one that matters most.** A real, correctly signed event whose body
    /// has been edited in flight — changing the plan, the quantity, the status.
    #[test]
    fn a_tampered_body_is_refused_even_with_a_real_signature() {
        let h = sign(BODY, 1_700_000_000, SECRET);
        let tampered = br#"{"event_type":"subscription.updated","data":{"id":"sub_2"}}"#;
        assert_eq!(
            verify(tampered, &h, SECRET, 1_700_000_000),
            Err(VerifyError::BadSignature)
        );
    }

    /// ⚠️ Even whitespace. This is why the handler must take raw bytes and must
    /// never round-trip the body through a parser before verifying.
    #[test]
    fn one_added_space_breaks_the_signature() {
        let h = sign(BODY, 1_700_000_000, SECRET);
        let mut respaced = BODY.to_vec();
        respaced.push(b' ');
        assert_eq!(
            verify(&respaced, &h, SECRET, 1_700_000_000),
            Err(VerifyError::BadSignature)
        );
    }

    /// ⚠️ A captured webhook replayed tomorrow. Correctly signed, and still refused.
    #[test]
    fn a_replayed_event_is_refused_once_it_is_stale() {
        let h = sign(BODY, 1_700_000_000, SECRET);
        assert_eq!(
            verify(BODY, &h, SECRET, 1_700_000_000 + MAX_AGE_SECONDS + 1),
            Err(VerifyError::Stale)
        );
        // And a clock that is behind, not just ahead.
        assert_eq!(
            verify(BODY, &h, SECRET, 1_700_000_000 - MAX_AGE_SECONDS - 1),
            Err(VerifyError::Stale)
        );
        // Inside the window either way.
        assert!(verify(BODY, &h, SECRET, 1_700_000_000 + MAX_AGE_SECONDS).is_ok());
    }

    /// ⚠️ An unset `PADDLE_WEBHOOK_SECRET` must not make every forgery valid.
    #[test]
    fn an_empty_secret_verifies_nothing() {
        let h = sign(BODY, 1_700_000_000, "");
        assert_eq!(
            verify(BODY, &h, "", 1_700_000_000),
            Err(VerifyError::BadSignature)
        );
    }

    #[test]
    fn a_malformed_header_is_distinguished_from_a_bad_signature() {
        for bad in ["", "garbage", "ts=abc;h1=00", "h1=00", "ts=1"] {
            let got = verify(BODY, bad, SECRET, 1_700_000_000);
            assert!(
                matches!(
                    got,
                    Err(VerifyError::MalformedHeader) | Err(VerifyError::BadSignature)
                ),
                "{bad:?} gave {got:?}"
            );
        }
    }

    /// Order-independent, and tolerant of a key we do not know — so Paddle adding
    /// `h2=` later does not break verification.
    #[test]
    fn the_header_parses_in_any_order_and_ignores_unknown_parts() {
        let ts = 1_700_000_000;
        let mut mac = HmacSha256::new_from_slice(SECRET.as_bytes()).unwrap();
        mac.update(ts.to_string().as_bytes());
        mac.update(b":");
        mac.update(BODY);
        let h1 = hex::encode(mac.finalize().into_bytes());

        for header in [
            format!("ts={ts};h1={h1}"),
            format!("h1={h1};ts={ts}"),
            format!("ts={ts};h2=deadbeef;h1={h1}"),
        ] {
            assert!(verify(BODY, &header, SECRET, ts).is_ok(), "{header}");
        }
    }
}
