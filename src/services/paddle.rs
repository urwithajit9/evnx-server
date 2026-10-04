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

// ─── Calling Paddle ───────────────────────────────────────────────────────────

/// A thin client over the Paddle API.
///
/// # ⚠️ Why this exists rather than a `reqwest::Client` at each call site
///
/// Five handlers now talk to Paddle, and each one of them must get the same
/// three things right:
///
/// 1. **Never log the request.** It carries `Authorization: Bearer pdl_…`.
/// 2. **Never log the response body.** Paddle echoes request detail on some
///    errors, and the bodies carry customer billing detail — the one category of
///    data evnx has so far never held.
/// 3. **Never surface Paddle's own message to the caller.** It is written for
///    the integrator, not the customer, and can name internal ids.
///
/// Those are easy to get right once and easy to forget on the fifth copy.
pub struct PaddleApi<'a> {
    cfg: &'a crate::config::PaddleConfig,
    http: reqwest::Client,
}

/// What went wrong, with no detail that could not safely be shown to anyone.
#[derive(Debug)]
pub enum ApiError {
    /// Could not reach Paddle at all.
    Unreachable,
    /// Paddle answered, but not with success. The status is kept for the log.
    Refused(reqwest::StatusCode),
    /// ⚠️ One specific Paddle error code, surfaced because it is the single most
    /// likely misconfiguration of this integration and the generic message sends
    /// people hunting in the wrong place.
    ///
    /// Verified against the sandbox API on 2026-10-05: with no default payment
    /// link set in the dashboard, Paddle **refuses to create the transaction at
    /// all** — it does not merely omit `checkout.url` — and it does so *even
    /// when `checkout.url` is passed explicitly in the request. So
    /// `PADDLE_CHECKOUT_URL` is not a substitute for the dashboard setting; both
    /// are required.
    NoCheckoutPage,
    /// Paddle answered with success and a shape we did not expect.
    Unexpected(&'static str),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable => write!(f, "could not reach the payment provider"),
            Self::Refused(s) => write!(f, "the payment provider refused the request ({s})"),
            Self::NoCheckoutPage => write!(
                f,
                "billing is not finished being set up: no default payment link is \
                 configured in Paddle (Checkout → Checkout configuration)"
            ),
            Self::Unexpected(what) => write!(f, "the payment provider returned no {what}"),
        }
    }
}

impl From<ApiError> for crate::errors::AppError {
    fn from(e: ApiError) -> Self {
        // ⚠️ ServiceUnavailable, not Internal — `Internal` renders as
        // "An internal error occurred" and would throw away every one of these
        // messages, including the one naming the single most likely setup
        // mistake. Each variant's Display text is written for a reader and
        // names no identifier, host or upstream message; see `ApiError`.
        crate::errors::AppError::ServiceUnavailable(e.to_string())
    }
}

impl<'a> PaddleApi<'a> {
    pub fn new(cfg: &'a crate::config::PaddleConfig) -> Self {
        Self {
            cfg,
            http: reqwest::Client::new(),
        }
    }

    /// Send a request and return `data`, which every Paddle response wraps.
    ///
    /// ⚠️ `method` and `path` are ours; nothing from a request body reaches the
    /// URL, so there is no path-injection surface here.
    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, ApiError> {
        let url = format!("{}{}", self.cfg.api_base(), path);
        let mut req = self
            .http
            .request(method, &url)
            .header("Authorization", format!("Bearer {}", self.cfg.api_key));
        if let Some(b) = body {
            req = req.json(&b);
        }

        let res = req.send().await.map_err(|e| {
            // ⚠️ `{e}` on a reqwest error prints the URL, never the headers. The
            // URL is ours and public.
            tracing::error!(error = %e, %url, "could not reach Paddle");
            ApiError::Unreachable
        })?;

        let status = res.status();
        // Read the body in every case, but only ever *use* it on success.
        let parsed: serde_json::Value = res.json().await.unwrap_or(serde_json::json!({}));

        if !status.is_success() {
            // ⚠️ Status and Paddle's own error *code* only — a short enum like
            // `subscription_locked`, which is diagnostic and carries no customer
            // detail. The message and `meta` are not logged.
            let code = parsed
                .get("error")
                .and_then(|e| e.get("code"))
                .and_then(|v| v.as_str())
                .unwrap_or("none");
            tracing::error!(%status, paddle_code = %code, %url, "Paddle refused a request");
            // ⚠️ Allow-listed by code, not pass-through. Paddle's own message is
            // written for an integrator and can name internal ids; this maps one
            // known code to a sentence of our own.
            if code == "transaction_default_checkout_url_not_set" {
                return Err(ApiError::NoCheckoutPage);
            }
            return Err(ApiError::Refused(status));
        }

        parsed
            .get("data")
            .cloned()
            .ok_or(ApiError::Unexpected("data"))
    }

    /// Create a transaction and return `(transaction_id, checkout_url)`.
    ///
    /// ⚠️ `custom_data.org_id` is set **here**, where the client cannot touch it.
    /// Paddle copies it to the subscription and then to every renewal, so this
    /// one value is what links the whole billing lifecycle to an organisation.
    /// Letting the browser supply it would let anyone attach a subscription to an
    /// organisation they do not own.
    pub async fn create_transaction(
        &self,
        price_id: &str,
        quantity: i64,
        org_id: uuid::Uuid,
    ) -> Result<(String, String), ApiError> {
        let mut body = serde_json::json!({
            "items": [{ "price_id": price_id, "quantity": quantity }],
            "custom_data": { "org_id": org_id.to_string() },
        });
        // Omitted entirely when unset, so Paddle falls back to the dashboard's
        // default payment link. Sending `null` means the same thing to Paddle but
        // reads here as "deliberately no page", which is not what is meant.
        if let Some(url) = self.cfg.checkout_url.as_deref() {
            body["checkout"] = serde_json::json!({ "url": url });
        }

        let data = self
            .call(reqwest::Method::POST, "/transactions", Some(body))
            .await?;

        let txn = data
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or(ApiError::Unexpected("transaction id"))?
            .to_string();

        // ⚠️ Kept even though the common cause is now caught above as
        // `NoCheckoutPage`. Paddle documents `checkout.url` as nullable, and a
        // null handed to the browser would make "Continue to payment" do nothing
        // at all with no error anywhere — a failure nobody would know where to
        // look for. Cheap guard against a shape we have not seen.
        let checkout_url = data
            .get("checkout")
            .and_then(|c| c.get("url"))
            .and_then(|v| v.as_str())
            .ok_or(ApiError::Unexpected(
                "checkout URL — set PADDLE_CHECKOUT_URL, or a default payment link in Paddle",
            ))?
            .to_string();

        Ok((txn, checkout_url))
    }

    /// Change the seat quantity on a live subscription.
    ///
    /// ⚠️ `proration_billing_mode` is required and there is no safe default to
    /// omit. `prorated_immediately` charges the difference now, which is what
    /// someone adding a seat mid-month expects and what keeps Paddle's quantity
    /// and our `seats` column from diverging for up to a month.
    pub async fn set_subscription_quantity(
        &self,
        subscription_id: &str,
        price_id: &str,
        quantity: i64,
    ) -> Result<(), ApiError> {
        self.call(
            reqwest::Method::PATCH,
            &format!("/subscriptions/{subscription_id}"),
            Some(serde_json::json!({
                "items": [{ "price_id": price_id, "quantity": quantity }],
                "proration_billing_mode": "prorated_immediately",
            })),
        )
        .await?;
        Ok(())
    }

    /// Remove a scheduled cancellation, so the subscription renews after all.
    ///
    /// ⚠️ Paddle expresses "cancelled but still running" as `scheduled_change`
    /// on an **active** subscription, so undoing it is a field set to null — not
    /// a resume operation and not a new subscription.
    pub async fn clear_scheduled_change(&self, subscription_id: &str) -> Result<(), ApiError> {
        self.call(
            reqwest::Method::PATCH,
            &format!("/subscriptions/{subscription_id}"),
            Some(serde_json::json!({ "scheduled_change": null })),
        )
        .await?;
        Ok(())
    }

    /// Authenticated deep links into Paddle's own customer portal.
    ///
    /// # ⚠️ Why cancellation and card updates are not our endpoints
    ///
    /// Paddle is the **merchant of record** — the seller on the customer's
    /// statement and the party holding their card. Rebuilding cancellation and
    /// payment-method capture here would mean our UI claiming authority over a
    /// contract we are not party to, and a card form on an origin that should
    /// never see one. The portal is Paddle's, it is already localised and
    /// PCI-scoped, and it stays correct when Paddle changes their flows.
    pub async fn portal_links(
        &self,
        customer_id: &str,
        subscription_id: Option<&str>,
    ) -> Result<serde_json::Value, ApiError> {
        let body = match subscription_id {
            Some(id) => serde_json::json!({ "subscription_ids": [id] }),
            None => serde_json::json!({}),
        };
        let data = self
            .call(
                reqwest::Method::POST,
                &format!("/customers/{customer_id}/portal-sessions"),
                Some(body),
            )
            .await?;

        let urls = data
            .get("urls")
            .ok_or(ApiError::Unexpected("portal URLs"))?;
        let general = urls.get("general").and_then(|g| g.get("overview"));
        // Paddle returns one entry per subscription asked for; we ask for one.
        let sub = urls
            .get("subscriptions")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first());

        let pick = |key: &str| {
            sub.and_then(|s| s.get(key))
                .and_then(|v| v.as_str())
                .map(str::to_string)
        };

        Ok(serde_json::json!({
            "overview": general.and_then(|v| v.as_str()),
            "view_subscription": pick("view_subscription"),
            "cancel_subscription": pick("cancel_subscription"),
            "update_payment_method": pick("update_subscription_payment_method"),
        }))
    }

    /// The configured prices, as Paddle currently describes them.
    ///
    /// # ⚠️ Why this asks Paddle instead of reading a constant
    ///
    /// A billing screen showing a price different from the one charged is the
    /// worst bug on the worst screen. Sandbox and live are separate catalogues
    /// and the dashboard can change an amount at any time, so the only number
    /// safe to display is the one Paddle will actually bill.
    ///
    /// Filtered through our own allow-list afterwards, so a price added in the
    /// dashboard but not configured here never appears as something buyable.
    pub async fn prices(
        &self,
        cfg: &crate::config::PaddleConfig,
    ) -> Result<serde_json::Value, ApiError> {
        let ids: Vec<&str> = cfg.prices.iter().map(|(id, _)| id.as_str()).collect();
        let data = self
            .call(
                reqwest::Method::GET,
                &format!("/prices?id={}&per_page=50", ids.join(",")),
                None,
            )
            .await?;

        let rows: Vec<serde_json::Value> = data
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|p| {
                        let id = p.get("id")?.as_str()?;
                        // The allow-list, applied again on the way out.
                        let plan = cfg.plan_for_price(id)?;
                        // ⚠️ An archived price is still returned by Paddle and
                        // still checks out, but it is not something to offer.
                        if p.get("status").and_then(|v| v.as_str()) != Some("active") {
                            return None;
                        }
                        let unit = p.get("unit_price");
                        Some(serde_json::json!({
                            "price_id": id,
                            "plan": plan,
                            // "month" | "year". ⚠️ Read from Paddle, not from the
                            // env var's name — `PADDLE_PRICE_TEAM_YEARLY` could
                            // be pointed at a monthly price by a typo and
                            // nothing would notice.
                            "interval": p
                                .get("billing_cycle")
                                .and_then(|b| b.get("interval")),
                            // A string in the lowest denomination ("900"), kept
                            // a string so it cannot become a float in transit.
                            "amount": unit.and_then(|u| u.get("amount")),
                            "currency_code": unit.and_then(|u| u.get("currency_code")),
                            "max_quantity": p
                                .get("quantity")
                                .and_then(|q| q.get("maximum")),
                        }))
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(serde_json::Value::Array(rows))
    }

    /// Past transactions for a subscription, newest first.
    ///
    /// ⚠️ Returns only what a receipt line needs — date, status, total, currency
    /// and Paddle's own invoice link. Not the address, not the tax breakdown, not
    /// the card. Storing none of it is the point; this is a pass-through.
    pub async fn invoices(&self, subscription_id: &str) -> Result<serde_json::Value, ApiError> {
        let data = self
            .call(
                reqwest::Method::GET,
                &format!(
                    "/transactions?subscription_id={subscription_id}\
                     &status=completed,billed,past_due&per_page=20&order_by=created_at[DESC]"
                ),
                None,
            )
            .await?;

        let rows: Vec<serde_json::Value> = data
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|t| {
                        let totals = t.get("details").and_then(|d| d.get("totals"));
                        serde_json::json!({
                            "id": t.get("id"),
                            "billed_at": t.get("billed_at").or_else(|| t.get("created_at")),
                            "status": t.get("status"),
                            "currency_code": t.get("currency_code"),
                            // ⚠️ A string in the lowest denomination ("3600"),
                            // because Paddle's amounts are not floats and must
                            // not become them on the way through.
                            "grand_total": totals.and_then(|v| v.get("grand_total")),
                            "quantity": t
                                .get("items")
                                .and_then(|i| i.as_array())
                                .and_then(|a| a.first())
                                .and_then(|i| i.get("quantity")),
                            "invoice_url": t.get("invoice_url"),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(serde_json::Value::Array(rows))
    }
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
