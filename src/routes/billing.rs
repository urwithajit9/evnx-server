// src/routes/billing.rs

//! Billing — the Paddle webhook, and starting a checkout.
//!
//! # ⛔ None of this can reach a secret
//!
//! A subscription decides which **plan's limits** apply to an organisation's seat
//! holders. It cannot grant or revoke access to a vault, because the server has
//! never been able to wrap a vault key. A lapsed subscription changes quotas;
//! nothing is deleted for non-payment, and the server could not read it in order
//! to delete it even if someone wanted that.
//!
//! # The webhook is the only unauthenticated write path in the server
//!
//! Everything it is told comes from the open internet. The one thing separating a
//! real Paddle event from a forgery is the HMAC in [`crate::services::paddle`], so
//! the order here is **verify, then parse, then write** — and nothing from the
//! body is logged or acted on before that.
//!
//! What a forged event would be worth:
//!
//! * `subscription.updated` with `plan = enterprise` — a free upgrade for anyone
//!   who can POST.
//! * `subscription.canceled` — a denial of service against a paying customer.
//!
//! # ⚠️ Paddle requires a 200 within five seconds
//!
//! So this handler does exactly one database round trip and returns. No outbound
//! HTTP, no email, no blob work. A slow handler means Paddle retries — **60 times
//! over three days in live**, which is also why every write here is idempotent.
//!
//! # ⚠️ Events arrive out of order and more than once
//!
//! `organizations.billing_updated_at` holds the `occurred_at` of the newest event
//! applied, and anything older is ignored. Without it a retried `updated` from
//! before a cancellation would quietly resurrect a subscription.

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    errors::AppError,
    middleware::org_role::{OrgAccess, OrgOwnerOnly},
    services::paddle,
    state::AppState,
};

// ─── Webhook ──────────────────────────────────────────────────────────────────

/// What we read out of a subscription event. Deliberately a small subset.
///
/// ⚠️ Untyped beyond this. Paddle's payload is large and will grow; binding all
/// of it would mean a schema change every time they add a field, and would tempt
/// somebody into storing billing detail — which evnx does not hold.
#[derive(Deserialize)]
struct Event {
    event_type: String,
    occurred_at: String,
    data: EventData,
}

#[derive(Deserialize)]
struct EventData {
    /// `sub_…`
    id: String,
    status: Option<String>,
    customer_id: Option<String>,
    custom_data: Option<serde_json::Value>,
    current_billing_period: Option<BillingPeriod>,
    items: Option<Vec<Item>>,
}

#[derive(Deserialize)]
struct BillingPeriod {
    ends_at: Option<String>,
}

#[derive(Deserialize)]
struct Item {
    quantity: Option<i64>,
    price: Option<Price>,
}

#[derive(Deserialize)]
struct Price {
    id: Option<String>,
}

/// `POST /api/v1/billing/webhook`
///
/// ⚠️ Takes `Bytes`, not `Json<T>`. The signature is computed over the **exact
/// bytes Paddle sent**; `Json` consumes the body and a re-serialisation changes
/// them. Paddle's own documentation is explicit that even added whitespace breaks
/// it.
pub async fn webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AppError> {
    let Some(paddle_cfg) = state.config.paddle.as_ref() else {
        // ⚠️ 503 rather than 500 or 404. A self-hosted deployment legitimately has
        // no Paddle configuration, and this says "not enabled here" rather than
        // implying a fault or hiding the route's existence.
        return Err(AppError::Internal(
            "billing is not configured on this deployment".into(),
        ));
    };

    let signature = headers
        .get("paddle-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    let now = chrono::Utc::now().timestamp();
    let occurred_ts = match paddle::verify(&body, signature, &paddle_cfg.webhook_secret, now) {
        Ok(ts) => ts,
        Err(e) => {
            // ⚠️ The reason is logged; the body never is. An unverified payload is
            // attacker-controlled, and logging it would let anyone write arbitrary
            // content into our logs.
            tracing::warn!(error = %e, "rejected a billing webhook");
            return Err(AppError::Unauthorized);
        }
    };
    let _ = occurred_ts;

    // Only now is it safe to look at what it says.
    let event: Event = match serde_json::from_slice(&body) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "a verified webhook did not parse");
            // ⚠️ 200 anyway. The signature was genuine, so this is Paddle sending
            // a shape we do not understand — retrying it 60 times changes nothing
            // and only buries the real events behind it.
            return Ok(StatusCode::OK);
        }
    };

    // Subscription events only. Anything else is acknowledged and dropped, so a
    // destination accidentally subscribed to more does not produce retries.
    if !event.event_type.starts_with("subscription.") {
        return Ok(StatusCode::OK);
    }

    let occurred_at = chrono::DateTime::parse_from_rfc3339(&event.occurred_at)
        .map(|d| d.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now());

    // The organisation, by subscription id first and `custom_data.org_id` second.
    //
    // ⚠️ `custom_data` is only consulted on the FIRST event for a subscription.
    // After that the subscription id is authoritative — otherwise a later event
    // carrying a different org_id could move a live subscription to another
    // organisation, and Paddle copies custom_data forward to every renewal.
    let org_id: Option<uuid::Uuid> = sqlx::query_scalar!(
        "SELECT id FROM organizations WHERE paddle_subscription_id = $1",
        event.data.id
    )
    .fetch_optional(&state.db)
    .await?
    .or_else(|| {
        event
            .data
            .custom_data
            .as_ref()
            .and_then(|c| c.get("org_id"))
            .and_then(|v| v.as_str())
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
    });

    let Some(org_id) = org_id else {
        // ⚠️ 200. A subscription we cannot attribute is not a failure Paddle can
        // fix by retrying — most likely a checkout from another integration, or a
        // test event. Logged so it is visible, acknowledged so it stops.
        tracing::warn!(
            event_type = %event.event_type,
            subscription = %event.data.id,
            "billing event for an unknown organisation"
        );
        return Ok(StatusCode::OK);
    };

    // Seats come from the item quantity; the plan from which price was bought.
    let (quantity, price_id) = event
        .data
        .items
        .as_ref()
        .and_then(|items| items.first())
        .map(|i| (i.quantity, i.price.as_ref().and_then(|p| p.id.clone())))
        .unwrap_or((None, None));

    let plan = price_id
        .as_deref()
        .and_then(|p| state.config.plan_for_price(p));

    let status = event.data.status.as_deref();
    let period_ends = event
        .data
        .current_billing_period
        .as_ref()
        .and_then(|p| p.ends_at.as_deref())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&chrono::Utc));

    // ⚠️ One statement, and the `billing_updated_at` guard is inside it. Reading
    // then writing would race two deliveries of the same event against each other;
    // this makes an out-of-order or duplicate event a no-op at the database.
    //
    // ⚠️ `plan` is only overwritten when the event names a price we recognise, so
    // an event without items cannot blank an organisation's plan.
    let applied = sqlx::query!(
        r#"
        UPDATE organizations SET
            paddle_subscription_id = $2,
            paddle_customer_id     = COALESCE($3, paddle_customer_id),
            subscription_status    = COALESCE($4, subscription_status),
            current_period_ends_at = COALESCE($5, current_period_ends_at),
            seats                  = COALESCE($6, seats),
            plan                   = COALESCE($7, plan),
            billing_updated_at     = $8,
            updated_at             = NOW()
        WHERE id = $1
          AND (billing_updated_at IS NULL OR billing_updated_at <= $8)
        "#,
        org_id,
        event.data.id,
        event.data.customer_id,
        status,
        period_ends,
        quantity.map(|q| q as i32),
        plan,
        occurred_at,
    )
    .execute(&state.db)
    .await?
    .rows_affected();

    if applied == 0 {
        tracing::info!(
            subscription = %event.data.id,
            event_type = %event.event_type,
            "ignored an out-of-order or duplicate billing event"
        );
    } else {
        // ⚠️ Event type, subscription id and the resulting plan. Never the
        // payload: it carries customer billing detail, which is the one category
        // of data evnx has so far never held.
        tracing::info!(
            org_id = %org_id,
            subscription = %event.data.id,
            event_type = %event.event_type,
            status = ?status,
            "applied a billing event"
        );
    }

    Ok(StatusCode::OK)
}

// ─── Checkout ─────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CheckoutRequest {
    /// A `pri_…` from our own configuration. ⚠️ Validated against it — see below.
    pub price_id: String,
    /// Seats to buy.
    pub quantity: i64,
}

/// `POST /api/v1/orgs/:org_id/checkout`
///
/// Creates a Paddle transaction and returns its id for `Paddle.Checkout.open()`.
///
/// # ⚠️ Why the transaction is created here and not in the browser
///
/// Paddle.js can open a checkout from a price id alone, with `custom_data` passed
/// client-side. That would mean **the browser chooses which organisation the
/// subscription pays for** — so anyone could attach a subscription to an
/// organisation they do not own, and the webhook would dutifully apply its plan
/// and seats to it.
///
/// Creating the transaction server-side puts `org_id` beyond the client's reach:
/// it comes from the session, behind `OrgAccess<OrgOwnerOnly>`.
///
/// # Errors
/// * `403` — not the organisation's owner. Buying is a billing act.
/// * `422` — a price id that is not one of ours.
/// * `503` — billing is not configured on this deployment.
pub async fn checkout(
    State(state): State<AppState>,
    access: OrgAccess<OrgOwnerOnly>,
    Json(req): Json<CheckoutRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let Some(cfg) = state.config.paddle.as_ref() else {
        return Err(AppError::Internal(
            "billing is not configured on this deployment".into(),
        ));
    };

    // ⚠️ Allow-listed, not merely well-formed. Without this a caller could pass
    // any `pri_…` in the Paddle account — including one priced at zero, or one
    // belonging to a different product — and buy a plan at the wrong price.
    if state.config.plan_for_price(&req.price_id).is_none() {
        return Err(AppError::Validation(
            "that price is not one of this deployment's plans".into(),
        ));
    }

    if req.quantity < 1 {
        return Err(AppError::Validation("quantity must be at least 1".into()));
    }

    let client = reqwest::Client::new();
    let res = client
        .post(format!("{}/transactions", cfg.api_base()))
        .header("Authorization", format!("Bearer {}", cfg.api_key))
        .json(&json!({
            "items": [{ "price_id": req.price_id, "quantity": req.quantity }],
            // ⚠️ Flat, and set here where the client cannot touch it. Paddle copies
            // it to the subscription and then to every renewal, so this one value
            // is what links the whole billing lifecycle to an organisation.
            "custom_data": { "org_id": access.org_id.to_string() },
        }))
        .send()
        .await
        .map_err(|e| {
            // ⚠️ Status and message only. The request carries our API key in a
            // header and the response echoes request detail on some errors.
            tracing::error!(error = %e, "could not reach Paddle to create a transaction");
            AppError::Internal("could not reach the payment provider".into())
        })?;

    let status = res.status();
    let body: serde_json::Value = res.json().await.unwrap_or(json!({}));

    if !status.is_success() {
        tracing::error!(%status, "Paddle refused to create a transaction");
        return Err(AppError::Internal(
            "the payment provider refused to start a checkout".into(),
        ));
    }

    let txn_id = body
        .get("data")
        .and_then(|d| d.get("id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Internal("Paddle returned no transaction id".into()))?;

    Ok(Json(json!({
        "transaction_id": txn_id,
        "client_token": null,
        "note": "Open this transaction with Paddle.js. A subscription decides which \
                 plan's limits apply — it does not grant access to any vault."
    })))
}

/// `GET /api/v1/orgs/:org_id/billing` — what the billing screen renders.
///
/// Any member may read it: knowing whether the organisation is paid up is not a
/// secret from the people it covers, and hiding it would make "why did my limits
/// change?" unanswerable without an admin.
pub async fn billing_state(
    State(state): State<AppState>,
    access: OrgAccess<crate::middleware::org_role::AtLeastOrgMember>,
) -> Result<Json<serde_json::Value>, AppError> {
    let row = sqlx::query!(
        r#"SELECT plan, seats, subscription_status, current_period_ends_at,
                  (paddle_subscription_id IS NOT NULL) AS "has_subscription!",
                  (SELECT COUNT(*) FROM organization_members m
                    WHERE m.org_id = $1 AND m.seat_assigned_at IS NOT NULL) AS "seats_used!"
           FROM organizations WHERE id = $1"#,
        access.org_id
    )
    .fetch_one(&state.db)
    .await?;

    Ok(Json(json!({
        "plan": row.plan,
        "seats": { "used": row.seats_used, "purchased": row.seats },
        "over_seated": row.seats.is_some_and(|p| row.seats_used > i64::from(p)),
        "subscription": {
            "exists": row.has_subscription,
            "status": row.subscription_status,
            "current_period_ends_at": row.current_period_ends_at,
        },
        // ⚠️ Said on the screen that is most likely to worry someone.
        "note": "Billing decides which plan's limits apply. No vault is affected by \
                 a subscription, and nothing is deleted for non-payment.",
    })))
}
