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
    /// ⚠️ A cancellation Paddle has accepted but not yet applied.
    ///
    /// Paddle does **not** set `status = canceled` when a customer cancels. The
    /// status stays `active` and this appears instead, saying what happens and
    /// when. Without reading it the billing screen tells someone who has just
    /// cancelled that their plan *renews* on the exact date it ends.
    scheduled_change: Option<ScheduledChange>,
}

#[derive(Deserialize)]
struct ScheduledChange {
    /// `cancel` | `pause` | `resume`.
    action: String,
    effective_at: Option<String>,
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
        return Err(AppError::ServiceUnavailable(
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

    // ⚠️ Written directly, NOT coalesced. Absent means "nothing is scheduled",
    // which is a real value and the one `POST /billing/resume` produces. A
    // COALESCE here would make a cancellation permanent: every later event would
    // preserve it and resuming could never be reflected.
    //
    // Safe because Paddle includes the full subscription entity on every
    // `subscription.*` event, so the field is present-and-null rather than
    // missing when there is no scheduled change.
    let (sched_action, sched_at) = match event.data.scheduled_change.as_ref() {
        Some(c) => (
            Some(c.action.clone()),
            c.effective_at
                .as_deref()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|d| d.with_timezone(&chrono::Utc)),
        ),
        None => (None, None),
    };
    // Migration 012's CHECK requires both or neither, and an action Paddle sends
    // that we have not seen would violate the closed set. Dropping the pair is
    // better than a 500 that makes Paddle retry sixty times over three days.
    let (sched_action, sched_at) = match (sched_action.as_deref(), sched_at) {
        (Some(a), Some(at)) if matches!(a, "cancel" | "pause" | "resume") => {
            (Some(a.to_string()), Some(at))
        }
        (None, _) => (None, None),
        (Some(a), _) => {
            tracing::warn!(action = %a, "ignored an unrecognised or undated scheduled change");
            (None, None)
        }
    };

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
            scheduled_change_action = $9,
            scheduled_change_at     = $10,
            -- ⚠️ COALESCE, unlike the scheduled change above: an event without
            -- items must not blank the price, or the next seat change has
            -- nothing to send Paddle. Same reasoning as `plan`.
            paddle_price_id        = COALESCE($11, paddle_price_id),
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
        sched_action,
        sched_at,
        price_id,
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

// ─── Everything below needs a configured Paddle ───────────────────────────────

/// ⚠️ One place, so no handler decides for itself what an unconfigured
/// deployment should do. Self-hosting evnx without a Paddle account is a
/// supported and expected state, not a fault.
fn require_paddle(state: &AppState) -> Result<&crate::config::PaddleConfig, AppError> {
    // ⚠️ 503 with the reason, not 500. This was written as "⚠️ 503 rather than
    // 500 or 404" when the route was added and then built with `AppError::Internal`,
    // which is a 500 whose body says "An internal error occurred" — so the comment
    // described an intent the code did not have. A self-hosted deployment legitimately
    // has no Paddle account, and that is not a fault to hide.
    state.config.paddle.as_ref().ok_or_else(|| {
        AppError::ServiceUnavailable("billing is not configured on this deployment".into())
    })
}

/// The organisation's Paddle ids, when it has them.
struct Subscription {
    subscription_id: String,
    customer_id: Option<String>,
}

async fn subscription_of(state: &AppState, org_id: uuid::Uuid) -> Result<Subscription, AppError> {
    let row = sqlx::query!(
        "SELECT paddle_subscription_id, paddle_customer_id FROM organizations WHERE id = $1",
        org_id
    )
    .fetch_one(&state.db)
    .await?;

    match row.paddle_subscription_id {
        Some(subscription_id) => Ok(Subscription {
            subscription_id,
            customer_id: row.paddle_customer_id,
        }),
        // ⚠️ 422, not 404. The organisation exists and the caller may see it;
        // what is missing is a subscription, and saying so is not a leak.
        None => Err(AppError::Validation(
            "this organisation has no subscription yet".into(),
        )),
    }
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
/// Creates a Paddle transaction and returns the URL where it can be paid.
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
/// # ⚠️ The URL returned is NOT on app.evnx.dev
///
/// Paddle Billing has no Paddle-hosted checkout page for the web — a payment link
/// is *our own page* plus `?_ptxn=…`, and that page has to load Paddle.js. The
/// page is `pay.evnx.dev`, which holds no session and no keys, because a
/// third-party script on the origin that holds the master key could render a
/// convincing "re-enter your master password" prompt. See `PADDLE_CHECKOUT_URL`.
///
/// # Errors
/// * `403` — not the organisation's owner. Buying is a billing act.
/// * `422` — a price id that is not one of ours.
/// * `500` — Paddle unreachable, or no checkout page configured anywhere.
pub async fn checkout(
    State(state): State<AppState>,
    access: OrgAccess<OrgOwnerOnly>,
    Json(req): Json<CheckoutRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let cfg = require_paddle(&state)?;

    // ⚠️ Allow-listed, not merely well-formed. Without this a caller could pass
    // any `pri_…` in the Paddle account — including one priced at zero, or one
    // belonging to a different product — and buy a plan at the wrong price.
    let Some(plan) = cfg.plan_for_price(&req.price_id) else {
        return Err(AppError::Validation(
            "that price is not one of this deployment's plans".into(),
        ));
    };

    if req.quantity < 1 {
        return Err(AppError::Validation("quantity must be at least 1".into()));
    }
    // ⚠️ Paddle's own catalogue maximum is 999,999 per price. A larger number is
    // refused by Paddle with an error written for an integrator, so it is caught
    // here where the message can be written for a person.
    if req.quantity > 999_999 {
        return Err(AppError::Validation(
            "that is more seats than Paddle will accept on one subscription".into(),
        ));
    }

    // ⚠️ Refused while one exists rather than quietly creating a second. Two
    // subscriptions for one organisation means two invoices, and whichever
    // webhook arrives last wins — `paddle_subscription_id` is UNIQUE, so the
    // second would also orphan the first.
    let existing: Option<String> = sqlx::query_scalar!(
        "SELECT paddle_subscription_id FROM organizations WHERE id = $1",
        access.org_id
    )
    .fetch_one(&state.db)
    .await?;
    if existing.is_some() {
        return Err(AppError::Validation(
            "this organisation already has a subscription. Change its seat count \
             or plan instead of starting a second one."
                .into(),
        ));
    }

    let (transaction_id, checkout_url) = paddle::PaddleApi::new(cfg)
        .create_transaction(&req.price_id, req.quantity, access.org_id)
        .await?;

    tracing::info!(
        org_id = %access.org_id,
        %transaction_id,
        plan,
        quantity = req.quantity,
        "started a checkout"
    );

    Ok(Json(json!({
        "transaction_id": transaction_id,
        // Open this in a NEW TAB, not in place: the app's master key lives in
        // memory on its own origin and navigating away loses it.
        "checkout_url": checkout_url,
        "plan": plan,
        "quantity": req.quantity,
        "note": "Payment is handled by Paddle, our merchant of record. A subscription \
                 decides which plan's limits apply — it does not grant access to any vault.",
    })))
}

/// `GET /api/v1/orgs/:org_id/billing/catalog`
///
/// What can be bought, priced by Paddle rather than by us.
///
/// # ⚠️ Why the amounts come from Paddle and are not constants
///
/// A billing screen that shows a price different from the one charged is the
/// worst kind of bug on the worst possible screen. Sandbox and live have entirely
/// separate catalogues, so a hard-coded `$9` would be right in one and unverified
/// in the other — and would stay unverified after any price change in the
/// dashboard. Paddle is asked.
pub async fn catalog(
    State(state): State<AppState>,
    _access: OrgAccess<crate::middleware::org_role::AtLeastOrgMember>,
) -> Result<Json<serde_json::Value>, AppError> {
    let cfg = require_paddle(&state)?;
    let prices = paddle::PaddleApi::new(cfg).prices(cfg).await?;
    Ok(Json(json!({ "prices": prices })))
}

// ─── Reading the state ────────────────────────────────────────────────────────

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
                  scheduled_change_action, scheduled_change_at,
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
        // ⚠️ The caller's own role, so the screen can explain who to ask rather
        // than render disabled buttons that look broken.
        "your_role": access.role.as_str(),
        "billing_configured": state.config.paddle.is_some(),
        "subscription": {
            "exists": row.has_subscription,
            "status": row.subscription_status,
            "current_period_ends_at": row.current_period_ends_at,
            // ⚠️ `status` is still `active` while a cancellation is pending.
            // Without this the screen says "renews" on the day it ends.
            "scheduled_change": row.scheduled_change_action.map(|action| json!({
                "action": action,
                "effective_at": row.scheduled_change_at,
            })),
        },
        // ⚠️ Said on the screen that is most likely to worry someone.
        "note": "Billing decides which plan's limits apply. No vault is affected by \
                 a subscription, and nothing is deleted for non-payment.",
    })))
}

/// `GET /api/v1/orgs/:org_id/billing/invoices`
///
/// ⚠️ A pass-through, stored nowhere. Paddle is the merchant of record and holds
/// the billing detail; keeping a copy here would make evnx a processor of
/// payment data it has no reason to hold and no obligation to.
pub async fn invoices(
    State(state): State<AppState>,
    access: OrgAccess<crate::middleware::org_role::AtLeastOrgMember>,
) -> Result<Json<serde_json::Value>, AppError> {
    let cfg = require_paddle(&state)?;
    let sub = subscription_of(&state, access.org_id).await?;
    let rows = paddle::PaddleApi::new(cfg)
        .invoices(&sub.subscription_id)
        .await?;
    Ok(Json(json!({ "invoices": rows })))
}

// ─── Changing it ──────────────────────────────────────────────────────────────

/// `POST /api/v1/orgs/:org_id/billing/portal`
///
/// Authenticated deep links into Paddle's own customer portal.
///
/// # ⚠️ Owner-only, although it only returns links
///
/// The links open cancellation and payment-method forms. An admin can assign
/// seats; only the owner changes what the organisation is billed.
pub async fn portal(
    State(state): State<AppState>,
    access: OrgAccess<OrgOwnerOnly>,
) -> Result<Json<serde_json::Value>, AppError> {
    let cfg = require_paddle(&state)?;
    let sub = subscription_of(&state, access.org_id).await?;

    // ⚠️ The customer id arrives on the first webhook, not at checkout. An
    // organisation that has paid but whose webhook has not landed yet has a
    // subscription id and no customer id, and this says so rather than calling
    // Paddle with the literal string "null" in the path.
    let Some(customer_id) = sub.customer_id else {
        return Err(AppError::Validation(
            "this subscription has no customer on file yet. Try again in a moment.".into(),
        ));
    };

    let urls = paddle::PaddleApi::new(cfg)
        .portal_links(&customer_id, Some(&sub.subscription_id))
        .await?;

    Ok(Json(json!({
        "urls": urls,
        "note": "These links open Paddle, our merchant of record. They expire shortly \
                 and are not shareable.",
    })))
}

#[derive(Deserialize)]
pub struct ChangeSeatsRequest {
    pub quantity: i64,
}

/// `POST /api/v1/orgs/:org_id/billing/seats`
///
/// Change how many seats the subscription pays for.
///
/// # ⚠️ Why this is separate from `PUT /orgs/:id/seats`
///
/// That route writes `organizations.seats` directly, which is right for a
/// deployment with no Paddle. With a live subscription it is **wrong**: Paddle's
/// quantity is what the invoice is computed from, so a local edit would grant
/// seats nobody is billed for and be silently reverted by the next webhook.
/// `PUT /seats` refuses while a subscription exists and names this route.
///
/// ⚠️ This does **not** write `seats` itself. Paddle confirms the change, and the
/// resulting `subscription.updated` webhook is what moves the column — so the
/// database never claims a seat count Paddle has not agreed to.
pub async fn change_seats(
    State(state): State<AppState>,
    access: OrgAccess<OrgOwnerOnly>,
    Json(req): Json<ChangeSeatsRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let cfg = require_paddle(&state)?;

    if req.quantity < 1 {
        return Err(AppError::Validation(
            "a subscription must pay for at least one seat. To stop paying, cancel it.".into(),
        ));
    }
    if req.quantity > 999_999 {
        return Err(AppError::Validation(
            "that is more seats than Paddle will accept on one subscription".into(),
        ));
    }

    let sub = subscription_of(&state, access.org_id).await?;

    // The price the subscription is already on — changing seats must not also
    // change the plan or the billing interval.
    let price_id: Option<String> = sqlx::query_scalar!(
        "SELECT paddle_price_id FROM organizations WHERE id = $1",
        access.org_id
    )
    .fetch_one(&state.db)
    .await?;
    let Some(price_id) = price_id else {
        return Err(AppError::Validation(
            "this subscription's price is not on file yet. Try again in a moment.".into(),
        ));
    };

    paddle::PaddleApi::new(cfg)
        .set_subscription_quantity(&sub.subscription_id, &price_id, req.quantity)
        .await?;

    tracing::info!(
        org_id = %access.org_id,
        subscription = %sub.subscription_id,
        quantity = req.quantity,
        "asked Paddle to change the seat count"
    );

    Ok(Json(json!({
        "quantity": req.quantity,
        // ⚠️ Said plainly, because the screen will still show the old number
        // until the webhook lands — usually a second, occasionally longer.
        "note": "Paddle has accepted the change and will confirm it in a moment. \
                 Nobody loses a seat automatically if the new count is lower.",
    })))
}

/// `POST /api/v1/orgs/:org_id/billing/resume`
///
/// Undo a scheduled cancellation.
///
/// ⚠️ Not "restart a cancelled subscription" — once the status is actually
/// `canceled` there is nothing to resume and a new checkout is required. This
/// clears the `scheduled_change` on a subscription that is **still active**.
pub async fn resume(
    State(state): State<AppState>,
    access: OrgAccess<OrgOwnerOnly>,
) -> Result<Json<serde_json::Value>, AppError> {
    let cfg = require_paddle(&state)?;
    let sub = subscription_of(&state, access.org_id).await?;

    let scheduled: Option<String> = sqlx::query_scalar!(
        "SELECT scheduled_change_action FROM organizations WHERE id = $1",
        access.org_id
    )
    .fetch_one(&state.db)
    .await?;
    if scheduled.is_none() {
        return Err(AppError::Validation(
            "nothing is scheduled on this subscription, so there is nothing to undo".into(),
        ));
    }

    paddle::PaddleApi::new(cfg)
        .clear_scheduled_change(&sub.subscription_id)
        .await?;

    tracing::info!(
        org_id = %access.org_id,
        subscription = %sub.subscription_id,
        "cleared a scheduled subscription change"
    );

    Ok(Json(json!({
        "note": "The scheduled change has been removed. Paddle will confirm in a moment.",
    })))
}
