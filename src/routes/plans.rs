// src/routes/plans.rs

//! What each plan allows — public, unauthenticated, no account required.
//!
//! ## Why this is public
//!
//! The pricing page has to state the free tier's limits, and until now it kept
//! its own copy of them. That copy is wrong the moment a `QUOTA_*` variable
//! changes in production, and nothing anywhere would say so: the server would
//! quietly enforce one number while the website advertised another, and the
//! first person to find out would be a user being refused something the page
//! had promised.
//!
//! So the server publishes what it enforces. The website reads this endpoint at
//! build time and commits the answer, which means a deploy carrying a quota
//! change produces a visible diff in the website repo rather than silence.
//!
//! ## ⚠️ What this deliberately does NOT return
//!
//! **Prices.** The server has no opinion about money and must not acquire one.
//! Limits are enforcement; prices are a commercial decision that lives in the
//! website and in Paddle. Putting them here would make a pricing change a
//! server deploy.
//!
//! ## ⚠️ Why it needs no authentication
//!
//! Every value here already appears on a public pricing page. There is no user
//! in the response, no count, no identifier — only configuration that is
//! intended to be read by anyone considering an account. Requiring a session
//! would mean the pricing page could not use it, which is the entire point.
//!
//! For what *you* are using against these limits, see
//! [`crate::routes::usage`] — that one is session-only, because it names the
//! vaults you own.

use axum::{extract::State, http::header, response::IntoResponse, Json};
use serde_json::json;

use crate::services::quota::{Plan, PlanLimits, Quotas};
use crate::state::AppState;

/// How long a CDN or client may hold this. Quotas change at deploy time, so
/// minutes are fine and the endpoint should never become a traffic concern.
const CACHE_SECONDS: u32 = 300;

/// Every plan, keyed by the string an account's `users.plan` column holds.
///
/// ⚠️ Driven by [`Plan::ALL`] rather than a list written out here. A list
/// written out here is a list that silently stops including a new tier, and
/// the symptom would be a pricing page missing a plan nobody noticed shipping.
fn render(quotas: &Quotas) -> serde_json::Value {
    let mut out = serde_json::Map::with_capacity(Plan::ALL.len());
    for plan in Plan::ALL {
        out.insert(plan.as_str().to_owned(), limits_json(quotas.for_plan(plan)));
    }
    serde_json::Value::Object(out)
}

fn limits_json(limits: PlanLimits) -> serde_json::Value {
    // `null` means unlimited, spelled as absence rather than as a sentinel —
    // the same convention `GET /auth/usage` uses. A very large number would be
    // indistinguishable from a misconfiguration.
    json!({
        "vaults": limits.vaults,
        "versions_per_vault": limits.versions_per_vault,
        "api_tokens": limits.api_tokens,
        "audit_retention_days": limits.audit_retention_days,
    })
}

/// Limits for every plan.
///
/// `GET /api/v1/plans`
///
/// ```json
/// {
///   "plans": {
///     "free":       { "vaults": 3, "versions_per_vault": 5, "api_tokens": 2, "audit_retention_days": 7 },
///     "team":       { "vaults": null, "versions_per_vault": null, "api_tokens": null, "audit_retention_days": 90 },
///     "enterprise": { "vaults": null, "versions_per_vault": null, "api_tokens": null, "audit_retention_days": null }
///   }
/// }
/// ```
///
/// ⚠️ The keys are the **same strings** as `users.plan`, which migration 008
/// constrains with `CHECK (plan IN ('free','team','enterprise'))`. A consumer
/// may rely on that: a plan id appearing here is a plan id an account can hold.
pub async fn plans(State(state): State<AppState>) -> impl IntoResponse {
    let body = Json(json!({ "plans": render(&state.config.quotas) }));

    (
        [(
            header::CACHE_CONTROL,
            format!("public, max-age={CACHE_SECONDS}"),
        )],
        body,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every plan the database permits must appear in the response.
    ///
    /// ⚠️ This is the check that catches a tier added to `Plan` and to
    /// migration 008 but never published. The website builds its pricing page
    /// from this endpoint, so a plan missing here is a plan nobody can buy.
    #[test]
    fn every_plan_is_published() {
        let rendered = render(&Quotas::default());

        // The closed set from `CHECK (plan IN (...))` in migration 008.
        for id in ["free", "team", "enterprise"] {
            assert!(
                rendered.get(id).is_some(),
                "plan {id:?} is storable in users.plan but is not published by GET /api/v1/plans"
            );
        }
        assert_eq!(
            rendered.as_object().unwrap().len(),
            3,
            "a plan was published that migration 008 will not let an account hold"
        );
    }

    /// Unlimited must serialise as `null`, not as a number or a string.
    #[test]
    fn unlimited_is_null() {
        let q = Quotas::default();
        let team = limits_json(q.for_plan(Plan::Team));
        assert!(
            team["vaults"].is_null(),
            "unlimited must be null, got {}",
            team["vaults"]
        );
        assert_eq!(team["audit_retention_days"], 90);
    }

    /// The free tier is the agreed set of numbers, and the website states them.
    ///
    /// ⚠️ Changing a number here changes a published price-page claim. That is
    /// allowed — it is configuration — but it should never happen by accident,
    /// so the agreed values are written down in a place that fails.
    #[test]
    fn the_free_tier_matches_what_the_pricing_page_advertises() {
        let free = limits_json(Quotas::default().for_plan(Plan::Free));
        assert_eq!(free["vaults"], 3);
        assert_eq!(free["versions_per_vault"], 5);
        assert_eq!(free["api_tokens"], 2);
        assert_eq!(free["audit_retention_days"], 7);
    }

    /// A price must never appear in this response.
    ///
    /// ⚠️ The temptation to "just add the price so the website has one source"
    /// is real and it is wrong: it makes a pricing change a server deploy, and
    /// it gives the API an opinion about money it has no way to keep current
    /// with Paddle.
    #[test]
    fn no_prices_leak_into_the_api() {
        let rendered = render(&Quotas::default()).to_string();
        for forbidden in ["price", "amount", "currency", "usd", "cents", "seat"] {
            assert!(
                !rendered.to_lowercase().contains(forbidden),
                "{forbidden:?} appeared in the plans response — prices belong in the website, not here"
            );
        }
    }
}
