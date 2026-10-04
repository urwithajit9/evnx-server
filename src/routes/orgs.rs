// src/routes/orgs.rs

//! Organisations: billing and a directory.
//!
//! ## ⛔ What these endpoints cannot do
//!
//! None of them grants access to a vault. The server cannot wrap a vault key, so
//! there is no request shape here that could. Joining an organisation changes
//! which **plan** applies to you (via `quota::resolve_plan`) and nothing else;
//! sharing a vault stays a deliberate act by a vault admin who holds the key.
//!
//! ⚠️ Every message in this module that could be misread as granting access says
//! so explicitly, because "I added them to the org, why can't they see the vault?"
//! is the first question this feature will generate.
//!
//! ## Why all of this is session-only
//!
//! Every route sits behind `require_user_session`, not `require_verified`. An
//! `evnx_tok_` CI token reaching these could invite people, assign seats and
//! change what the account is billed — the same reasoning that keeps
//! `/auth/tokens` and `/auth/account` off API tokens.

use axum::{
    extract::{Path, State},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::{
    errors::AppError,
    middleware::client_ip::ClientContext,
    middleware::org_role::{AtLeastOrgAdmin, AtLeastOrgMember, OrgAccess, OrgOwnerOnly, OrgRole},
    services::audit::record_org_event,
    services::jwt::Claims,
    state::AppState,
};

/// How many live organisations one account may own.
///
/// ⚠️ A hard constant, and it should not stay one. Every other limit in the server
/// is configuration (`quota::Quotas`) precisely so a tier's numbers change without
/// a release — but organisations are not yet a billable thing, so there is no tier
/// for this to belong to. It exists because creating one is free and owning one
/// now *blocks account deletion*: unbounded creation means unbounded blockers on a
/// path someone needs to work.
///
/// Move it into `Quotas` when billing lands (3.3), where it can differ per plan.
const MAX_OWNED_ORGS: i64 = 5;

/// Slug rules, mirrored from migration 010's CHECK.
///
/// ⚠️ Validated here as well as there, so a bad slug is a 422 naming the rule
/// rather than a 500 from a constraint violation. The database remains the
/// authority — this is the error message, not the enforcement.
fn validate_slug(slug: &str) -> Result<(), AppError> {
    let ok = !slug.is_empty()
        && slug.len() <= 63
        && slug
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !slug.starts_with('-')
        && !slug.ends_with('-');

    if ok {
        Ok(())
    } else {
        Err(AppError::Validation(
            "slug must be 1–63 characters of lowercase letters, digits and hyphens, \
             and may not start or end with a hyphen"
                .into(),
        ))
    }
}

fn validate_name(name: &str) -> Result<(), AppError> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.len() > 120 {
        return Err(AppError::Validation(
            "name must be between 1 and 120 characters".into(),
        ));
    }
    Ok(())
}

// ─── Create ───────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateOrgRequest {
    pub name: String,
    pub slug: String,
}

/// `POST /api/v1/orgs`
///
/// ⚠️ **The creator gets the owner role and NO seat**, and that is deliberate.
///
/// Assigning a seat on creation would fail outright for anyone already holding one
/// elsewhere — migration 010 allows at most one seat per person — so the obvious
/// convenience would make "create a second organisation" an error with a confusing
/// message. It would also grant nothing: a new organisation is on `free`, so its
/// seat resolves to the same plan the account already had.
///
/// Seats are assigned deliberately, which is what they will be once they cost
/// money.
///
/// # Errors
/// * `409` — the slug is taken, or the account already owns [`MAX_OWNED_ORGS`].
/// * `422` — the name or slug is malformed.
pub async fn create_org(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<Claims>,
    client: ClientContext,
    Json(req): Json<CreateOrgRequest>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), AppError> {
    let user_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;

    validate_name(&req.name)?;
    validate_slug(&req.slug)?;

    let owned: i64 = sqlx::query_scalar!(
        r#"SELECT COUNT(*) AS "n!" FROM organizations
           WHERE owner_id = $1 AND deleted_at IS NULL"#,
        user_id
    )
    .fetch_one(&state.db)
    .await?;

    if owned >= MAX_OWNED_ORGS {
        return Err(AppError::Conflict(format!(
            "this account already owns {MAX_OWNED_ORGS} organisations, which is the limit. \
             Delete one you no longer need."
        )));
    }

    // One transaction: an organisation with no owner row would be invisible to
    // `list_orgs` (which joins through `organization_members`) while still holding
    // its unique slug — the same orphan shape `create_vault` was fixed for in B10.
    let mut tx = state.db.begin().await?;

    let org_id: Uuid = match sqlx::query_scalar!(
        r#"INSERT INTO organizations (name, slug, owner_id)
           VALUES ($1, $2, $3) RETURNING id"#,
        req.name.trim(),
        req.slug,
        user_id
    )
    .fetch_one(&mut *tx)
    .await
    {
        Ok(id) => id,
        // ⚠️ Mapped rather than surfaced. A unique violation on the slug is a
        // user-correctable condition, and `AppError::Database` renders as a 500
        // with "Internal server error" — which tells someone who typed a taken
        // name that the service is broken.
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(AppError::Conflict(format!(
                "the slug {:?} is already taken. Pick another.",
                req.slug
            )));
        }
        Err(e) => return Err(AppError::Database(e)),
    };

    sqlx::query!(
        r#"INSERT INTO organization_members (org_id, user_id, role, seat_assigned_at)
           VALUES ($1, $2, 'owner', NULL)"#,
        org_id,
        user_id
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    record_org_event(
        &state.db,
        org_id,
        user_id,
        "org_created",
        &client,
        json!({ "slug": req.slug }),
    );

    Ok((
        axum::http::StatusCode::CREATED,
        Json(json!({
            "id": org_id,
            "name": req.name.trim(),
            "slug": req.slug,
            "plan": "free",
            "your_role": "owner",
            // Said here because it is the moment someone forms a belief about what
            // they just made.
            "note": "An organisation is billing and a directory. It does not grant \
                     access to any vault — share a vault with `evnx vault share`."
        })),
    ))
}

// ─── Read ─────────────────────────────────────────────────────────────────────

/// `GET /api/v1/orgs` — organisations this account belongs to.
pub async fn list_orgs(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<Claims>,
) -> Result<Json<serde_json::Value>, AppError> {
    let user_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;

    let rows = sqlx::query!(
        r#"
        SELECT o.id, o.name, o.slug, o.plan, o.seats,
               m.role AS "role!", (m.seat_assigned_at IS NOT NULL) AS "has_seat!",
               (SELECT COUNT(*) FROM organization_members s
                 WHERE s.org_id = o.id AND s.seat_assigned_at IS NOT NULL) AS "seats_used!"
        FROM organizations o
        JOIN organization_members m ON m.org_id = o.id AND m.user_id = $1
        WHERE o.deleted_at IS NULL
        ORDER BY o.name
        "#,
        user_id
    )
    .fetch_all(&state.db)
    .await?;

    let orgs: Vec<_> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.id, "name": r.name, "slug": r.slug, "plan": r.plan,
                "your_role": r.role,
                "you_hold_a_seat": r.has_seat,
                "seats": { "used": r.seats_used, "purchased": r.seats },
            })
        })
        .collect();

    Ok(Json(json!({ "organizations": orgs })))
}

/// `GET /api/v1/orgs/:org_id/members` — the directory, and who holds a seat.
///
/// Any member may see this. Knowing who else is in your organisation is the point
/// of a directory, and the alternative — admins only — would make a team unable to
/// find each other's addresses to share vaults with.
pub async fn list_members(
    State(state): State<AppState>,
    access: OrgAccess<AtLeastOrgMember>,
) -> Result<Json<serde_json::Value>, AppError> {
    let rows = sqlx::query!(
        r#"
        SELECT u.id, u.email, m.role AS "role!",
               m.seat_assigned_at, m.created_at AS "joined_at!"
        FROM organization_members m
        JOIN users u ON u.id = m.user_id
        WHERE m.org_id = $1
        ORDER BY m.role DESC, u.email
        "#,
        access.org_id
    )
    .fetch_all(&state.db)
    .await?;

    let members: Vec<_> = rows
        .into_iter()
        .map(|r| {
            json!({
                "user_id": r.id,
                "email": r.email,
                "role": r.role,
                "holds_a_seat": r.seat_assigned_at.is_some(),
                "seat_assigned_at": r.seat_assigned_at,
                "joined_at": r.joined_at,
                "is_you": r.id == access.user_id,
            })
        })
        .collect();

    Ok(Json(json!({
        "members": members,
        "note": "Organisation membership does not grant access to any vault."
    })))
}

// ─── Update the organisation ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct PatchOrgRequest {
    pub name: Option<String>,
}

/// `PATCH /api/v1/orgs/:org_id` — rename. Administration, not billing.
pub async fn patch_org(
    State(state): State<AppState>,
    access: OrgAccess<AtLeastOrgAdmin>,
    Json(req): Json<PatchOrgRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let name = req
        .name
        .ok_or_else(|| AppError::Validation("nothing to change: send name".into()))?;
    validate_name(&name)?;

    sqlx::query!(
        "UPDATE organizations SET name = $1, updated_at = NOW() WHERE id = $2",
        name.trim(),
        access.org_id
    )
    .execute(&state.db)
    .await?;

    Ok(Json(json!({ "id": access.org_id, "name": name.trim() })))
}

#[derive(Deserialize)]
pub struct SetSeatsRequest {
    /// Purchased seats. `null` is unlimited.
    pub seats: Option<i32>,
}

/// `PUT /api/v1/orgs/:org_id/seats` — how many seats are purchased.
///
/// ⚠️ **Its own route, owner-only, because the authorisation belongs in the
/// signature.** This started out as a `seats` field on `PATCH /:org_id` with an
/// inline `if role < Owner` check and a comment explaining why one handler carried
/// two authorisations. The comment was rationalising the shape rather than
/// justifying it: `middleware::org_role`'s whole premise is that a requirement in
/// the signature cannot be skipped and is visible without reading the body. An
/// inline check is exactly the thing that premise exists to avoid.
///
/// Seat *count* is owner-only while seat *assignment* is admin, because the count
/// is what an invoice is computed from. An admin who could raise it could raise
/// the bill.
///
/// ⚠️ Temporary. Once Paddle is wired (3.3) this number comes from a verified
/// webhook; a human endpoint that sets it exists only so seats can be exercised
/// before billing does.
pub async fn set_seats(
    State(state): State<AppState>,
    access: OrgAccess<OrgOwnerOnly>,
    client: ClientContext,
    Json(req): Json<SetSeatsRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    if let Some(n) = req.seats {
        if n < 0 {
            return Err(AppError::Validation(
                "seats must be zero or more, or null for unlimited".into(),
            ));
        }
    }

    sqlx::query!(
        "UPDATE organizations SET seats = $1, updated_at = NOW() WHERE id = $2",
        req.seats,
        access.org_id
    )
    .execute(&state.db)
    .await?;

    let assigned: i64 = sqlx::query_scalar!(
        r#"SELECT COUNT(*) AS "n!" FROM organization_members
           WHERE org_id = $1 AND seat_assigned_at IS NOT NULL"#,
        access.org_id
    )
    .fetch_one(&state.db)
    .await?;

    // ⚠️ Lowering the count below what is already assigned is ALLOWED, and only
    // reported. Refusing would be right for a human edit and wrong for Paddle's
    // downgrade webhook, which this endpoint stands in for — a refused downgrade
    // leaves billing and the database disagreeing with no way to reconcile.
    // Migration 010 records the same decision for why no trigger enforces it.
    let over_seated = req.seats.is_some_and(|p| assigned > i64::from(p));
    if over_seated {
        tracing::warn!(
            org_id = %access.org_id,
            assigned,
            purchased = ?req.seats,
            "organisation is over-seated after a seat-count change"
        );
    }

    record_org_event(
        &state.db,
        access.org_id,
        access.user_id,
        "org_seats_changed",
        &client,
        json!({ "purchased": req.seats, "assigned": assigned, "over_seated": over_seated }),
    );

    Ok(Json(json!({
        "id": access.org_id,
        "seats": { "used": assigned, "purchased": req.seats },
        "over_seated": over_seated,
        // Reported rather than refused, so whoever lowered it knows the state they
        // created instead of discovering it when someone's limits drop.
        "note": if over_seated {
            "More seats are assigned than purchased. Release some, or raise the count."
        } else {
            "ok"
        },
    })))
}

/// `DELETE /api/v1/orgs/:org_id` — soft-delete an organisation.
///
/// ⚠️ **This endpoint exists because leaving it out was a trap.** Owning an
/// organisation blocks account deletion (see `auth::delete_account`), and
/// `MAX_OWNED_ORGS` caps creation at five — so without a way to delete one, five
/// organisations would permanently remove the ability to close the account. A
/// limit with no release valve is worse than no limit.
///
/// Owner-only, by signature.
///
/// ⚠️ **Soft delete, and `quota::resolve_plan` already honours it**: the join
/// carries `o.deleted_at IS NULL`, so every seat holder drops back to their own
/// plan the moment this returns. That is the intended behaviour and the reason
/// the confirmation below spells it out — it is a plan change for everybody at
/// once.
///
/// Membership rows are left in place rather than deleted. They are unreachable
/// through every query (all of which join a live organisation), and keeping them
/// means an accidental deletion can be undone by clearing one column.
///
/// # Errors
/// * `403` — not the owner.
/// * `409` — seats are still assigned, unless `force` is set.
pub async fn delete_org(
    State(state): State<AppState>,
    access: OrgAccess<OrgOwnerOnly>,
    client: ClientContext,
    Json(req): Json<DeleteOrgRequest>,
) -> Result<axum::http::StatusCode, AppError> {
    let assigned: i64 = sqlx::query_scalar!(
        r#"SELECT COUNT(*) AS "n!" FROM organization_members
           WHERE org_id = $1 AND seat_assigned_at IS NOT NULL"#,
        access.org_id
    )
    .fetch_one(&state.db)
    .await?;

    // ⚠️ Refused by default when seats are assigned, because deleting is a plan
    // change for every holder at once and they are not the one running this. The
    // owner's own seat counts: it is still somebody losing limits.
    if assigned > 0 && !req.force {
        return Err(AppError::Conflict(format!(
            "{assigned} seat(s) are still assigned, and deleting this organisation              drops every holder back to their own plan. Release the seats first, or              send force = true to accept that."
        )));
    }

    sqlx::query!(
        "UPDATE organizations SET deleted_at = NOW(), updated_at = NOW()          WHERE id = $1 AND deleted_at IS NULL",
        access.org_id
    )
    .execute(&state.db)
    .await?;

    record_org_event(
        &state.db,
        access.org_id,
        access.user_id,
        "org_deleted",
        &client,
        json!({ "seats_assigned_at_deletion": assigned, "forced": req.force }),
    );

    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Deserialize, Default)]
pub struct DeleteOrgRequest {
    /// Delete even though seats are assigned, accepting that every holder's plan
    /// drops back to their own.
    #[serde(default)]
    pub force: bool,
}

// ─── Members ──────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct PatchMemberRequest {
    pub role: Option<String>,
    /// `true` assigns a seat, `false` releases one.
    pub seat: Option<bool>,
}

/// `PATCH /api/v1/orgs/:org_id/members/:user_id` — role and seat.
///
/// # Errors
/// * `403` — not an admin, or acting on someone you do not outrank.
/// * `404` — no such member of this organisation.
/// * `409` — the target already holds a seat in another organisation, which is
///   named; or this organisation has no seat free.
pub async fn patch_member(
    State(state): State<AppState>,
    access: OrgAccess<AtLeastOrgAdmin>,
    client: ClientContext,
    Path(params): Path<std::collections::HashMap<String, String>>,
    Json(req): Json<PatchMemberRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let target = params
        .get("user_id")
        .and_then(|v| Uuid::parse_str(v).ok())
        .ok_or(AppError::NotFound)?;

    if req.role.is_none() && req.seat.is_none() {
        return Err(AppError::Validation(
            "nothing to change: send role, seat, or both".into(),
        ));
    }

    let current: String = sqlx::query_scalar!(
        r#"SELECT role AS "role!" FROM organization_members
           WHERE org_id = $1 AND user_id = $2"#,
        access.org_id,
        target
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)?;

    let current_role = OrgRole::parse(&current)
        .ok_or_else(|| AppError::Internal(format!("unrecognised org role: {current:?}")))?;

    // ⚠️ **Role changes and seat changes have different threat models, and a single
    // rank check for both was wrong.**
    //
    // The first version of this handler required `outranks(target)` before doing
    // anything, which made an admin unable to assign a seat to THEMSELVES —
    // `Admin > Admin` is false. That is not a privilege question at all: a seat is
    // one the organisation has already purchased, and assigning seats is precisely
    // what an admin is for. Caught by
    // `setting_the_seat_count_is_owner_only_but_assigning_a_seat_is_admin`.
    //
    // The three rules, stated separately because they protect different things:
    //
    //   role change    outrank the target AND the granted role — otherwise an
    //                  admin creates a peer neither of them can manage
    //   seat assign    admin is enough, any target including yourself. It spends
    //                  a purchased seat; it grants nothing within the org
    //   seat release   outrank the target, or release your own. Releasing someone
    //                  else's seat LOWERS THEIR PLAN, so an admin releasing the
    //                  owner's seat would be a hostile act against the person
    //                  paying for the organisation

    if let Some(ref raw) = req.role {
        if !access.outranks(current_role) {
            return Err(AppError::Forbidden);
        }
        let granted = OrgRole::parse(raw)
            .filter(|r| OrgRole::ASSIGNABLE.contains(r))
            .ok_or_else(|| {
                AppError::Validation(format!(
                    "role must be one of: {}",
                    OrgRole::ASSIGNABLE
                        .iter()
                        .map(|r| r.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            })?;

        // ⚠️ And you may only grant a role you outrank, for the same reason.
        if !access.outranks(granted) {
            return Err(AppError::Forbidden);
        }

        sqlx::query!(
            "UPDATE organization_members SET role = $1 WHERE org_id = $2 AND user_id = $3",
            granted.as_str(),
            access.org_id,
            target
        )
        .execute(&state.db)
        .await?;

        record_org_event(
            &state.db,
            access.org_id,
            access.user_id,
            "org_role_changed",
            &client,
            json!({ "target": target, "from": current_role.as_str(), "to": granted.as_str() }),
        );
    }

    if let Some(assign) = req.seat {
        // Releasing someone else's seat drops their plan, so it needs rank.
        // Assigning does not, and neither does releasing your own.
        if !assign && target != access.user_id && !access.outranks(current_role) {
            return Err(AppError::Forbidden);
        }

        if assign {
            // Capacity first. `NULL` purchased seats is unlimited.
            let row = sqlx::query!(
                r#"SELECT o.seats,
                          (SELECT COUNT(*) FROM organization_members s
                            WHERE s.org_id = o.id AND s.seat_assigned_at IS NOT NULL) AS "used!"
                   FROM organizations o WHERE o.id = $1"#,
                access.org_id
            )
            .fetch_one(&state.db)
            .await?;

            if let Some(purchased) = row.seats {
                if row.used >= i64::from(purchased) {
                    return Err(AppError::Conflict(format!(
                        "all {purchased} seats are assigned. Release one, or raise the \
                         seat count."
                    )));
                }
            }

            match sqlx::query!(
                "UPDATE organization_members SET seat_assigned_at = NOW() \
                 WHERE org_id = $1 AND user_id = $2 AND seat_assigned_at IS NULL",
                access.org_id,
                target
            )
            .execute(&state.db)
            .await
            {
                Ok(_) => {}
                // ⚠️ The one-seat-per-person index firing. Surfaced as a named
                // conflict rather than a 500, because the admin needs to know they
                // are not merely blocked — someone else's organisation is paying
                // for this person, and taking the seat silently would move a charge
                // between two customers.
                Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                    let other: Option<String> = sqlx::query_scalar!(
                        r#"SELECT o.name FROM organization_members m
                           JOIN organizations o ON o.id = m.org_id AND o.deleted_at IS NULL
                           WHERE m.user_id = $1 AND m.seat_assigned_at IS NOT NULL"#,
                        target
                    )
                    .fetch_optional(&state.db)
                    .await?;

                    return Err(AppError::Conflict(match other {
                        Some(name) => format!(
                            "this person already holds a seat in {name}, and a person may \
                             hold only one. That organisation has to release it first."
                        ),
                        None => "this person already holds a seat elsewhere.".into(),
                    }));
                }
                Err(e) => return Err(AppError::Database(e)),
            }
        } else {
            sqlx::query!(
                "UPDATE organization_members SET seat_assigned_at = NULL \
                 WHERE org_id = $1 AND user_id = $2",
                access.org_id,
                target
            )
            .execute(&state.db)
            .await?;
        }

        // ⚠️ Recorded for both directions. A seat IS a plan change, so "when did
        // my limits move, and who moved them" has to be answerable — that is the
        // question a billing dispute actually asks.
        record_org_event(
            &state.db,
            access.org_id,
            access.user_id,
            if assign {
                "org_seat_assigned"
            } else {
                "org_seat_released"
            },
            &client,
            json!({ "target": target }),
        );
    }

    Ok(Json(json!({
        "user_id": target,
        "changed": true,
        // ⚠️ Said on every seat change, because a seat *is* a plan change and the
        // person it happened to will see their limits move without asking.
        "note": "A seat decides which plan's limits apply to this account. It does \
                 not grant access to any vault."
    })))
}

/// `DELETE /api/v1/orgs/:org_id/members/:user_id`
///
/// ⚠️ Admin to remove someone else, any member to remove **themselves**. Leaving
/// an organisation you were invited to should not require asking an admin, and the
/// route therefore requires only membership, with the rank check done here.
///
/// The owner cannot be removed or leave: migration 010 makes `owner_id` the
/// organisation's, and an organisation with no owner has nobody who can delete it
/// or change its billing.
pub async fn remove_member(
    State(state): State<AppState>,
    access: OrgAccess<AtLeastOrgMember>,
    client: ClientContext,
    Path(params): Path<std::collections::HashMap<String, String>>,
) -> Result<axum::http::StatusCode, AppError> {
    let target = params
        .get("user_id")
        .and_then(|v| Uuid::parse_str(v).ok())
        .ok_or(AppError::NotFound)?;

    let current: String = sqlx::query_scalar!(
        r#"SELECT role AS "role!" FROM organization_members
           WHERE org_id = $1 AND user_id = $2"#,
        access.org_id,
        target
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)?;

    let current_role = OrgRole::parse(&current)
        .ok_or_else(|| AppError::Internal(format!("unrecognised org role: {current:?}")))?;

    if current_role == OrgRole::Owner {
        return Err(AppError::Conflict(
            "the owner cannot be removed from their own organisation. Transfer \
             ownership, or delete the organisation."
                .into(),
        ));
    }

    let leaving_voluntarily = target == access.user_id;
    if !leaving_voluntarily {
        if access.role < OrgRole::Admin {
            return Err(AppError::Forbidden);
        }
        if !access.outranks(current_role) {
            return Err(AppError::Forbidden);
        }
    }

    // The row delete releases the seat with it, since the seat lives on the row.
    sqlx::query!(
        "DELETE FROM organization_members WHERE org_id = $1 AND user_id = $2",
        access.org_id,
        target
    )
    .execute(&state.db)
    .await?;

    record_org_event(
        &state.db,
        access.org_id,
        access.user_id,
        if leaving_voluntarily {
            "org_left"
        } else {
            "org_member_removed"
        },
        &client,
        json!({ "target": target, "role": current_role.as_str() }),
    );

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ─── Invitations ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateInviteRequest {
    pub email: String,
    pub role: Option<String>,
}

/// `POST /api/v1/orgs/:org_id/invites`
///
/// Returns the raw token **once**, the same shape as minting an API token. The
/// email carries a link as well; the token is returned so a CLI can offer to copy
/// one and so this flow is exercisable without a mailbox.
///
/// ⚠️ Returning it is safe only because redemption checks that the invited address
/// is the redeemer's own account email. Without that check, an admin inviting an
/// address they do not control would be handing themselves a second membership.
pub async fn create_invite(
    State(state): State<AppState>,
    access: OrgAccess<AtLeastOrgAdmin>,
    client: ClientContext,
    Json(req): Json<CreateInviteRequest>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), AppError> {
    let email = req.email.trim().to_lowercase();
    if email.is_empty() || !email.contains('@') {
        return Err(AppError::Validation("a valid email is required".into()));
    }

    let role = match req.role.as_deref() {
        None => OrgRole::Member,
        Some(raw) => OrgRole::parse(raw)
            .filter(|r| OrgRole::ASSIGNABLE.contains(r))
            .ok_or_else(|| {
                AppError::Validation(format!(
                    "role must be one of: {}",
                    OrgRole::ASSIGNABLE
                        .iter()
                        .map(|r| r.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            })?,
    };

    // ⚠️ And you may only invite at a rank you outrank — an admin inviting an
    // admin creates a peer, same rule as the role change above.
    if !access.outranks(role) {
        return Err(AppError::Forbidden);
    }

    // Already in the directory? Answer plainly. This is not an enumeration risk:
    // the caller is an admin of this organisation and can already list its members.
    let existing: Option<Uuid> = sqlx::query_scalar!(
        r#"SELECT m.user_id FROM organization_members m
           JOIN users u ON u.id = m.user_id
           WHERE m.org_id = $1 AND lower(u.email) = $2"#,
        access.org_id,
        email
    )
    .fetch_optional(&state.db)
    .await?;

    if existing.is_some() {
        return Err(AppError::Conflict(format!(
            "{email} is already a member of this organisation."
        )));
    }

    use rand::RngCore;
    let mut raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let token = format!("evnx_inv_{}", hex::encode(raw));
    let token_hash = blake3::hash(token.as_bytes()).to_hex().to_string();

    let invite_id: Uuid = sqlx::query_scalar!(
        r#"INSERT INTO organization_invites (org_id, email, role, token_hash, invited_by)
           VALUES ($1, $2, $3, $4, $5) RETURNING id"#,
        access.org_id,
        email,
        role.as_str(),
        token_hash,
        access.user_id
    )
    .fetch_one(&state.db)
    .await?;

    let org_name: String = sqlx::query_scalar!(
        r#"SELECT name AS "name!" FROM organizations WHERE id = $1"#,
        access.org_id
    )
    .fetch_one(&state.db)
    .await?;

    // Fire-and-forget, like every other mail: an outage must not fail the
    // invitation, and the token is returned below regardless.
    {
        let email_service = state.email.clone();
        let to = email.clone();
        let org_name = org_name.clone();
        let token = token.clone();
        tokio::spawn(async move {
            if let Err(e) = email_service.send_org_invite(&to, &org_name, &token).await {
                // ⚠️ The token is a bearer credential, so the failure is logged
                // without it — the same discipline as the verification mail.
                tracing::warn!(error = %e, "failed to send an organisation invitation");
            }
        });
    }

    // ⚠️ The address is recorded; the token never is. Who was invited is the fact
    // a billing dispute turns on, and the org's own admins can already list it —
    // the token is a bearer credential and belongs in no row but its own hash.
    record_org_event(
        &state.db,
        access.org_id,
        access.user_id,
        "org_invited",
        &client,
        json!({ "email": email, "role": role.as_str() }),
    );

    Ok((
        axum::http::StatusCode::CREATED,
        Json(json!({
            "id": invite_id,
            "email": email,
            "role": role.as_str(),
            "token": token,
            "expires_in_days": 7,
            "note": "Joining this organisation decides which plan's limits apply. It \
                     does not grant access to any vault."
        })),
    ))
}

/// `GET /api/v1/orgs/:org_id/invites` — invitations not yet redeemed or expired.
pub async fn list_invites(
    State(state): State<AppState>,
    access: OrgAccess<AtLeastOrgAdmin>,
) -> Result<Json<serde_json::Value>, AppError> {
    let rows = sqlx::query!(
        r#"SELECT id, email, role AS "role!", expires_at, created_at
           FROM organization_invites
           WHERE org_id = $1 AND used_at IS NULL AND expires_at > NOW()
           ORDER BY created_at DESC"#,
        access.org_id
    )
    .fetch_all(&state.db)
    .await?;

    let invites: Vec<_> = rows
        .into_iter()
        // ⚠️ No `token_hash`. It is useless to a client and listing it would put a
        // credential-shaped value in a response for no reason.
        .map(|r| {
            json!({
                "id": r.id, "email": r.email, "role": r.role,
                "expires_at": r.expires_at, "created_at": r.created_at,
            })
        })
        .collect();

    Ok(Json(json!({ "invites": invites })))
}

/// `DELETE /api/v1/orgs/:org_id/invites/:invite_id` — withdraw an invitation.
///
/// Marks it used rather than deleting the row, so the record of who invited whom
/// survives. A withdrawn invitation and a redeemed one are both simply unusable.
pub async fn revoke_invite(
    State(state): State<AppState>,
    access: OrgAccess<AtLeastOrgAdmin>,
    client: ClientContext,
    Path(params): Path<std::collections::HashMap<String, String>>,
) -> Result<axum::http::StatusCode, AppError> {
    let invite_id = params
        .get("invite_id")
        .and_then(|v| Uuid::parse_str(v).ok())
        .ok_or(AppError::NotFound)?;

    let affected = sqlx::query!(
        "UPDATE organization_invites SET used_at = NOW() \
         WHERE id = $1 AND org_id = $2 AND used_at IS NULL",
        invite_id,
        access.org_id
    )
    .execute(&state.db)
    .await?
    .rows_affected();

    if affected == 0 {
        return Err(AppError::NotFound);
    }

    record_org_event(
        &state.db,
        access.org_id,
        access.user_id,
        "org_invite_revoked",
        &client,
        json!({ "invite_id": invite_id }),
    );

    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct AcceptInviteRequest {
    pub token: String,
}

/// `POST /api/v1/orgs/invites/accept`
///
/// ⚠️ **Not under `/:org_id`**, because the caller is not a member yet — there is
/// no organisation role to extract and `OrgAccess` could not be satisfied. The
/// only credential is the token.
///
/// ⚠️ **A wrong token, an expired one, a used one and one addressed to somebody
/// else all answer identically.** Distinguishing them would turn this endpoint
/// into an oracle for which invitations exist and who they were sent to.
///
/// ⚠️ **The invited address must be the caller's own account email.** Without that
/// check the token alone would be enough, so anyone it was forwarded to could join
/// a paid organisation.
pub async fn accept_invite(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<Claims>,
    client: ClientContext,
    Json(req): Json<AcceptInviteRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let user_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;
    let token_hash = blake3::hash(req.token.trim().as_bytes())
        .to_hex()
        .to_string();

    // One opaque refusal for every way this can fail.
    let refused = || {
        AppError::Validation(
            "that invitation is not valid for this account. It may have expired, been \
             used already, or been sent to a different address."
                .into(),
        )
    };

    let mut tx = state.db.begin().await?;

    // `FOR UPDATE` so two concurrent redemptions of one token cannot both pass the
    // `used_at IS NULL` check — the row is locked until the update below commits.
    let invite = sqlx::query!(
        r#"SELECT i.id, i.org_id, i.email, i.role AS "role!", o.name AS "org_name!"
           FROM organization_invites i
           JOIN organizations o ON o.id = i.org_id AND o.deleted_at IS NULL
           WHERE i.token_hash = $1 AND i.used_at IS NULL AND i.expires_at > NOW()
           FOR UPDATE OF i"#,
        token_hash
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(refused)?;

    let caller_email: String = sqlx::query_scalar!(
        r#"SELECT email AS "email!" FROM users WHERE id = $1"#,
        user_id
    )
    .fetch_one(&mut *tx)
    .await?;

    if caller_email.to_lowercase() != invite.email.to_lowercase() {
        return Err(refused());
    }

    // ⚠️ `ON CONFLICT DO NOTHING` rather than letting the insert fail: being
    // already in the directory is not an error worth refusing a redemption over,
    // and the invitation is spent either way.
    sqlx::query!(
        r#"INSERT INTO organization_members (org_id, user_id, role, seat_assigned_at)
           VALUES ($1, $2, $3, NULL)
           ON CONFLICT (org_id, user_id) DO NOTHING"#,
        invite.org_id,
        user_id,
        invite.role
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query!(
        "UPDATE organization_invites SET used_at = NOW() WHERE id = $1",
        invite.id
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    record_org_event(
        &state.db,
        invite.org_id,
        user_id,
        "org_joined",
        &client,
        json!({ "role": invite.role }),
    );

    Ok(Json(json!({
        "org_id": invite.org_id,
        "organization": invite.org_name,
        "role": invite.role,
        // ⚠️ Joining assigns NO seat. An admin assigns one deliberately, so the
        // plan does not change on redemption — and this says so rather than
        // leaving someone to wonder why their limits did not move.
        "seat": false,
        "note": "You are in the directory. An administrator assigns a seat, which is \
                 what decides your plan's limits. Membership does not grant access \
                 to any vault — a vault is shared with `evnx vault share`."
    })))
}
