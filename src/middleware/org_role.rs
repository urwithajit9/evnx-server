// src/middleware/org_role.rs

//! Organisation-level authorisation: may this user administer *this organisation*?
//!
//! ## ⛔ This is not vault authorisation, and the two must never be conflated
//!
//! An organisation role says what you may do to the **organisation** — invite
//! people, assign seats, rename it. It says **nothing** about any vault.
//!
//! An org owner is not thereby a vault admin. A vault admin is not thereby an org
//! admin. The server cannot wrap a vault key, so no organisation role can grant
//! vault access; see migration 010. [`crate::middleware::vault_role::VaultAccess`]
//! answers vault questions and this answers organisation questions, and there is
//! deliberately no conversion between them.
//!
//! ⚠️ The Phase 3 mockups made exactly this mistake, describing an org that could
//! grant vault access. The plan superseded them and the migration has no column
//! that could express it. This module is the third place the separation is stated,
//! because collapsing the two axes is the single most tempting wrong turn here.
//!
//! ## Rank, not set membership
//!
//! Same shape as `vault_role`: [`OrgRole`] is ordered and a requirement is a
//! minimum, so adding a rung later is one edit rather than a sweep of call sites.

use std::marker::PhantomData;

use axum::{
    async_trait,
    extract::{FromRequestParts, Path},
    http::request::Parts,
};
use uuid::Uuid;

use crate::{errors::AppError, services::jwt::Claims, state::AppState};

/// A role within an organisation, ordered from least to most privileged.
///
/// The derived `Ord` **is** the permission model, so the declaration order below
/// is load-bearing. Reordering these variants silently changes who can do what.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OrgRole {
    /// In the directory. May see who else is, and nothing more.
    Member,
    /// May invite, remove, and assign seats.
    Admin,
    /// Everything, plus renaming, changing seat count and deleting the org.
    /// Exactly one per organisation.
    Owner,
}

impl OrgRole {
    /// Parse the stored value.
    ///
    /// Migration 010's `organization_members_role_is_known` makes an unknown role
    /// unstorable, so this failing means the row was written outside the
    /// application. A 500 rather than a guess: silently treating an unrecognised
    /// role as `Member` would be a quiet privilege change in whichever direction
    /// happened to be wrong.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "member" => Some(Self::Member),
            "admin" => Some(Self::Admin),
            "owner" => Some(Self::Owner),
            _ => None,
        }
    }

    /// The stored representation. Must match migration 010's CHECK.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::Admin => "admin",
            Self::Owner => "owner",
        }
    }

    /// Roles that may be handed to someone else.
    ///
    /// ⚠️ `Owner` is absent, and migration 010's invite CHECK refuses it too. An
    /// organisation has exactly one owner, set at creation and moved only by a
    /// deliberate transfer. Handing it out through an invitation — a link someone
    /// can forward — or through a role change would allow two owners, and "exactly
    /// one owner" is what the refusal to remove the last one relies on.
    pub const ASSIGNABLE: [OrgRole; 2] = [OrgRole::Member, OrgRole::Admin];
}

/// The minimum rank a route requires.
pub trait MinOrgRole {
    const MIN: OrgRole;
}

/// Any member of the organisation.
pub struct AtLeastOrgMember;
impl MinOrgRole for AtLeastOrgMember {
    const MIN: OrgRole = OrgRole::Member;
}

/// Enough to invite, remove and assign seats.
pub struct AtLeastOrgAdmin;
impl MinOrgRole for AtLeastOrgAdmin {
    const MIN: OrgRole = OrgRole::Admin;
}

/// The owner alone.
///
/// ⚠️ Seat *count* is owner-only while seat *assignment* is admin. The count is a
/// billing decision — it is what an invoice is computed from — and assignment is
/// day-to-day administration. An admin who could raise the count could raise the
/// bill.
pub struct OrgOwnerOnly;
impl MinOrgRole for OrgOwnerOnly {
    const MIN: OrgRole = OrgRole::Owner;
}

/// Proof that the caller holds at least `M::MIN` in the organisation in the path.
///
/// Constructing one is the authorisation check; a handler taking this argument
/// cannot run without it having passed.
pub struct OrgAccess<M: MinOrgRole> {
    /// The organisation from the request path.
    pub org_id: Uuid,
    /// The caller.
    pub user_id: Uuid,
    /// What they actually hold — at least `M::MIN`, possibly more.
    pub role: OrgRole,
    _marker: PhantomData<M>,
}

impl<M: MinOrgRole> OrgAccess<M> {
    /// Whether the caller outranks a given role.
    ///
    /// Used where one member acts on another: an admin must not be able to remove
    /// an owner, or to promote someone to their own rank and create a peer neither
    /// can remove.
    pub fn outranks(&self, other: OrgRole) -> bool {
        self.role > other
    }
}

#[async_trait]
impl<M: MinOrgRole> FromRequestParts<AppState> for OrgAccess<M> {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Claims are inserted by `require_user_session`, which every org route sits
        // behind. Their absence is a router wiring bug, not a client error — the
        // same class as B1 — so it must not read as 401.
        let claims = parts
            .extensions
            .get::<Claims>()
            .ok_or_else(|| {
                AppError::Internal(
                    "org route reached without an auth guard — check the router".into(),
                )
            })?
            .clone();

        let user_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;

        // A map rather than `Path<Uuid>`: several routes carry a second parameter
        // (`/members/:user_id`), and a single-typed Path would fail to extract on
        // those with an error resembling a bad request rather than a mismatch.
        let params =
            Path::<std::collections::HashMap<String, String>>::from_request_parts(parts, state)
                .await
                .map_err(|_| AppError::NotFound)?;

        let org_id = params
            .get("org_id")
            .and_then(|v| Uuid::parse_str(v).ok())
            .ok_or(AppError::NotFound)?;

        // ⚠️ 404 for a non-member, not 403, and the join excludes soft-deleted
        // organisations. A distinct "this org exists but is not yours" would let
        // anyone probe for organisation ids, and every vault route already answers
        // this way.
        let stored: Option<String> = sqlx::query_scalar(
            "SELECT m.role FROM organization_members m \
             JOIN organizations o ON o.id = m.org_id AND o.deleted_at IS NULL \
             WHERE m.org_id = $1 AND m.user_id = $2",
        )
        .bind(org_id)
        .bind(user_id)
        .fetch_optional(&state.db)
        .await?;

        let stored = stored.ok_or(AppError::NotFound)?;

        let role = OrgRole::parse(&stored).ok_or_else(|| {
            AppError::Internal(format!("unrecognised org role in the database: {stored:?}"))
        })?;

        // 403, not 404: they are a member, so the organisation's existence is not a
        // secret from them. Only the action is refused.
        if role < M::MIN {
            return Err(AppError::Forbidden);
        }

        Ok(Self {
            org_id,
            user_id,
            role,
            _marker: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_role_round_trips_and_an_unknown_one_is_refused() {
        for r in [OrgRole::Member, OrgRole::Admin, OrgRole::Owner] {
            assert_eq!(OrgRole::parse(r.as_str()), Some(r));
        }
        assert_eq!(OrgRole::parse("developer"), None, "that is a vault role");
        assert_eq!(OrgRole::parse("Owner"), None, "the column stores lowercase");
        assert_eq!(OrgRole::parse(""), None);
    }

    /// The ladder is the permission model, so its order is worth asserting rather
    /// than leaving to the `derive`.
    #[test]
    fn the_ladder_runs_member_admin_owner() {
        assert!(OrgRole::Member < OrgRole::Admin);
        assert!(OrgRole::Admin < OrgRole::Owner);
    }

    /// ⚠️ Owner must not be assignable, here or in migration 010's invite CHECK.
    #[test]
    fn owner_is_not_assignable() {
        assert!(!OrgRole::ASSIGNABLE.contains(&OrgRole::Owner));
        assert_eq!(OrgRole::ASSIGNABLE.len(), 2);
    }

    /// ⛔ The separation stated as a test: the two role ladders share no values
    /// beyond the words, so a vault role string cannot be read as an org role or
    /// the reverse. `developer` and `viewer` are vault-only; `member` is org-only.
    #[test]
    fn org_roles_and_vault_roles_do_not_interchange() {
        use crate::middleware::vault_role::Role as VaultRole;

        assert_eq!(OrgRole::parse("developer"), None);
        assert_eq!(OrgRole::parse("viewer"), None);
        assert_eq!(VaultRole::parse("member"), None);

        // `admin` and `owner` are spelled the same in both ladders, which is why
        // there is no `From` impl between them — a conversion that compiled would
        // make it possible to satisfy a vault check with an org role by accident.
        assert!(OrgRole::parse("admin").is_some());
        assert!(VaultRole::parse("admin").is_some());
    }
}
