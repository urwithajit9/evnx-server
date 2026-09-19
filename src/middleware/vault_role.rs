// src/middleware/vault_role.rs

//! Vault-level authorisation: one place that answers "may this user do X here?"
//!
//! ## Why this exists
//!
//! Before Phase 3 the answer was six separate `find_member_role` calls inlined in
//! handlers, each re-deriving the rule with a literal array:
//!
//! ```text
//! if !["owner", "admin", "developer"].contains(&role.as_str()) { ... }
//! ```
//!
//! Nothing was *wrong* — every route that needed a check had one. The problem is
//! that a rule re-derived in six places is a rule the seventh handler forgets.
//! That is exactly what produced B1, where a handler taking `Extension<Claims>`
//! with no guard behind it returned 500 on every request, and it is why API-token
//! scope was deliberately centralised in `require_verified` rather than left to
//! each handler. Vault roles were the last thing still doing it the old way.
//!
//! ## Rank, not set membership
//!
//! [`Role`] is **ordered**. A requirement is stated as a minimum — "at least
//! developer" — rather than as a list of roles that happen to qualify today.
//!
//! The difference matters when a role is added. A list has to be revisited at
//! every call site, and the one that gets missed fails *open* or *closed* with no
//! pattern to it. A ladder places the new rung once.
//!
//! ⚠️ This is also what makes organisations cheap to add later. An org-derived
//! role is a second source of truth for the same question; with one resolver it
//! is one extra branch here, and with six inlined checks it would be six chances
//! to miss one. See `phase_3/PHASE3-TEAM-RBAC-PLAN.md` §5b.
//!
//! ## Usage
//!
//! The requirement goes in the handler's **signature**, so it cannot be skipped
//! and is visible without reading the body:
//!
//! ```text
//! pub async fn push_version(
//!     State(state): State<AppState>,
//!     access: VaultAccess<AtLeastDeveloper>,
//!     ...
//! ) -> Result<..., AppError> {
//!     // access.vault_id and access.role are already resolved and checked.
//! }
//! ```

use std::marker::PhantomData;

use axum::{
    async_trait,
    extract::{FromRequestParts, Path},
    http::request::Parts,
};
use uuid::Uuid;

use crate::{db::vaults, errors::AppError, services::jwt::Claims, state::AppState};

/// A vault role, ordered from least to most privileged.
///
/// The derived `Ord` **is** the permission model — `Viewer < Developer < Admin <
/// Owner` — so the declaration order below is load-bearing. Reordering these
/// variants silently changes who can do what.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    /// Pull and read history. Cannot push.
    Viewer,
    /// Pull and push.
    Developer,
    /// Share, revoke, re-key, manage members.
    Admin,
    /// Everything, plus deleting the vault. Exactly one per vault.
    Owner,
}

impl Role {
    /// Parse the stored value.
    ///
    /// Migration 005 makes an unknown role unstorable, so this failing means the
    /// database was changed outside the application or a new role was added to
    /// the CHECK without being added here. Both are worth a 500 rather than a
    /// guess — silently treating an unrecognised role as `Viewer` would be a
    /// quiet privilege *change*, in whichever direction happened to be wrong.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "viewer" => Some(Self::Viewer),
            "developer" => Some(Self::Developer),
            "admin" => Some(Self::Admin),
            "owner" => Some(Self::Owner),
            _ => None,
        }
    }

    /// The stored representation. Must match migration 005's CHECK.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Developer => "developer",
            Self::Admin => "admin",
            Self::Owner => "owner",
        }
    }

    /// Roles that may be *assigned* to someone else.
    ///
    /// `Owner` is absent on purpose: it is set once, by vault creation. Handing
    /// it out through `add_member` would allow two owners, and "exactly one
    /// owner" is what `remove_member` relies on to refuse removing the last one.
    pub const ASSIGNABLE: [Role; 3] = [Role::Viewer, Role::Developer, Role::Admin];
}

/// The minimum rank a route requires. Implemented by the marker types below.
pub trait MinRole {
    const MIN: Role;
}

/// Any member. Enough to read, and to see who else has access.
pub struct AtLeastViewer;
impl MinRole for AtLeastViewer {
    const MIN: Role = Role::Viewer;
}

/// Enough to push a new version.
pub struct AtLeastDeveloper;
impl MinRole for AtLeastDeveloper {
    const MIN: Role = Role::Developer;
}

/// Enough to share, revoke and re-key.
///
/// ⚠️ Re-keying is `Admin`, decided 2026-09-19. It is a destructive-feeling
/// operation, but gating it to `Owner` alone would mean a team whose owner is on
/// holiday cannot revoke a departing colleague — and a revocation that has to
/// wait is the failure mode this phase exists to remove.
pub struct AtLeastAdmin;
impl MinRole for AtLeastAdmin {
    const MIN: Role = Role::Admin;
}

/// The owner alone. Deleting a vault, and removing a member.
pub struct OwnerOnly;
impl MinRole for OwnerOnly {
    const MIN: Role = Role::Owner;
}

/// Proof that the caller holds at least `M::MIN` on the vault in the path.
///
/// Constructing one is the authorisation check; a handler taking this argument
/// cannot run without it having passed.
pub struct VaultAccess<M: MinRole> {
    /// The vault from the request path.
    pub vault_id: Uuid,
    /// The caller.
    pub user_id: Uuid,
    /// What they actually hold — at least `M::MIN`, possibly more. Handlers that
    /// need a finer distinction than the route's minimum can read it.
    pub role: Role,
    _marker: PhantomData<M>,
}

impl<M: MinRole> VaultAccess<M> {
    /// Whether the caller outranks a given role. Used where one member acts on
    /// another — an admin must not be able to remove an owner.
    pub fn outranks(&self, other: Role) -> bool {
        self.role > other
    }
}

// `#[async_trait]` rather than a native `async fn`: axum-core 0.4 still declares
// `FromRequestParts` with the macro, so an inherent async fn fails to match its
// lifetimes. Taken from axum's own re-export, which costs no new dependency.
#[async_trait]
impl<M: MinRole> FromRequestParts<AppState> for VaultAccess<M> {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Claims are inserted by `require_verified`, which every vault route sits
        // behind. Their absence is a router wiring bug, not a client error — the
        // same class as B1 — so it must not read as 401.
        let claims = parts
            .extensions
            .get::<Claims>()
            .ok_or_else(|| {
                AppError::Internal(
                    "vault route reached without an auth guard — check the router".into(),
                )
            })?
            .clone();

        let user_id = claims.user_id().map_err(|_| AppError::Unauthorized)?;

        // A map rather than `Path<Uuid>`: several routes carry a second parameter
        // (`/versions/:n/blob`), and a single-typed Path would fail to extract on
        // those with an error that looks like a bad request rather than a
        // mismatch.
        let params =
            Path::<std::collections::HashMap<String, String>>::from_request_parts(parts, state)
                .await
                .map_err(|_| AppError::NotFound)?;

        let vault_id = params
            .get("vault_id")
            .and_then(|v| Uuid::parse_str(v).ok())
            .ok_or(AppError::NotFound)?;

        // ⚠️ 404 for a non-member, not 403. A distinct "this vault exists but is
        // not yours" would let anyone probe for vault ids, and every other vault
        // route already answers this way.
        let stored = vaults::find_member_role(&state.db, vault_id, user_id)
            .await?
            .ok_or(AppError::NotFound)?;

        let role = Role::parse(&stored).ok_or_else(|| {
            AppError::Internal(format!(
                "unrecognised vault role in the database: {stored:?}"
            ))
        })?;

        // 403, not 404: they are a member, so the vault's existence is not a
        // secret from them. Only the action is refused.
        if role < M::MIN {
            return Err(AppError::Forbidden);
        }

        Ok(Self {
            vault_id,
            user_id,
            role,
            _marker: PhantomData,
        })
    }
}
