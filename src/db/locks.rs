// src/db/locks.rs

//! Row locks that order membership changes against pushes and re-keys (C4).
//!
//! ## The lock order
//!
//! **vault row first, then membership row.** Every transaction that takes more
//! than one of these takes them in that order, so none can wait on another in a
//! cycle.
//!
//! | operation                    | vault row     | membership row          |
//! |------------------------------|---------------|-------------------------|
//! | push (`push_version`)        | `FOR KEY SHARE` | caller's row, `FOR SHARE` |
//! | remove / change a role       | `FOR KEY SHARE` | target's row, by the `DELETE` / `UPDATE` itself |
//! | re-key (`rekey`)             | `FOR UPDATE`  | every member's row, by its writes |
//!
//! Why these modes:
//!
//! * **Push vs. revocation.** A push holds its own membership row `FOR SHARE`
//!   until it commits. A `DELETE` or role `UPDATE` of that row conflicts with it,
//!   so a revocation waits for an in-flight push, and a push that starts after
//!   the revocation committed re-reads the row and finds it gone or lowered. A
//!   revoked user can therefore never land a version *after* their revocation.
//! * **Push vs. push.** `FOR KEY SHARE` on the vault conflicts only with `FOR
//!   UPDATE`, so pushes do not serialise on it. Two concurrent pushes to one vault
//!   still race on `UNIQUE (vault_id, version_num)`; the loser is a 409.
//! * **Push vs. re-key.** The re-key's `FOR UPDATE` on the vault conflicts with
//!   every push's `FOR KEY SHARE`: it waits for pushes in flight, and pushes that
//!   arrive during it wait for it. Its version set, read after the lock, is
//!   therefore the set that will be there when it commits.
//!
//! ⚠️ Never take the vault lock *after* a membership lock in the same
//! transaction. Never do network IO (storage) while holding either.
//!
//! These are plain queries rather than `query!` so they need no offline cache
//! entry; they select nothing but a role string.

use sqlx::PgConnection;
use uuid::Uuid;

/// Lock the vault row so a re-key cannot run while the caller's transaction is
/// open. Many holders at once. `false` if the vault does not exist or is deleted.
pub async fn lock_vault_shared(
    conn: &mut PgConnection,
    vault_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let row: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM vaults WHERE id = $1 AND deleted_at IS NULL FOR KEY SHARE",
    )
    .bind(vault_id)
    .fetch_optional(conn)
    .await?;
    Ok(row.is_some())
}

/// Lock the vault row exclusively: waits for every in-flight push, and holds new
/// ones off until commit. `false` if the vault does not exist or is deleted.
pub async fn lock_vault_exclusive(
    conn: &mut PgConnection,
    vault_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let row: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM vaults WHERE id = $1 AND deleted_at IS NULL FOR UPDATE")
            .bind(vault_id)
            .fetch_optional(conn)
            .await?;
    Ok(row.is_some())
}

/// Lock one membership row `FOR SHARE` and return its role, or `None` if the
/// user is not (or no longer) a member. Take the vault lock first.
pub async fn lock_member_shared(
    conn: &mut PgConnection,
    vault_id: Uuid,
    user_id: Uuid,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT role FROM vault_members WHERE vault_id = $1 AND user_id = $2 FOR SHARE",
    )
    .bind(vault_id)
    .bind(user_id)
    .fetch_optional(conn)
    .await
}
