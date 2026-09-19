-- migrations/005_role_is_a_closed_set.sql
--
-- Phase 3 step 2: make an invalid vault role unstorable.
--
-- `vault_members.role` is free-form TEXT. It accepts 'admni', 'Admin', 'god' and
-- '' without complaint, and every one of those silently fails the role checks in
-- the handlers — which read as "this user has no permission" rather than "this
-- row is corrupt". A typo in a future handler becomes a lockout nobody can
-- diagnose from the error.
--
-- ─── Why a CHECK and not an ENUM ─────────────────────────────────────────────
--
-- A Postgres ENUM would also make the value unstorable, and would let sqlx hand
-- Rust a real enum directly. It was rejected for one reason: `ALTER TYPE ... ADD
-- VALUE` cannot be undone. A value added to an enum can never be removed, so a
-- role added speculatively is permanent. A CHECK is edited by an ordinary
-- migration, in either direction.
--
-- The guarantee is the same either way — the database refuses the row — and the
-- Rust side parses into a real `Role` enum at the boundary regardless, so the
-- type safety is not lost by choosing the reversible option.

-- Normalise anything already stored before constraining. In practice this
-- touches nothing: every row is written by a handler that uses a literal.
--
-- ⚠️ THE `WHERE` CLAUSE IS LOad-BEARING, and the first version of this migration
-- did not have it. A blanket `UPDATE vault_members SET role = lower(trim(role))`
-- aborted against the development database with:
--
--     new row for relation "vault_members" violates check constraint
--     "vault_members_wrap_is_whole"
--
-- **A `NOT VALID` constraint exempts existing rows only until something updates
-- them.** Migration 004 added `vault_members_wrap_is_whole` as NOT VALID
-- precisely so pre-F1 shares could stay; but rewriting such a row — even setting
-- a column to the value it already held — makes Postgres re-check it, and it
-- fails. Development still holds 140 of those rows (test fixtures); production
-- had none and the constraint was validated there on 2026-09-18.
--
-- The general rule this exposes: **any UPDATE touching a row exempted by a
-- NOT VALID constraint will fail.** That applies to handlers too, not just
-- migrations — `add_member`'s ON CONFLICT DO UPDATE would fail on such a row.
-- Restricting the update to rows that actually need it keeps that from being
-- this migration's problem.
UPDATE vault_members
   SET role = lower(trim(role))
 WHERE role <> lower(trim(role));

ALTER TABLE vault_members
    ADD CONSTRAINT vault_members_role_is_known
    CHECK (role IN ('owner', 'admin', 'developer', 'viewer'));

-- ⚠️ VALIDATED, not NOT VALID — unlike migration 004.
--
-- 004 could not scan existing rows because a pre-F1 share would legitimately
-- violate it. Here there is no such case: every role in the table was written by
-- a handler from a literal in that same list, so a violation would be corruption
-- rather than history. If this migration aborts, something wrote a role no code
-- path produces, and that is worth stopping for.
