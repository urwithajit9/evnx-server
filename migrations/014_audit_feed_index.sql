-- migrations/014_audit_feed_index.sql
--
-- Index for the cross-vault audit feed (`GET /api/v1/audit`).
--
-- `idx_audit_events_vault` (001) covers `(vault_id, created_at DESC)`. The feed
-- pages by keyset on `(created_at, id)`, and `created_at` is not unique (two
-- events in one transaction share a `NOW()`), so the page boundary has to
-- break ties on `id`. With the tiebreaker as a trailing index column the
-- row comparison `(created_at, id) < ($cursor_ts, $cursor_id)` and the
-- `ORDER BY created_at DESC, id DESC` are both answered by an index range scan
-- per vault, and a deep page costs what the first one does.
--
-- Additive: nothing is dropped, and `idx_audit_events_vault` stays for the
-- per-vault view and anything else already using it. Cheap to drop later if it
-- proves redundant. `audit_events` is append-only (006), so the index never has
-- to follow an UPDATE.
--
-- ⚠️ Not CONCURRENTLY: sqlx runs each migration in a transaction and CREATE
-- INDEX CONCURRENTLY cannot. The build takes a SHARE lock, which blocks audit
-- INSERTs for its duration. Audit writes are spawned and logged-not-propagated,
-- so a long build costs rows, not requests. Run this deploy off-peak if the
-- table is large.

CREATE INDEX IF NOT EXISTS idx_audit_events_vault_page
    ON audit_events (vault_id, created_at DESC, id DESC);
