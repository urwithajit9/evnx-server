-- migrations/006_audit_is_append_only.sql
--
-- Make `audit_events` append-only in the database rather than by convention.
--
-- ─── What was actually true before this ──────────────────────────────────────
--
-- The schema comment in CLAUDE.md read `audit_events -- … ← append-only`, and it
-- was not. Verified 2026-09-19: no trigger, no row-level security, nothing that
-- refused an UPDATE or a DELETE. The application never issued one, which is a
-- different claim — and a weaker one, because an audit trail's value is exactly
-- that it cannot be edited by whoever is being audited.
--
-- ⚠️ An audit log that the application merely declines to modify is not an audit
-- log. Anyone with the database credentials — which is anyone who has taken the
-- server — can rewrite history and leave no trace of having done so. The point
-- of the table is to survive that.

CREATE OR REPLACE FUNCTION audit_events_reject_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    -- ⚠️ ONE UPDATE IS PERMITTED, and refusing it was the first version's bug.
    --
    -- Both foreign keys are ON DELETE SET NULL, so deleting a user or a vault
    -- makes Postgres itself UPDATE this table to null the reference. A blanket
    -- refusal therefore does not protect the audit log — it makes deleting a
    -- user impossible, which nobody asked for and which would surface as a
    -- baffling constraint error far from its cause.
    --
    -- So: an update that only nulls `vault_id` or `user_id` and changes nothing
    -- else is allowed. The event itself — what happened, when, with what
    -- metadata — is what the log is for, and that stays untouchable.
    --
    -- The residual risk is real and worth naming: someone who can delete a user
    -- can disassociate that user's events from them. They cannot alter or erase
    -- what the events say, and deleting a user is already a privileged act.
    IF TG_OP = 'UPDATE'
       AND NEW.event_type      IS NOT DISTINCT FROM OLD.event_type
       AND NEW.ip_hash         IS NOT DISTINCT FROM OLD.ip_hash
       AND NEW.user_agent_hash IS NOT DISTINCT FROM OLD.user_agent_hash
       AND NEW.metadata        IS NOT DISTINCT FROM OLD.metadata
       AND NEW.created_at      IS NOT DISTINCT FROM OLD.created_at
       AND (NEW.vault_id IS NULL OR NEW.vault_id IS NOT DISTINCT FROM OLD.vault_id)
       AND (NEW.user_id  IS NULL OR NEW.user_id  IS NOT DISTINCT FROM OLD.user_id)
    THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION
        'audit_events is append-only: % is not permitted', TG_OP
        USING HINT = 'Audit history is evidence. Correct it by appending, never by editing.',
              ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER audit_events_no_update
    BEFORE UPDATE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_reject_mutation();

CREATE TRIGGER audit_events_no_delete
    BEFORE DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_reject_mutation();

-- ⚠️ A superuser, or the table's owner, can still DROP these triggers — so this
-- raises the cost of tampering rather than making it impossible. Genuinely
-- tamper-evident logging means shipping events off the box to somewhere the
-- application's credentials cannot reach, which is a separate piece of work.
-- What this does buy: no ordinary code path, no stray migration and no careless
-- `DELETE FROM` can quietly rewrite the record.
--
-- ⚠️ CONSEQUENCE FOR TESTS AND DEVELOPMENT: audit rows can no longer be deleted,
-- so they accumulate. Deleting the *user* still works — the FK nulls out under
-- the exemption above — but the event rows stay. Point DATABASE_URL at a scratch
-- database if that matters.
