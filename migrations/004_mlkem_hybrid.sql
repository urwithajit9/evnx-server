-- migrations/004_mlkem_hybrid.sql
--
-- F1: hybrid X25519 + ML-KEM-768 vault-key wrapping.
--
-- Two new columns and one constraint. The constraint is the important part.

-- ─── users: the ML-KEM public key ────────────────────────────────────────────
--
-- Nullable, exactly like x25519_public_key in migration 002, and for the same
-- reason: existing rows cannot have one. The key is DERIVED from the Ed25519
-- seed the user already has, so it appears the next time they sign in with a
-- client that knows how to derive it. Nobody is prompted, nothing is re-sealed.
--
-- 1184 bytes base64 -> exactly 1580 characters.
ALTER TABLE users ADD COLUMN mlkem_public_key TEXT;

-- ─── vault_members: the ML-KEM ciphertext ────────────────────────────────────
--
-- Nullable for the SAME reason eph_pub_key is: the vault creator's own copy is
-- wrapped under an HKDF subkey of their master key — symmetric, no ECDH, no KEM,
-- and already post-quantum safe. Requiring a ciphertext here would force the
-- creator through a key-agreement path they do not need.
--
-- 1088 bytes base64 -> exactly 1452 characters.
ALTER TABLE vault_members ADD COLUMN mlkem_ciphertext TEXT;

-- ─── The invariant that makes the hybrid non-optional ────────────────────────
--
-- A shared row has BOTH an ephemeral X25519 key and an ML-KEM ciphertext. The
-- creator's own row has NEITHER. There is no legitimate row with one and not
-- the other — such a row is either a client bug or a deliberate downgrade,
-- someone stripping the post-quantum half to leave a wrap that Shor can open.
--
-- Stating it as a CHECK makes it a database invariant rather than client
-- discipline. A future handler that forgets the rule fails loudly at the INSERT
-- instead of quietly storing a weakened key.
--
-- ⚠️ NOT VALID, deliberately.
--
-- Postgres enforces a NOT VALID check on every INSERT and UPDATE from this
-- moment on; what it skips is the full-table scan over rows that already exist.
-- That is exactly the behaviour wanted here. Every pre-F1 share carries an
-- ephemeral and no ML-KEM ciphertext, so a validating constraint would abort the
-- migration — and the only ways to get past that are to delete rows or to weaken
-- the rule, neither of which a migration should decide on an operator's behalf.
--
-- The first attempt at this migration DID abort, on 140 rows in the development
-- database. They turned out to be integration-test fixtures — every one carried
-- `eph_pub_key = 'YmFy'`, base64 for "bar" — but that was only discoverable by
-- looking. A migration that had "cleaned them up" automatically would have been
-- right in development and catastrophic anywhere those rows were real: a row
-- with role='owner' and an ephemeral is somebody's own vault.
--
-- To see what a given deployment is carrying:
--
--     SELECT v.name, v.environment, m.role, u.email, m.granted_at
--     FROM vault_members m
--     JOIN vaults v ON v.id = m.vault_id
--     JOIN users  u ON u.id = m.user_id
--     WHERE m.eph_pub_key IS NOT NULL AND m.mlkem_ciphertext IS NULL;
--
-- Those grants are already dead: a 0.2.0 client requires an ML-KEM ciphertext to
-- unwrap, so the member cannot decrypt regardless. Re-share the vault to restore
-- access, delete the rows once nothing needs them, then:
--
--     ALTER TABLE vault_members VALIDATE CONSTRAINT vault_members_wrap_is_whole;
--
-- which takes no exclusive lock and checks the remaining rows.
ALTER TABLE vault_members
    ADD CONSTRAINT vault_members_wrap_is_whole
    CHECK (
        (eph_pub_key IS NULL     AND mlkem_ciphertext IS NULL)
     OR (eph_pub_key IS NOT NULL AND mlkem_ciphertext IS NOT NULL)
    ) NOT VALID;

-- ⚠️ NOT adding NOT NULL to users.mlkem_public_key.
--
-- It would refuse every existing row, and there is no value to backfill them
-- with: the server cannot derive the key, only the client holding the master
-- password can. Enforcement lives where the key is used — sharing a vault with
-- a user who has no ML-KEM key on file is refused by the handler, which is the
-- moment it actually matters.
