# API changes

## 2026-11-09

### New: `GET /api/v1/audit`, activity across every vault you can read
The per-vault trail (`GET /vaults/:id/audit`) is unchanged. This adds one feed
over all of them, for dashboards.

**Auth.** Same guard as the per-vault route: a user session, or an API token
that is not scoped to a single vault (a `read` token is enough, it is a GET).
No credentials: 401. ⚠️ A token scoped to one vault gets **403**
`{"reason":"TOKEN_SCOPE"}`; the route spans vaults and such a token must not
read the others. It can still use `GET /vaults/:its_vault/audit`.

**Scope rule.** An event is returned only if, right now, you could read that
vault's audit at `GET /vaults/:id/audit`: a current membership at **viewer or
above** (any member) on a vault that is not deleted. The role requirement is
the same type (`AuditReader`) the per-vault handler uses, applied in SQL. A
revoked membership stops showing that vault's events immediately; vaults you
were never in never appear; events with no vault (e.g. logins) never appear.
Plan retention applies as on the per-vault route: your plan decides how far back
events are shown (`retention_days`, `null` = unlimited); nothing is deleted.
`hidden_by_retention` is not returned here.

**Query parameters** (all optional)

| Param | Meaning |
|---|---|
| `limit` | Page size, 1 to 200, default 50. Anything else: 422 `VALIDATION_ERROR`. |
| `before` | Opaque cursor from a previous `next_cursor`; returns events older than it. A value this server did not issue: 422. |
| `vault_id` | Only these vaults. **Comma-separated list in one parameter** (`?vault_id=a,b`), at most 100; repeating the parameter is not supported. Narrows, never widens: if any id is not a vault you can read (unknown, not a member, deleted, revoked) the answer is **404** `NOT_FOUND`, as for a non-member on the vault routes. A malformed id: 422. |

**Response 200**
```json
{
  "events": [
    {
      "id": "0b9f7a4e-6c1d-4c53-9d1e-2f6a9e4b8a10",
      "event_type": "vault_rekey",
      "user_id": "5d2c1c60-51d7-4b43-a4c3-0a1f7d3e9b21",
      "actor_email": "ada@example.com",
      "metadata": {
        "removed_user_id": "c8e1f4a2-77b0-4d0e-9f53-6a2b1c0d4e55",
        "removed_email": "grace@example.com"
      },
      "created_at": "2026-11-09T09:14:03.512044Z",
      "vault_id": "7a1e9c3b-2f84-4a6d-8b35-1d0c5e7f9a42",
      "vault_name": "payments-prod"
    },
    {
      "id": "e4a6d1b9-3c27-4f08-a5b1-9c8d7e6f5a30",
      "event_type": "pull",
      "user_id": "5d2c1c60-51d7-4b43-a4c3-0a1f7d3e9b21",
      "actor_email": "ada@example.com",
      "metadata": { "version": 4, "purpose": "rekey" },
      "created_at": "2026-11-09T09:13:58.100200Z",
      "vault_id": "7a1e9c3b-2f84-4a6d-8b35-1d0c5e7f9a42",
      "vault_name": "payments-prod"
    }
  ],
  "limit": 50,
  "next_cursor": "MTc2MjY4MDg0MzUxMjA0NC5iNzVkMDhm...",
  "retention_days": 7
}
```
Each event is exactly the per-vault event (`id`, `event_type`, `user_id`,
`actor_email`, `metadata` including `removed_email` and `purpose`, `created_at`)
plus `vault_id` and `vault_name`. No `ip_hash` or `user_agent_hash`. Newest
first, ordered by `(created_at, id)` descending, so events with equal timestamps
have a stable order.

**Pagination.** Keyset, not offset. Request the next page by passing the
previous `next_cursor` as `before`, with the same `limit` and `vault_id`.
`next_cursor` is `null` on the last page (never a trailing empty page). Treat the
cursor as opaque. Events written after you started do not shift older pages.

```
GET /api/v1/audit?limit=2
GET /api/v1/audit?limit=2&before=<next_cursor>
GET /api/v1/audit?vault_id=7a1e9c3b-2f84-4a6d-8b35-1d0c5e7f9a42,3b9d...&limit=100
```

Migration `014_audit_feed_index.sql` adds an index (additive, runs at server
startup).

## 2026-11-08

### 403 responses carry a `reason` (RM-56)
Status stays 403 and `code` stays `"FORBIDDEN"`; new optional field `reason`:

| `reason` | Meaning | Extra fields |
|---|---|---|
| `ROLE_TOO_LOW` | Caller is a member but below the role the route needs (vault or org). | `required_role`: `viewer`, `developer`, `admin`, `owner` (org: `member`, `admin`, `owner`) |
| `TOKEN_SCOPE` | API token is scoped to a different vault (or to one vault, on a non-vault route). | |
| `TOKEN_READ_ONLY` | Read-only API token attempted a write. | |
| `PLAN_LIMIT` | A plan quota was reached (existing). | |

No `reason` means a refusal with no single fixable cause: an API token on a
session-only endpoint, and "outranks" checks (removing/changing someone with an
equal or higher role). Non-members still receive 404, never 403.

### Org-limit status change: 409 -> 403 (RM-58)
`POST /orgs` over the plan's owned-organisation limit now answers
**403** `{"code":"FORBIDDEN","reason":"PLAN_LIMIT"}` instead of 409. A taken slug
is still 409, as is the seat-capacity check ("all N seats are assigned").

### `GET /vaults/:id/audit`: `removed_email` (RM-57)
Events whose metadata has `removed_user_id` (`vault_rekey`) now include
`metadata.removed_email`, resolved at read time (`null` if the account no longer
exists). Stored rows are unchanged.

### `GET /vaults/:id/versions/:n/blob?purpose=rekey` (RM-57)
Optional `purpose`. With `rekey` and a caller of role admin or above, the `pull`
audit event metadata is `{"version": n, "purpose": "rekey"}`. Any other value or
a lower role is ignored: the pull is recorded as before and the blob is served.
