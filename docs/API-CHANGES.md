# API changes

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
