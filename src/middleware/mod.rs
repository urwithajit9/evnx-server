// src/middleware/mod.rs

pub mod auth;

/// Who a request came from, as keyed digests — never a raw address.
pub mod client_ip;

/// Every error response carries `{ "error", "code" }` — the framework's too.
pub mod json_errors;
pub mod org_role;
pub mod security_headers;

/// Vault-level authorisation — the `Role` ladder and the `VaultAccess` extractor.
pub mod vault_role;
