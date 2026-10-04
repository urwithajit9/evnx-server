// src/middleware/mod.rs

pub mod auth;

/// Who a request came from, as keyed digests — never a raw address.
pub mod client_ip;
pub mod org_role;
pub mod security_headers;

/// Vault-level authorisation — the `Role` ladder and the `VaultAccess` extractor.
pub mod vault_role;
