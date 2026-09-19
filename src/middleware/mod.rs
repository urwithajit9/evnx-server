// src/middleware/mod.rs

pub mod auth;
pub mod security_headers;

/// Vault-level authorisation — the `Role` ladder and the `VaultAccess` extractor.
pub mod vault_role;
