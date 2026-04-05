// src/services/cache.rs

use redis::{aio::ConnectionManager, AsyncCommands};
use serde::{de::DeserializeOwned, Serialize};

/// Wrapper around Redis operations used by evnx-server.
///
/// Key naming convention:
///   srp:{session_id}            → SRP server state (5-min TTL)
///   rate:auth:{ip_hash}         → auth attempt counter (15-min window)
///   rate:register:{ip_hash}     → registration counter (24h window)
///   totp_lockout:{user_id}      → failed TOTP counter (15-min TTL)
///   jwt_blocklist:{session_id}  → revoked JWT sessions
#[derive(Clone)]
pub struct CacheService(pub ConnectionManager);

impl CacheService {
    pub fn new(conn: ConnectionManager) -> Self {
        Self(conn)
    }

    /// Set a JSON-serializable value with TTL (seconds).
    pub async fn set_json<T: Serialize>(
        &self,
        key: &str,
        value: &T,
        ttl_seconds: u64,
    ) -> Result<(), CacheError> {
        let mut conn = self.0.clone();
        let serialized =
            serde_json::to_string(value).map_err(|e| CacheError::Serialization(e.to_string()))?;
        conn.set_ex::<_, _, ()>(key, serialized, ttl_seconds)
            .await
            .map_err(CacheError::Redis)
    }

    /// Get and deserialize a JSON value. Returns None if key doesn't exist.
    pub async fn get_json<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, CacheError> {
        let mut conn = self.0.clone();
        let raw: Option<String> = conn.get(key).await.map_err(CacheError::Redis)?;
        match raw {
            None => Ok(None),
            Some(s) => serde_json::from_str(&s)
                .map(Some)
                .map_err(|e| CacheError::Serialization(e.to_string())),
        }
    }

    /// Delete a key.
    pub async fn del(&self, key: &str) -> Result<(), CacheError> {
        let mut conn = self.0.clone();
        conn.del::<_, ()>(key).await.map_err(CacheError::Redis)
    }

    /// Increment a counter and set TTL on first increment.
    /// Returns the new count.
    pub async fn incr_with_ttl(&self, key: &str, ttl_seconds: u64) -> Result<u64, CacheError> {
        let mut conn = self.0.clone();
        // INCR atomically increments (or creates at 0 then increments)
        let count: u64 = conn.incr(key, 1).await.map_err(CacheError::Redis)?;
        if count == 1 {
            // First increment — set the expiry
            conn.expire::<_, ()>(key, ttl_seconds as i64)
                .await
                .map_err(CacheError::Redis)?;
        }
        Ok(count)
    }

    /// Check rate limit. Returns Ok(true) if under limit, Ok(false) if exceeded.
    pub async fn check_rate_limit(
        &self,
        key: &str,
        max_attempts: u64,
        window_seconds: u64,
    ) -> Result<bool, CacheError> {
        let count = self.incr_with_ttl(key, window_seconds).await?;
        Ok(count <= max_attempts)
    }

    /// Check if a key exists (used for JWT blocklist).
    pub async fn exists(&self, key: &str) -> Result<bool, CacheError> {
        let mut conn = self.0.clone();
        let n: u64 = conn.exists(key).await.map_err(CacheError::Redis)?;
        Ok(n > 0)
    }

    /// Set a key with no value (just existence matters — blocklist pattern).
    pub async fn set_flag(&self, key: &str, ttl_seconds: u64) -> Result<(), CacheError> {
        let mut conn = self.0.clone();
        conn.set_ex::<_, _, ()>(key, "1", ttl_seconds)
            .await
            .map_err(CacheError::Redis)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("Serialization error: {0}")]
    Serialization(String),
}

impl From<CacheError> for crate::errors::AppError {
    fn from(e: CacheError) -> Self {
        tracing::error!(error = %e, "Cache error");
        crate::errors::AppError::Internal(e.to_string())
    }
}
