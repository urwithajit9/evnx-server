// src/services/cache.rs

use redis::{aio::ConnectionManager, AsyncCommands};
use serde::{de::DeserializeOwned, Serialize};

/// Wrapper around the Valkey operations used by evnx-server.
///
/// Only seven commands are used — SETEX, GET, DEL, INCR, EXPIRE, EXISTS, TTL —
/// all core primitives with identical semantics in Redis and Valkey. No Lua, no
/// streams, no modules, so the backing store is interchangeable.
///
/// Key naming convention:
///   srp:{session_id}            → SRP server state (5-min TTL)
///   rate:srp_init:{email_hash}  → SRP init counter (30 per 15 min; guessing
///                                  is bounded by srp_lockout, 5 per 15 min)
///   rate:resend_verify:{email_hash} → verification resend counter (3 per hour)
///
/// ⚠️ Rate limiting is keyed by **email hash, not by IP**, and the two are not
/// interchangeable: an email key throttles attacks against one account, an IP
/// key throttles one attacker across many. Only the first exists.
///
/// Client addresses ARE available now (`middleware::client_ip`, 2026-09-30) and
/// audit events carry them — but an IP-keyed limit is still deliberately absent.
/// It would be keyed on a value that is only trustworthy when
/// `TRUST_PROXY_HEADER` is on *and* the proxy sanitises the header, and a limit
/// that silently stops limiting on a misconfigured deployment is worse than one
/// that never claimed to. If it is added, the trust decision has to be part of it
/// rather than assumed.
///
/// An earlier revision of this comment listed `rate:auth:{ip_hash}` and
/// `rate:register:{ip_hash}`. Neither key has ever existed.
///   totp_lockout:{user_id}      → failed TOTP counter (15-min TTL)
///   srp_lockout:{user_id}       → failed SRP proof counter (15-min TTL)
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
            .map_err(CacheError::Valkey)
    }

    /// Get and deserialize a JSON value. Returns None if key doesn't exist.
    pub async fn get_json<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, CacheError> {
        let mut conn = self.0.clone();
        let raw: Option<String> = conn.get(key).await.map_err(CacheError::Valkey)?;
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
        conn.del::<_, ()>(key).await.map_err(CacheError::Valkey)
    }

    /// Increment a counter and set TTL on first increment.
    /// Returns the new count.
    pub async fn incr_with_ttl(&self, key: &str, ttl_seconds: u64) -> Result<u64, CacheError> {
        let mut conn = self.0.clone();
        // INCR atomically increments (or creates at 0 then increments)
        let count: u64 = conn.incr(key, 1).await.map_err(CacheError::Valkey)?;
        if count == 1 {
            // First increment — set the expiry
            conn.expire::<_, ()>(key, ttl_seconds as i64)
                .await
                .map_err(CacheError::Valkey)?;
        }
        Ok(count)
    }

    /// Count one attempt against a limit of `max_attempts` per `window_seconds`.
    ///
    /// ⚠️ **Over the limit, it says how long is really left** (I-304). Every
    /// caller used to answer with the whole window — "900 seconds" — however
    /// much of it remained; the live review measured 648-714 s actually left.
    /// The TTL is read only on a refusal, so an allowed request costs nothing
    /// extra.
    ///
    /// ⚠️ **A counter with no expiry is given one here.** [`Self::incr_with_ttl`]
    /// creates the key and sets its expiry in two commands; a server stopped
    /// between them leaves a counter that never expires, which locks the address
    /// out for good. TTL `-1` is exactly that state, so the refusal repairs it.
    pub async fn rate_limit(
        &self,
        key: &str,
        max_attempts: u64,
        window_seconds: u64,
    ) -> Result<RateLimit, CacheError> {
        let count = self.incr_with_ttl(key, window_seconds).await?;
        if count <= max_attempts {
            return Ok(RateLimit::Allowed);
        }

        let mut conn = self.0.clone();
        let ttl: i64 = conn.ttl(key).await.map_err(CacheError::Valkey)?;
        let retry_after_seconds = match ttl {
            t if t > 0 => t as u64,
            // -1: the key exists with no expiry — the gap above.
            -1 => {
                conn.expire::<_, ()>(key, window_seconds as i64)
                    .await
                    .map_err(CacheError::Valkey)?;
                window_seconds
            }
            // -2 (expired since the INCR) or 0: the window is over now.
            _ => 1,
        };
        Ok(RateLimit::Exceeded {
            retry_after_seconds,
        })
    }

    /// Check if a key exists (used for JWT blocklist).
    pub async fn exists(&self, key: &str) -> Result<bool, CacheError> {
        let mut conn = self.0.clone();
        let n: u64 = conn.exists(key).await.map_err(CacheError::Valkey)?;
        Ok(n > 0)
    }

    /// Delete a key and report whether it was there.
    ///
    /// ⚠️ One round trip, deliberately. `exists` followed by `del` lets two
    /// concurrent requests both observe the same single-use flag before either
    /// spends it, which for a flag authorising an irreversible operation means
    /// it authorises two.
    pub async fn take_flag(&self, key: &str) -> Result<bool, CacheError> {
        let mut conn = self.0.clone();
        let removed: u64 = conn.del(key).await.map_err(CacheError::Valkey)?;
        Ok(removed > 0)
    }

    /// Set a key with no value (just existence matters — blocklist pattern).
    pub async fn set_flag(&self, key: &str, ttl_seconds: u64) -> Result<(), CacheError> {
        let mut conn = self.0.clone();
        conn.set_ex::<_, _, ()>(key, "1", ttl_seconds)
            .await
            .map_err(CacheError::Valkey)
    }
}

/// What [`CacheService::rate_limit`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimit {
    Allowed,
    /// Refused; the window has this many seconds left.
    Exceeded {
        retry_after_seconds: u64,
    },
}

impl RateLimit {
    /// `Err(RateLimited)` with the real wait when refused, so a handler reads
    /// `state.cache.rate_limit(..).await?.or_refuse()?`.
    pub fn or_refuse(self) -> Result<(), crate::errors::AppError> {
        match self {
            RateLimit::Allowed => Ok(()),
            RateLimit::Exceeded {
                retry_after_seconds,
            } => Err(crate::errors::AppError::RateLimited {
                retry_after_seconds,
            }),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    /// Wraps `redis::RedisError` — the crate name, not the server.
    #[error("Valkey error: {0}")]
    Valkey(#[from] redis::RedisError),
    #[error("Serialization error: {0}")]
    Serialization(String),
}

impl From<CacheError> for crate::errors::AppError {
    fn from(e: CacheError) -> Self {
        tracing::error!(error = %e, "Cache error");
        crate::errors::AppError::Internal(e.to_string())
    }
}
