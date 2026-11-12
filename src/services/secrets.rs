// src/services/secrets.rs

//! Server-held secrets at rest.
//!
//! One configured key, `SERVER_DATA_KEY` (32 bytes, base64), is the root. Each
//! use derives its own purpose key from it with HKDF-SHA256, so a value sealed
//! for one purpose cannot be opened as another and a new purpose needs no new
//! environment variable.
//!
//! ## What is sealed
//!
//! The TOTP secret. The stored form is `v1:` + base64(`nonce(24) || ciphertext`),
//! XChaCha20-Poly1305 with a random nonce and the owning user's id as associated
//! data, so a ciphertext copied onto another account's row does not open.
//!
//! Values written before this existed are bare base32 with no prefix. Base32 has
//! no `:`, so the prefix tells the two apart without ambiguity, and
//! [`DataKey::open_totp_secret`] reports which it found so the caller can rewrite
//! the row.
//!
//! ## What this does not do
//!
//! The key lives in the server's environment. Someone who can read both the
//! database and that environment can open the values. This protects a database
//! copy (a backup, a replica, a leaked dump) on its own.

use base64ct::{Base64, Encoding};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use uuid::Uuid;

/// Prefix of a sealed value. Bump it when the format changes.
const SEALED_PREFIX: &str = "v1:";
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

/// HKDF `info` for each purpose. Never reuse one for a second purpose.
const PURPOSE_TOTP: &[u8] = b"evnx/v1/totp-secret";
const PURPOSE_DECOY_SALT: &[u8] = b"evnx/v1/srp-decoy-salt";

/// The fixed key used when `SERVER_DATA_KEY` is unset in development.
///
/// Public on purpose: it protects nothing, and exists so a development
/// database and the test suite work without setup. `Config::from_env` refuses
/// to use it outside `ENVIRONMENT=development`.
pub const DEVELOPMENT_KEY: [u8; 32] = *b"evnx-development-data-key-0000!!";

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("SERVER_DATA_KEY must be {} bytes encoded as base64", 32)]
    BadKey,
    #[error("sealed value is malformed or does not open")]
    Open,
    #[error("could not seal the value")]
    Seal,
}

/// The root data key. `Debug` is redacted: `Config` derives `Debug`.
#[derive(Clone)]
pub struct DataKey([u8; 32]);

impl std::fmt::Debug for DataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DataKey(<redacted>)")
    }
}

/// What [`DataKey::open_totp_secret`] found.
#[derive(Debug, PartialEq, Eq)]
pub struct OpenedSecret {
    pub plaintext: String,
    /// The stored value was an old unsealed one; the caller should rewrite it.
    pub was_legacy_plaintext: bool,
}

impl DataKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parse the base64 form used in the environment.
    pub fn from_base64(s: &str) -> Result<Self, SecretError> {
        let raw = Base64::decode_vec(s.trim()).map_err(|_| SecretError::BadKey)?;
        let bytes: [u8; 32] = raw.try_into().map_err(|_| SecretError::BadKey)?;
        Ok(Self(bytes))
    }

    pub fn development() -> Self {
        Self(DEVELOPMENT_KEY)
    }

    fn purpose_key(&self, info: &[u8]) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let mut out = [0u8; 32];
        hk.expand(info, &mut out)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        out
    }

    /// Seal a TOTP secret for `user_id`.
    pub fn seal_totp_secret(&self, user_id: Uuid, plaintext: &str) -> Result<String, SecretError> {
        let cipher = XChaCha20Poly1305::new(&self.purpose_key(PURPOSE_TOTP).into());
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: user_id.as_bytes(),
                },
            )
            .map_err(|_| SecretError::Seal)?;
        let mut blob = Vec::with_capacity(NONCE_LEN + ct.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        Ok(format!("{SEALED_PREFIX}{}", Base64::encode_string(&blob)))
    }

    /// Open a stored TOTP secret, accepting an old unsealed value.
    pub fn open_totp_secret(
        &self,
        user_id: Uuid,
        stored: &str,
    ) -> Result<OpenedSecret, SecretError> {
        let Some(body) = stored.strip_prefix(SEALED_PREFIX) else {
            return Ok(OpenedSecret {
                plaintext: stored.to_owned(),
                was_legacy_plaintext: true,
            });
        };
        let blob = Base64::decode_vec(body).map_err(|_| SecretError::Open)?;
        if blob.len() < NONCE_LEN + TAG_LEN {
            return Err(SecretError::Open);
        }
        let (nonce, ct) = blob.split_at(NONCE_LEN);
        let cipher = XChaCha20Poly1305::new(&self.purpose_key(PURPOSE_TOTP).into());
        let pt = cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ct,
                    aad: user_id.as_bytes(),
                },
            )
            .map_err(|_| SecretError::Open)?;
        Ok(OpenedSecret {
            plaintext: String::from_utf8(pt).map_err(|_| SecretError::Open)?,
            was_legacy_plaintext: false,
        })
    }

    /// Whether a stored value is already in the sealed form.
    pub fn is_sealed(stored: &str) -> bool {
        stored.starts_with(SEALED_PREFIX)
    }

    /// A salt for an address that has no account, in the same shape a real one
    /// has (32 bytes, base64).
    ///
    /// HMAC-SHA256 under the decoy-salt purpose key over `label || 0x00 ||
    /// email`, so the same address gets the same value on every call, a
    /// different value per `label`, and nobody without the key can predict or
    /// recompute it. `email_lower` must already be trimmed and lowercased.
    pub fn decoy_salt(&self, email_lower: &str, label: &str) -> String {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.purpose_key(PURPOSE_DECOY_SALT))
            .expect("HMAC accepts any key length");
        mac.update(label.as_bytes());
        mac.update(&[0]);
        mac.update(email_lower.as_bytes());
        Base64::encode_string(&mac.finalize().into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> DataKey {
        DataKey::from_bytes([7u8; 32])
    }

    #[test]
    fn a_sealed_secret_round_trips_and_is_not_the_plaintext() {
        let uid = Uuid::new_v4();
        let sealed = key().seal_totp_secret(uid, "JBSWY3DPEHPK3PXP").unwrap();
        assert!(sealed.starts_with("v1:"));
        assert!(!sealed.contains("JBSWY3DPEHPK3PXP"));
        let opened = key().open_totp_secret(uid, &sealed).unwrap();
        assert_eq!(opened.plaintext, "JBSWY3DPEHPK3PXP");
        assert!(!opened.was_legacy_plaintext);
    }

    #[test]
    fn two_seals_of_one_value_differ() {
        let uid = Uuid::new_v4();
        let a = key().seal_totp_secret(uid, "ABCDEFGH").unwrap();
        let b = key().seal_totp_secret(uid, "ABCDEFGH").unwrap();
        assert_ne!(a, b, "the nonce must be random");
    }

    #[test]
    fn a_sealed_secret_does_not_open_for_another_user_or_key() {
        let sealed = key()
            .seal_totp_secret(Uuid::new_v4(), "JBSWY3DPEHPK3PXP")
            .unwrap();
        assert!(key().open_totp_secret(Uuid::new_v4(), &sealed).is_err());

        let uid = Uuid::new_v4();
        let sealed = key().seal_totp_secret(uid, "JBSWY3DPEHPK3PXP").unwrap();
        let other = DataKey::from_bytes([8u8; 32]);
        assert!(other.open_totp_secret(uid, &sealed).is_err());
    }

    #[test]
    fn a_tampered_or_truncated_value_is_refused() {
        let uid = Uuid::new_v4();
        let sealed = key().seal_totp_secret(uid, "JBSWY3DPEHPK3PXP").unwrap();
        let mut raw = Base64::decode_vec(&sealed[3..]).unwrap();
        *raw.last_mut().unwrap() ^= 1;
        let tampered = format!("v1:{}", Base64::encode_string(&raw));
        assert!(key().open_totp_secret(uid, &tampered).is_err());
        assert!(key().open_totp_secret(uid, "v1:AAAA").is_err());
        assert!(key().open_totp_secret(uid, "v1:!!!").is_err());
    }

    #[test]
    fn an_unprefixed_value_is_reported_as_legacy() {
        let opened = key()
            .open_totp_secret(Uuid::new_v4(), "JBSWY3DPEHPK3PXP")
            .unwrap();
        assert_eq!(opened.plaintext, "JBSWY3DPEHPK3PXP");
        assert!(opened.was_legacy_plaintext);
        assert!(!DataKey::is_sealed("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn the_key_must_be_32_bytes_of_base64() {
        let good = Base64::encode_string(&[1u8; 32]);
        assert!(DataKey::from_base64(&good).is_ok());
        assert!(DataKey::from_base64(&Base64::encode_string(&[1u8; 31])).is_err());
        assert!(DataKey::from_base64(&Base64::encode_string(&[1u8; 33])).is_err());
        assert!(DataKey::from_base64("not base64!").is_err());
    }

    #[test]
    fn purposes_derive_different_keys() {
        let k = key();
        assert_ne!(
            k.purpose_key(PURPOSE_TOTP),
            k.purpose_key(PURPOSE_DECOY_SALT)
        );
    }

    #[test]
    fn debug_does_not_print_the_key() {
        assert_eq!(format!("{:?}", key()), "DataKey(<redacted>)");
    }

    #[test]
    fn a_decoy_salt_is_stable_per_email_and_label() {
        let k = key();
        let a = k.decoy_salt("a@example.test", "srp");
        assert_eq!(a, k.decoy_salt("a@example.test", "srp"));
        assert_ne!(a, k.decoy_salt("b@example.test", "srp"));
        assert_ne!(a, k.decoy_salt("a@example.test", "argon2"));
        assert_ne!(
            a,
            DataKey::from_bytes([8u8; 32]).decoy_salt("a@example.test", "srp")
        );
    }

    #[test]
    fn a_decoy_salt_has_the_shape_of_a_real_one() {
        // Registration requires exactly 44 base64 characters.
        let s = key().decoy_salt("a@example.test", "srp");
        assert_eq!(s.len(), 44);
        assert_eq!(Base64::decode_vec(&s).unwrap().len(), 32);
    }
}
