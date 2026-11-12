// src/services/transport.rs

//! The transport hash and the stored blob layout.
//!
//! A blob is stored as `nonce(12) || ciphertext`. The **transport hash** is the
//! BLAKE3 digest of the ciphertext alone, as lowercase hex: the nonce is not
//! part of it. A client sends it with every push and staged re-key blob, the
//! server checks it on the way in and again on the way out, and `blob_hash` in
//! `vault_versions` stores it.
//!
//! This is the only place the server computes it. It used to be a bare
//! `blake3::hash(..)` at each call site, and the encoding is exactly the kind of
//! detail two copies can drift apart on.

/// Length of the AES-256-GCM nonce stored in front of every blob.
pub const NONCE_LEN: usize = 12;

/// The transport hash of `ciphertext`: BLAKE3, lowercase hex, 64 characters.
pub fn transport_hash(ciphertext: &[u8]) -> String {
    blake3::hash(ciphertext).to_hex().to_string()
}

/// Split a stored blob into its nonce and ciphertext. `None` if it is shorter
/// than a nonce.
pub fn split_stored_blob(stored: &[u8]) -> Option<(&[u8], &[u8])> {
    (stored.len() >= NONCE_LEN).then(|| stored.split_at(NONCE_LEN))
}

/// The transport hash of a stored blob's ciphertext. `None` if it is shorter
/// than a nonce.
pub fn stored_blob_hash(stored: &[u8]) -> Option<String> {
    split_stored_blob(stored).map(|(_, ct)| transport_hash(ct))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BLAKE3's published test vectors for inputs of 0 and 1 bytes (the input is
    /// the byte pattern `i % 251`). If these change, every stored `blob_hash`
    /// and every client's check changes with them.
    #[test]
    fn the_transport_hash_matches_fixed_vectors() {
        assert_eq!(
            transport_hash(b""),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        assert_eq!(
            transport_hash(&[0u8]),
            "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"
        );
    }

    #[test]
    fn the_hash_is_64_lowercase_hex_characters() {
        let h = transport_hash(b"some ciphertext");
        assert_eq!(h.len(), 64);
        assert!(h
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));
    }

    #[test]
    fn a_stored_blob_is_hashed_without_its_nonce() {
        let ct = b"the ciphertext and tag";
        let mut stored = vec![7u8; NONCE_LEN];
        stored.extend_from_slice(ct);
        assert_eq!(stored_blob_hash(&stored), Some(transport_hash(ct)));
        let (nonce, rest) = split_stored_blob(&stored).unwrap();
        assert_eq!(nonce, &[7u8; NONCE_LEN]);
        assert_eq!(rest, ct);
    }

    #[test]
    fn a_blob_shorter_than_a_nonce_has_no_hash() {
        assert_eq!(stored_blob_hash(&[0u8; NONCE_LEN - 1]), None);
        assert!(split_stored_blob(&[]).is_none());
        // Exactly a nonce: an empty ciphertext.
        assert_eq!(
            stored_blob_hash(&[0u8; NONCE_LEN]),
            Some(transport_hash(b""))
        );
    }
}
