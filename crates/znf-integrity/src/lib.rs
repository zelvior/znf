//! ZNF Integrity: BLAKE3 hashing and verification.
//!
//! BLAKE3 is an unkeyed hash function. It detects accidental
//! corruption and (with overwhelming probability) intentional
//! modification, but it is **not** authentication: anyone can
//! recompute a BLAKE3 hash. For authenticity, use `znf-crypto`
//! (AEAD) or a keyed MAC. Do not confuse checksums with
//! cryptographic authentication.
//!
//! This crate provides streaming hashing (bounded memory) and
//! one-shot helpers.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::all)]

use thiserror::Error;

/// BLAKE3 hash output length in bytes.
pub const HASH_LEN: usize = 32;

/// Errors from integrity operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IntegrityError {
    /// Hash mismatch: data does not match expected hash.
    #[error("hash mismatch: expected {expected}, computed {computed}")]
    HashMismatch {
        /// Expected hash (hex).
        expected: String,
        /// Computed hash (hex).
        computed: String,
    },

    /// I/O error while hashing.
    #[error("I/O error: {0}")]
    Io(String),
}

/// Streaming BLAKE3 hasher with bounded memory.
#[derive(Debug, Clone)]
pub struct Hasher {
    inner: blake3::Hasher,
}

impl Hasher {
    /// Create a new hasher.
    #[must_use]
    pub fn new() -> Self {
        Hasher {
            inner: blake3::Hasher::new(),
        }
    }

    /// Feed bytes into the hash.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize and return the hash.
    #[must_use]
    pub fn finalize(&self) -> Hash {
        Hash(*self.inner.finalize().as_bytes())
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

/// A BLAKE3 hash value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash(pub [u8; HASH_LEN]);

impl Hash {
    /// Parse from 32 raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; HASH_LEN]) -> Self {
        Hash(bytes)
    }

    /// Raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    /// Lowercase hex encoding (64 chars).
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in &self.0 {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// Parse from lowercase hex (64 chars).
    ///
    /// # Errors
    ///
    /// Returns [`IntegrityError::HashMismatch`] with a parse message
    /// if the input is not valid hex of the right length. (Reuses the
    /// mismatch variant to avoid a separate parse error type; the
    /// message distinguishes the case.)
    pub fn from_hex(hex: &str) -> Result<Self, IntegrityError> {
        if hex.len() != 64 {
            return Err(IntegrityError::HashMismatch {
                expected: "64 hex chars".to_string(),
                computed: format!("{} chars", hex.len()),
            });
        }
        let bytes = hex.as_bytes();
        let mut out = [0u8; HASH_LEN];
        for i in 0..HASH_LEN {
            let hi = hex_val(bytes[2 * i])?;
            let lo = hex_val(bytes[2 * i + 1])?;
            out[i] = (hi << 4) | lo;
        }
        Ok(Hash(out))
    }

    /// Verify that `data` hashes to this value.
    ///
    /// # Errors
    ///
    /// Returns [`IntegrityError::HashMismatch`] if they differ.
    pub fn verify(&self, data: &[u8]) -> Result<(), IntegrityError> {
        let computed = hash(data);
        if computed != *self {
            return Err(IntegrityError::HashMismatch {
                expected: self.to_hex(),
                computed: computed.to_hex(),
            });
        }
        Ok(())
    }
}

fn hex_val(b: u8) -> Result<u8, IntegrityError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(IntegrityError::HashMismatch {
            expected: "hex digit".to_string(),
            computed: format!("{b}"),
        }),
    }
}

/// One-shot hash of `data`.
#[must_use]
pub fn hash(data: &[u8]) -> Hash {
    Hash(*blake3::hash(data).as_bytes())
}

/// Hash all bytes readable from `reader` (streaming, bounded memory).
///
/// # Errors
///
/// Returns [`IntegrityError::Io`] on read failure.
pub fn hash_reader<R: std::io::Read>(mut reader: R) -> Result<Hash, IntegrityError> {
    let mut hasher = Hasher::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| IntegrityError::Io(e.to_string()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake3_known_vector() {
        // BLAKE3("") = af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262
        let h = hash(b"");
        assert_eq!(
            h.to_hex(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn streaming_matches_oneshot() {
        let data = b"hello world, this is a test of streaming hash consistency";
        let mut h = Hasher::new();
        h.update(&data[..10]);
        h.update(&data[10..]);
        assert_eq!(h.finalize(), hash(data));
    }

    #[test]
    fn hex_roundtrip() {
        let h = hash(b"abc");
        let hex = h.to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(Hash::from_hex(&hex).unwrap(), h);
    }

    #[test]
    fn verify_detects_mismatch() {
        let h = hash(b"original");
        assert!(h.verify(b"original").is_ok());
        assert!(h.verify(b"tampered").is_err());
    }
}
