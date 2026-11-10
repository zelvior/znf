//! ZNF Cryptography: AEAD encryption, password KDF, and OS randomness.
//!
//! # Security Assumptions and Design
//!
//! This crate never implements cryptographic algorithms; it wraps
//! established RustCrypto libraries:
//!
//! - **AEAD**: `XChaCha20-Poly1305` (256-bit key, 192-bit nonce, 128-bit tag).
//!   The 24-byte extended nonce makes random nonces safe against collision.
//!   Headers/metadata are passed as Associated Data (AAD) so any tampering
//!   with unencrypted header fields causes decryption to fail before
//!   releasing plaintext.
//! - **KDF**: `Argon2id` v19 (memory-hard password key derivation).
//!   Default parameters: 64 MiB memory, 3 iterations, parallelism 4,
//!   16-byte random salt, 32-byte key output. Parameter limits are enforced
//!   when reading untrusted files to prevent resource-exhaustion attacks.
//! - **Randomness**: OS CSPRNG via `getrandom` (`/dev/urandom` / `getrandom(2)`
//!   on Linux/Android, `BCryptGenRandom` on Windows, `getentropy` on macOS).
//! - **Zeroization**: Key and password buffers implement `ZeroizeOnDrop`.
//!
//! Checksums (CRC-32, BLAKE3) are **not** authentication; use AEAD for
//! authenticity and confidentiality.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::all)]

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Key length in bytes (256 bits).
pub const KEY_LEN: usize = 32;

/// XChaCha20-Poly1305 nonce length in bytes (192 bits).
pub const NONCE_LEN: usize = 24;

/// Poly1305 authentication tag length in bytes (128 bits).
pub const TAG_LEN: usize = 16;

/// Argon2id salt length in bytes (128 bits).
pub const SALT_LEN: usize = 16;

/// Encoded KdfParams size in bytes (`m_cost` + `t_cost` + `p_cost` + salt).
pub const KDF_PARAMS_LEN: usize = 4 + 4 + 4 + SALT_LEN;

/// Maximum Argon2 memory cost accepted from untrusted files (1 GiB).
pub const MAX_M_COST_KIB: u32 = 1024 * 1024;

/// Maximum Argon2 time cost accepted from untrusted files.
pub const MAX_T_COST: u32 = 32;

/// Maximum Argon2 parallelism accepted from untrusted files.
pub const MAX_P_COST: u32 = 64;

/// Errors from cryptographic operations.
///
/// Decryption failure is deliberately opaque to avoid oracle leakage.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// AEAD authentication failed (wrong key, tampered ciphertext, or tampered AAD).
    #[error("authentication failed (wrong password/key or corrupted data)")]
    AuthenticationFailed,

    /// Invalid KDF parameters (out of bounds or rejected by policy).
    #[error("invalid KDF parameters: {0}")]
    InvalidKdfParams(String),

    /// OS random number generator failure.
    #[error("OS RNG failure: {0}")]
    RngFailure(String),

    /// Input buffer too short for encoded parameters.
    #[error("buffer too short: need {need} bytes, have {have}")]
    TooShort {
        /// Bytes needed.
        need: usize,
        /// Bytes available.
        have: usize,
    },
}

/// A 256-bit symmetric key, zeroized on drop.
#[derive(Clone)]
pub struct SecretKey([u8; KEY_LEN]);

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SecretKey {}

impl SecretKey {
    /// Create from raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        SecretKey(bytes)
    }

    /// Generate a fresh random key from the OS CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::RngFailure`] if the OS RNG fails.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = [0u8; KEY_LEN];
        random_bytes(&mut bytes)?;
        Ok(SecretKey(bytes))
    }

    /// Borrow key bytes (avoid copying where possible).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey([REDACTED])")
    }
}

/// Fill `dest` with cryptographically secure random bytes from the OS.
///
/// # Errors
///
/// Returns [`CryptoError::RngFailure`] if the OS CSPRNG is unavailable.
pub fn random_bytes(dest: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::fill(dest).map_err(|e| CryptoError::RngFailure(e.to_string()))
}

/// Generate a random 24-byte XChaCha20-Poly1305 nonce.
///
/// # Errors
///
/// Returns [`CryptoError::RngFailure`] if the OS RNG fails.
pub fn generate_nonce() -> Result<[u8; NONCE_LEN], CryptoError> {
    let mut n = [0u8; NONCE_LEN];
    random_bytes(&mut n)?;
    Ok(n)
}

/// Argon2id key derivation parameters (stored in file header extensions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    /// Time cost (iterations).
    pub t_cost: u32,
    /// Parallelism (lanes).
    pub p_cost: u32,
    /// 16-byte random salt.
    pub salt: [u8; SALT_LEN],
}

impl KdfParams {
    /// Production defaults: 64 MiB, 3 iterations, 4 lanes, fresh random salt.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::RngFailure`] if salt generation fails.
    pub fn new_default() -> Result<Self, CryptoError> {
        let mut salt = [0u8; SALT_LEN];
        random_bytes(&mut salt)?;
        Ok(KdfParams {
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 4,
            salt,
        })
    }

    /// Fast parameters for tests only (8 MiB, 1 iteration, 1 lane).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::RngFailure`] if salt generation fails.
    pub fn new_interactive_test() -> Result<Self, CryptoError> {
        let mut salt = [0u8; SALT_LEN];
        random_bytes(&mut salt)?;
        Ok(KdfParams {
            m_cost_kib: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
            salt,
        })
    }

    /// Validate parameters against safe bounds (protects against DoS from
    /// untrusted files requesting huge memory or CPU).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKdfParams`] if out of bounds.
    pub fn validate(&self) -> Result<(), CryptoError> {
        if self.m_cost_kib < 8 * 1024 || self.m_cost_kib > MAX_M_COST_KIB {
            return Err(CryptoError::InvalidKdfParams(format!(
                "m_cost_kib {} outside [8192, {MAX_M_COST_KIB}]",
                self.m_cost_kib
            )));
        }
        if self.t_cost < 1 || self.t_cost > MAX_T_COST {
            return Err(CryptoError::InvalidKdfParams(format!(
                "t_cost {} outside [1, {MAX_T_COST}]",
                self.t_cost
            )));
        }
        if self.p_cost < 1 || self.p_cost > MAX_P_COST {
            return Err(CryptoError::InvalidKdfParams(format!(
                "p_cost {} outside [1, {MAX_P_COST}]",
                self.p_cost
            )));
        }
        Ok(())
    }

    /// Encode into 28 bytes (little-endian).
    #[must_use]
    pub fn encode(&self) -> [u8; KDF_PARAMS_LEN] {
        let mut out = [0u8; KDF_PARAMS_LEN];
        out[0..4].copy_from_slice(&self.m_cost_kib.to_le_bytes());
        out[4..8].copy_from_slice(&self.t_cost.to_le_bytes());
        out[8..12].copy_from_slice(&self.p_cost.to_le_bytes());
        out[12..28].copy_from_slice(&self.salt);
        out
    }

    /// Decode and validate from 28 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if too short or parameters are out of bounds.
    pub fn decode(buf: &[u8]) -> Result<Self, CryptoError> {
        if buf.len() < KDF_PARAMS_LEN {
            return Err(CryptoError::TooShort {
                need: KDF_PARAMS_LEN,
                have: buf.len(),
            });
        }
        let m_cost_kib = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let t_cost = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let p_cost = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&buf[12..28]);
        let params = KdfParams {
            m_cost_kib,
            t_cost,
            p_cost,
            salt,
        };
        params.validate()?;
        Ok(params)
    }

    /// Derive a 256-bit key from `password` using Argon2id v19.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKdfParams`] if parameters are invalid.
    pub fn derive_key(&self, password: &[u8]) -> Result<SecretKey, CryptoError> {
        self.validate()?;
        let params = argon2::Params::new(self.m_cost_kib, self.t_cost, self.p_cost, Some(KEY_LEN))
            .map_err(|e| CryptoError::InvalidKdfParams(e.to_string()))?;
        let argon =
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut key = [0u8; KEY_LEN];
        argon
            .hash_password_into(password, &self.salt, &mut key)
            .map_err(|e| CryptoError::InvalidKdfParams(e.to_string()))?;
        Ok(SecretKey::from_bytes(key))
    }
}

/// Encrypt `plaintext` with `XChaCha20-Poly1305`, binding `aad` (Associated Data).
///
/// Returns ciphertext with the 16-byte Poly1305 tag appended (`plaintext.len() + 16`).
/// The caller must never reuse `(key, nonce)` for different messages.
///
/// # Errors
///
/// Returns [`CryptoError::AuthenticationFailed`] if encryption fails.
pub fn encrypt(
    key: &SecretKey,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let xnonce = XNonce::from(*nonce);
    cipher
        .encrypt(
            &xnonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)
}

/// Decrypt `ciphertext` (with appended 16-byte tag) using `XChaCha20-Poly1305`,
/// verifying `aad`.
///
/// If authentication fails, no plaintext is returned.
///
/// # Errors
///
/// Returns [`CryptoError::AuthenticationFailed`] if the key, nonce, ciphertext,
/// tag, or AAD is invalid.
pub fn decrypt(
    key: &SecretKey,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < TAG_LEN {
        return Err(CryptoError::AuthenticationFailed);
    }
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let xnonce = XNonce::from(*nonce);
    cipher
        .decrypt(
            &xnonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)
}

/// Derive a per-chunk nonce from a base nonce and a 64-bit chunk index.
///
/// XORs `chunk_index` (little-endian) into the last 8 bytes of `base_nonce`.
/// This standard construction ensures unique nonces across ordered chunks
/// under a single key when `base_nonce` is random per stream/entry.
#[must_use]
pub fn chunk_nonce(base_nonce: &[u8; NONCE_LEN], chunk_index: u64) -> [u8; NONCE_LEN] {
    let mut n = *base_nonce;
    let idx = chunk_index.to_le_bytes();
    for i in 0..8 {
        n[16 + i] ^= idx[i];
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_roundtrip_and_tamper_detection() {
        let key = SecretKey::generate().unwrap();
        let nonce = generate_nonce().unwrap();
        let msg = b"confidential archive payload";
        let aad = b"ZNF header bytes";

        let ct = encrypt(&key, &nonce, msg, aad).unwrap();
        assert_eq!(ct.len(), msg.len() + TAG_LEN);

        // Valid decrypt.
        let pt = decrypt(&key, &nonce, &ct, aad).unwrap();
        assert_eq!(pt, msg);

        // Tampered ciphertext rejected.
        let mut bad_ct = ct.clone();
        bad_ct[0] ^= 1;
        assert_eq!(
            decrypt(&key, &nonce, &bad_ct, aad).unwrap_err(),
            CryptoError::AuthenticationFailed
        );

        // Tampered AAD rejected.
        assert_eq!(
            decrypt(&key, &nonce, &ct, b"wrong header").unwrap_err(),
            CryptoError::AuthenticationFailed
        );

        // Wrong key rejected.
        let wrong_key = SecretKey::generate().unwrap();
        assert_eq!(
            decrypt(&wrong_key, &nonce, &ct, aad).unwrap_err(),
            CryptoError::AuthenticationFailed
        );
    }

    #[test]
    fn kdf_deterministic_and_params_roundtrip() {
        let params = KdfParams::new_interactive_test().unwrap();
        let enc = params.encode();
        let dec = KdfParams::decode(&enc).unwrap();
        assert_eq!(params, dec);

        let k1 = params.derive_key(b"correct horse battery staple").unwrap();
        let k2 = dec.derive_key(b"correct horse battery staple").unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());

        let k3 = params.derive_key(b"different password").unwrap();
        assert_ne!(k1.as_bytes(), k3.as_bytes());
    }

    #[test]
    fn kdf_rejects_excessive_params() {
        let bad = KdfParams {
            m_cost_kib: MAX_M_COST_KIB + 1,
            t_cost: 3,
            p_cost: 4,
            salt: [0u8; SALT_LEN],
        };
        assert!(bad.validate().is_err());
    }
}
