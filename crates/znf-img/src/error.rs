//! Error types for ZIMG image operations.

use thiserror::Error;
use znf_compression::CompressionError;
use znf_core::Error as CoreError;
use znf_crypto::CryptoError;
use znf_integrity::IntegrityError;
use znf_stream::StreamError;

/// Errors returned by ZIMG image encoding, decoding, inspection, and verification.
#[derive(Debug, Error)]
pub enum ZimgError {
    /// Underlying ZNF Core header/TLV/metadata error.
    #[error("core format error: {0}")]
    Core(#[from] CoreError),

    /// Compression or decompression error.
    #[error("compression error: {0}")]
    Compression(#[from] CompressionError),

    /// Cryptographic authentication or KDF error.
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),

    /// BLAKE3 integrity error.
    #[error("integrity error: {0}")]
    Integrity(#[from] IntegrityError),

    /// Streaming/chunk framing error.
    #[error("stream error: {0}")]
    Stream(#[from] StreamError),

    /// File is a valid ZNF container, but not a `.zimg` image (`FormatId != ZIMG`).
    #[error("unexpected format id {0:#010x} (expected ZIMG 0x00000003)")]
    NotZimgFormat(u32),

    /// Image requires a password/key for decryption, or was given a password when unencrypted.
    #[error("encryption state mismatch: {0}")]
    EncryptionMismatch(&'static str),

    /// Image structure is malformed.
    #[error("malformed image structure: {0}")]
    MalformedImage(String),

    /// Image dimensions are invalid or exceed configured limits.
    #[error("invalid image dimensions: {0}")]
    InvalidDimensions(String),

    /// Pixel format is unsupported or inconsistent.
    #[error("unsupported pixel format: {0}")]
    UnsupportedPixelFormat(String),

    /// Requested chunk was not found in the image.
    #[error("chunk not found: {0}")]
    ChunkNotFound(usize),

    /// Output image already exists and `overwrite` is `false`.
    #[error("target path already exists (pass overwrite to replace): {0}")]
    TargetAlreadyExists(String),

    /// Image exceeds configured resource or bomb-protection limits.
    #[error("image resource limit exceeded: {0}")]
    ResourceLimitExceeded(String),

    /// Standard I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl ZimgError {
    /// Returns `true` if this error represents an AEAD authentication failure.
    #[must_use]
    pub fn is_authentication_failure(&self) -> bool {
        matches!(
            self,
            ZimgError::Crypto(CryptoError::AuthenticationFailed)
                | ZimgError::Core(CoreError::AuthenticationFailed)
        )
    }

    /// Returns `true` if this error indicates data corruption.
    #[must_use]
    pub fn is_corruption(&self) -> bool {
        match self {
            ZimgError::Core(e) => e.is_corruption(),
            ZimgError::Integrity(_) => true,
            ZimgError::Compression(CompressionError::CorruptData(_)) => true,
            _ => false,
        }
    }

    /// Returns `true` if this error indicates an unsupported version or critical feature.
    #[must_use]
    pub fn is_unsupported(&self) -> bool {
        match self {
            ZimgError::Core(e) => e.is_unsupported(),
            ZimgError::UnsupportedPixelFormat(_) => true,
            _ => false,
        }
    }
}
