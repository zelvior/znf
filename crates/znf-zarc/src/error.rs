//! Error types for ZARC archive operations.

use thiserror::Error;
use znf_compression::CompressionError;
use znf_core::Error as CoreError;
use znf_crypto::CryptoError;
use znf_integrity::IntegrityError;
use znf_recovery::RecoveryError;
use znf_stream::StreamError;

use crate::path::PathError;

/// Errors returned by ZARC archive creation, inspection, verification, and extraction.
#[derive(Debug, Error)]
pub enum ZarcError {
    /// Underlying ZNF Core header/TLV error.
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

    /// Recovery error.
    #[error("recovery error: {0}")]
    Recovery(#[from] RecoveryError),

    /// Path validation / traversal error.
    #[error("unsafe or invalid archive path: {0}")]
    Path(#[from] PathError),

    /// File is a valid ZNF container, but not a `.zarc` archive (`FormatId != ZARC`).
    #[error("unexpected format id {0:#010x} (expected ZARC 0x00000001)")]
    NotZarcFormat(u32),

    /// Archive requires a password/key for decryption, or was given a password when unencrypted.
    #[error("encryption state mismatch: {0}")]
    EncryptionMismatch(&'static str),

    /// Archive entry or footer index is malformed.
    #[error("malformed archive structure: {0}")]
    MalformedArchive(String),

    /// Duplicate entry path in archive.
    #[error("duplicate entry path in archive: {0}")]
    DuplicateEntry(String),

    /// Archive exceeds configured resource or bomb-protection limits.
    #[error("archive resource limit exceeded: {0}")]
    ResourceLimitExceeded(String),

    /// Symlinks or unsupported special files encountered when disallowed.
    #[error("unsupported filesystem entry (symlink or device): {0}")]
    UnsupportedFsEntry(String),

    /// Standard I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
