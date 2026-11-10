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

    /// Two entry paths collide on case-insensitive filesystems (e.g. `File.txt` vs `file.txt`).
    #[error("case-insensitive path collision between '{first}' and '{second}'")]
    CaseInsensitiveCollision {
        /// First path encountered.
        first: String,
        /// Colliding path.
        second: String,
    },

    /// Output archive or extracted file already exists and `overwrite` is `false`.
    #[error("target path already exists (pass overwrite to replace): {0}")]
    TargetAlreadyExists(String),

    /// Source file changed on disk while being archived.
    #[error("source file changed during archiving: {0}")]
    SourceFileChanged(String),

    /// Requested entry path was not found in the archive.
    #[error("entry not found in archive: {0}")]
    EntryNotFound(String),

    /// Archive exceeds configured resource or bomb-protection limits.
    #[error("archive resource limit exceeded: {0}")]
    ResourceLimitExceeded(String),

    /// Symlinks or unsupported special files encountered when disallowed.
    #[error("unsupported filesystem entry (symlink or device): {0}")]
    UnsupportedFsEntry(String),

    /// Symlink encountered where symlinks are disallowed.
    #[error("symlink not allowed: {0}")]
    SymlinkNotAllowed(String),

    /// Operation was cancelled by caller.
    #[error("archive operation cancelled")]
    Cancelled,

    /// Standard I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl ZarcError {
    /// Returns `true` if this error represents an AEAD authentication failure (wrong password/key or tampered tag/AAD).
    #[must_use]
    pub fn is_authentication_failure(&self) -> bool {
        matches!(
            self,
            ZarcError::Crypto(CryptoError::AuthenticationFailed)
                | ZarcError::Core(CoreError::AuthenticationFailed)
        )
    }

    /// Returns `true` if this error indicates data corruption (CRC-32, BLAKE3, or compressed stream corruption).
    #[must_use]
    pub fn is_corruption(&self) -> bool {
        match self {
            ZarcError::Core(e) => e.is_corruption(),
            ZarcError::Integrity(_) => true,
            ZarcError::Compression(CompressionError::CorruptData(_)) => true,
            _ => false,
        }
    }

    /// Returns `true` if this error indicates an unsupported version, critical flag, or critical TLV extension.
    #[must_use]
    pub fn is_unsupported(&self) -> bool {
        match self {
            ZarcError::Core(e) => e.is_unsupported(),
            ZarcError::Compression(CompressionError::UnknownAlgorithm(_)) => true,
            _ => false,
        }
    }
}
