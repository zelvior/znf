//! Error types for ZDOC document operations.

use thiserror::Error;
use znf_compression::CompressionError;
use znf_core::Error as CoreError;
use znf_crypto::CryptoError;
use znf_integrity::IntegrityError;
use znf_stream::StreamError;

/// Errors returned by ZDOC document encoding, decoding, inspection, and verification.
#[derive(Debug, Error)]
pub enum ZdocError {
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

    /// File is a valid ZNF container, but not a `.zdoc` document (`FormatId != ZDOC`).
    #[error("unexpected format id {0:#010x} (expected ZDOC 0x00000004)")]
    NotZdocFormat(u32),

    /// Document requires a password/key for decryption, or was given a password when unencrypted.
    #[error("encryption state mismatch: {0}")]
    EncryptionMismatch(&'static str),

    /// Document structure is malformed.
    #[error("malformed document structure: {0}")]
    MalformedStructure(String),

    /// Document dimensions or limits are invalid or exceed configured limits.
    #[error("invalid document dimensions: {0}")]
    InvalidDimensions(String),

    /// Object type is unsupported or invalid.
    #[error("unsupported object type: {0}")]
    UnsupportedObjectType(u8),

    /// Style is invalid or inheritance is circular.
    #[error("invalid style: {0}")]
    InvalidStyle(String),

    /// Document object was not found.
    #[error("object not found: {0}")]
    ObjectNotFound(String),

    /// Duplicate identifier within the document.
    #[error("duplicate identifier: {0}")]
    DuplicateIdentifier(String),

    /// Broken reference to a missing object.
    #[error("broken reference: {0}")]
    BrokenReference(String),

    /// Circular relationship where prohibited (e.g. style inheritance, section nesting).
    #[error("circular relationship: {0}")]
    CircularRelationship(String),

    /// Text is not valid UTF-8.
    #[error("invalid UTF-8 in document text: {0}")]
    InvalidUtf8(String),

    /// Output document already exists and `overwrite` is `false`.
    #[error("target path already exists (pass overwrite to replace): {0}")]
    TargetAlreadyExists(String),

    /// Document exceeds configured resource or bomb-protection limits.
    #[error("document resource limit exceeded: {0}")]
    ResourceLimitExceeded(String),

    /// Standard I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl ZdocError {
    /// Returns `true` if this error represents an AEAD authentication failure.
    #[must_use]
    pub fn is_authentication_failure(&self) -> bool {
        matches!(
            self,
            ZdocError::Crypto(CryptoError::AuthenticationFailed)
                | ZdocError::Core(CoreError::AuthenticationFailed)
        )
    }

    /// Returns `true` if this error indicates data corruption.
    #[must_use]
    pub fn is_corruption(&self) -> bool {
        match self {
            ZdocError::Core(e) => e.is_corruption(),
            ZdocError::Integrity(_) => true,
            ZdocError::Compression(CompressionError::CorruptData(_)) => true,
            _ => false,
        }
    }

    /// Returns `true` if this error indicates an unsupported version or critical feature.
    #[must_use]
    pub fn is_unsupported(&self) -> bool {
        match self {
            ZdocError::Core(e) => e.is_unsupported(),
            ZdocError::UnsupportedObjectType(_) => true,
            ZdocError::InvalidStyle(_) => true,
            _ => false,
        }
    }
}
