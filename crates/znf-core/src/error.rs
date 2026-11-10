//! Error types for ZNF Core parsing, encoding, validation, and container operations.
//!
//! `ZnfError` (also aliased as `Error`) distinguishes clearly between:
//! - **Corrupted data** (CRC-32 or BLAKE3 mismatch, truncated stream, corrupt compressed stream),
//! - **Authentication failure** (wrong key/password or tampered AEAD ciphertext/AAD),
//! - **Unsupported version or critical feature** (major version mismatch, unknown critical flag,
//!   unknown critical TLV extension, unknown compression/encryption identifier), and
//! - **Resource limit violations** (declared or expanded lengths exceeding configured `Limits`).

use thiserror::Error;

/// Primary error type for ZNF Core operations.
///
/// All variants indicate malformed, corrupted, unauthenticated, or unsupported
/// input, or an I/O / cancellation event. No variant represents an internal panic.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ZnfError {
    /// Input is shorter than the minimum required size.
    #[error("input too short: need {need} bytes, have {have}")]
    TooShort {
        /// Minimum bytes required.
        need: usize,
        /// Bytes actually available.
        have: usize,
    },

    /// Magic bytes do not match `ZNF\0`.
    #[error("invalid magic: expected ZNF\\0, found {found:?}")]
    InvalidMagic {
        /// First four bytes of input (or fewer if truncated).
        found: Vec<u8>,
    },

    /// Format identifier is reserved (`0` or `u32::MAX`) or unrecognized when strict.
    #[error("unknown or reserved format id: {0:#010x}")]
    UnknownFormatId(u32),

    /// Major version is unsupported (`0` or newer than supported major version).
    #[error("unsupported major version {found}, supported major version is {supported}")]
    UnsupportedMajorVersion {
        /// Version found in file.
        found: u16,
        /// Supported major version.
        supported: u16,
    },

    /// Header contains invalid or unsupported critical feature flags.
    #[error("invalid or unsupported critical feature flags: {0:#018x}")]
    InvalidFlags(u64),

    /// Header flags and compression/encryption identifiers are inconsistent.
    #[error("inconsistent header flags and identifiers: {0}")]
    FlagHeaderInconsistency(&'static str),

    /// Unknown compression identifier in header.
    #[error("unsupported compression identifier: {0}")]
    UnsupportedCompression(u8),

    /// Unknown encryption identifier in header.
    #[error("unsupported encryption identifier: {0}")]
    UnsupportedEncryption(u8),

    /// Header length is invalid (smaller than 64 bytes or inconsistent with file).
    #[error("invalid header length: {0}")]
    InvalidHeaderLength(u64),

    /// Payload offset is invalid (before header end or beyond file).
    #[error("invalid payload offset: {0}")]
    InvalidPayloadOffset(u64),

    /// Payload length is inconsistent with file size or stream.
    #[error("invalid payload length: {0}")]
    InvalidPayloadLength(u64),

    /// Reserved header field is non-zero.
    #[error("reserved field must be zero, found {0:#x}")]
    NonZeroReserved(u64),

    /// Header CRC-32 mismatch (accidental corruption detected).
    #[error("header CRC mismatch: stored {stored:#010x}, computed {computed:#010x}")]
    HeaderCrcMismatch {
        /// CRC stored in header.
        stored: u32,
        /// CRC computed over header bytes.
        computed: u32,
    },

    /// Metadata BLAKE3 hash mismatch (metadata corruption detected).
    #[error("metadata BLAKE3 mismatch: expected {expected}, computed {computed}")]
    MetadataHashMismatch {
        /// Expected hex digest.
        expected: String,
        /// Computed hex digest.
        computed: String,
    },

    /// Payload BLAKE3 hash mismatch (payload corruption detected).
    #[error("payload BLAKE3 mismatch: expected {expected}, computed {computed}")]
    PayloadHashMismatch {
        /// Expected hex digest.
        expected: String,
        /// Computed hex digest.
        computed: String,
    },

    /// Whole-container pre-footer BLAKE3 hash mismatch.
    #[error("container BLAKE3 mismatch: expected {expected}, computed {computed}")]
    ContainerHashMismatch {
        /// Expected hex digest.
        expected: String,
        /// Computed hex digest.
        computed: String,
    },

    /// Decompressed byte length does not match expected uncompressed length.
    #[error("uncompressed payload length mismatch: expected {expected}, got {got}")]
    UncompressedLengthMismatch {
        /// Declared uncompressed byte length.
        expected: u64,
        /// Actual decompressed byte length.
        got: u64,
    },

    /// A length field exceeds the configured limit.
    #[error("{what} length {len} exceeds limit {limit}")]
    LengthExceedsLimit {
        /// What length was checked (e.g. "header", "tlv", "metadata", "payload", "expanded").
        what: &'static str,
        /// Length found.
        len: u64,
        /// Configured limit.
        limit: u64,
    },

    /// TLV length exceeds remaining bytes.
    #[error("TLV length {len} exceeds remaining {remaining} bytes")]
    TlvLengthExceedsRemaining {
        /// Declared TLV value length.
        len: u32,
        /// Bytes remaining in buffer.
        remaining: usize,
    },

    /// TLV type is reserved (`0x0000`) and must not appear.
    #[error("reserved TLV type {0:#06x} must not appear")]
    ReservedTlvType(u16),

    /// Critical TLV extension (`0x4000..=0x6FFF`) is not supported by this reader.
    #[error("unsupported critical extension TLV type {0:#06x}")]
    UnsupportedCriticalExtension(u16),

    /// Structured metadata or container section is malformed.
    #[error("invalid metadata or section structure: {0}")]
    InvalidMetadata(String),

    /// Required container TLV or key material is missing.
    #[error("missing required container field or key material: {0}")]
    MissingRequiredField(&'static str),

    /// AEAD authentication failed (wrong password/key, tampered ciphertext, or tampered header/metadata AAD).
    #[error("cryptographic authentication failed (wrong key/password or tampered data)")]
    AuthenticationFailed,

    /// Invalid cryptographic or KDF parameters.
    #[error("invalid cryptographic parameters: {0}")]
    InvalidCryptoParams(String),

    /// Compressed payload stream is malformed or corrupted.
    #[error("corrupt compressed payload: {0}")]
    CorruptCompressedPayload(String),

    /// Unexpected end of input while parsing.
    #[error("unexpected end of input at offset {offset}")]
    UnexpectedEof {
        /// Byte offset where more data was expected.
        offset: u64,
    },

    /// Integer overflow while validating offsets or lengths.
    #[error("integer overflow while validating {0}")]
    IntegerOverflow(&'static str),

    /// Streaming operation was cancelled by caller.
    #[error("operation cancelled")]
    Cancelled,

    /// I/O error during read/write.
    #[error("I/O error: {0}")]
    Io(String),
}

/// Alias for [`ZnfError`] for crate-level ergonomics.
pub type Error = ZnfError;

impl ZnfError {
    /// Returns `true` if this error indicates data corruption (checksum/hash/compression failure).
    #[must_use]
    pub fn is_corruption(&self) -> bool {
        matches!(
            self,
            ZnfError::HeaderCrcMismatch { .. }
                | ZnfError::MetadataHashMismatch { .. }
                | ZnfError::PayloadHashMismatch { .. }
                | ZnfError::ContainerHashMismatch { .. }
                | ZnfError::CorruptCompressedPayload(_)
                | ZnfError::UncompressedLengthMismatch { .. }
        )
    }

    /// Returns `true` if this error indicates an unsupported version or critical feature/extension.
    #[must_use]
    pub fn is_unsupported(&self) -> bool {
        matches!(
            self,
            ZnfError::UnsupportedMajorVersion { .. }
                | ZnfError::InvalidFlags(_)
                | ZnfError::UnsupportedCriticalExtension(_)
                | ZnfError::UnsupportedCompression(_)
                | ZnfError::UnsupportedEncryption(_)
        )
    }

    /// Returns `true` if this error is an AEAD cryptographic authentication failure.
    #[must_use]
    pub fn is_authentication_failure(&self) -> bool {
        matches!(self, ZnfError::AuthenticationFailed)
    }
}

impl From<std::io::Error> for ZnfError {
    fn from(e: std::io::Error) -> Self {
        ZnfError::Io(e.to_string())
    }
}

impl From<znf_compression::CompressionError> for ZnfError {
    fn from(e: znf_compression::CompressionError) -> Self {
        match e {
            znf_compression::CompressionError::UnknownAlgorithm(b) => {
                ZnfError::UnsupportedCompression(b)
            }
            znf_compression::CompressionError::ExpandedSizeExceedsLimit { limit, got } => {
                ZnfError::LengthExceedsLimit {
                    what: "expanded",
                    len: got,
                    limit,
                }
            }
            znf_compression::CompressionError::CorruptData(msg) => {
                ZnfError::CorruptCompressedPayload(msg)
            }
            znf_compression::CompressionError::Io(msg) => ZnfError::Io(msg),
        }
    }
}

impl From<znf_crypto::CryptoError> for ZnfError {
    fn from(e: znf_crypto::CryptoError) -> Self {
        match e {
            znf_crypto::CryptoError::AuthenticationFailed => ZnfError::AuthenticationFailed,
            znf_crypto::CryptoError::InvalidKdfParams(msg) => ZnfError::InvalidCryptoParams(msg),
            znf_crypto::CryptoError::RngFailure(msg) => ZnfError::Io(format!("RNG failure: {msg}")),
            znf_crypto::CryptoError::TooShort { need, have } => ZnfError::TooShort { need, have },
        }
    }
}

impl From<znf_stream::StreamError> for ZnfError {
    fn from(e: znf_stream::StreamError) -> Self {
        match e {
            znf_stream::StreamError::ChunkTooLarge { len, max } => ZnfError::LengthExceedsLimit {
                what: "chunk",
                len: len as u64,
                limit: max as u64,
            },
            znf_stream::StreamError::LimitExceeded { limit } => ZnfError::LengthExceedsLimit {
                what: "stream",
                len: limit.saturating_add(1),
                limit,
            },
            znf_stream::StreamError::UnexpectedEof => ZnfError::UnexpectedEof { offset: 0 },
            znf_stream::StreamError::Io(io_err) => ZnfError::Io(io_err.to_string()),
        }
    }
}
