//! ZNF Core: versioned binary-format engine for Zelvior Native Formats.
//!
//! This crate implements the complete ZNF Core v1.0 container foundation:
//!
//! - **Fixed 64-byte Header (`ZnfHeader` / `Header`):** Magic identifier (`ZNF\0`),
//!   [`FormatId`], [`ZnfFormatVersion`], [`ZnfFeatureFlags`], [`ZnfCompression`],
//!   [`ZnfEncryption`], section offsets/lengths, and IEEE 802.3 CRC-32 checksum.
//! - **Structured Metadata (`ZnfMetadata`):** Deterministic TLV and nested `BTreeMap`
//!   encoding supporting Unicode text, binary blobs, integers, booleans, lists, maps,
//!   non-critical extension preservation (`0x7000..=0xFFFE`), critical extension
//!   enforcement (`0x4000..=0x6FFF`), and non-circular BLAKE3 integrity.
//! - **Streaming & Contiguous Container I/O (`ZnfWriter`, `ZnfReader`, `ZnfValidator`):**
//!   Integrated with `znf-compression` (`Store`, `Zstd`, `LZ4`), `znf-crypto`
//!   (`XChaCha20-Poly1305` + `Argon2id` + OS CSPRNG), `znf-integrity` (`BLAKE3`),
//!   and `znf-stream` (`Read` / `Write` bounded chunks).
//!
//! All parsing is strict: malformed, corrupted, or unsupported input returns
//! [`ZnfError`], never panics, and never performs unbounded allocations.
//!
//! # Examples
//!
//! ## Round-Trip Container with Compression, Encryption, and Metadata
//!
//! ```
//! use znf_core::{
//!     EncryptionKeySource, ZnfCompression, ZnfMetadata, ZnfReader, ZnfValidator, ZnfWriter,
//! };
//! use znf_crypto::KdfParams;
//!
//! let mut meta = ZnfMetadata::new();
//! meta.insert_text("document.title", "ZNF Core Engine Specification");
//! meta.insert_uint("document.revision", 1);
//!
//! let kdf = KdfParams::new_interactive_test().unwrap();
//! let writer = ZnfWriter::new()
//!     .with_compression(ZnfCompression::Zstd)
//!     .with_encryption(EncryptionKeySource::PasswordWithParams(
//!         b"correct-horse-battery-staple".to_vec(),
//!         kdf,
//!     ))
//!     .with_metadata(meta);
//!
//! let container_bytes = writer.write_to_vec(b"Exact lossless payload bytes").unwrap();
//!
//! // Validate structure without needing the decryption password:
//! let info = ZnfValidator::new().validate_structure(&container_bytes).unwrap();
//! assert_eq!(info.compression, ZnfCompression::Zstd);
//!
//! // Read, authenticate, decompress, and verify BLAKE3 integrity:
//! let decoded = ZnfReader::new()
//!     .with_encryption_key(EncryptionKeySource::Password(
//!         b"correct-horse-battery-staple".to_vec(),
//!     ))
//!     .read_container(&container_bytes)
//!     .unwrap();
//! assert_eq!(decoded.payload, b"Exact lossless payload bytes");
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::all)]

pub mod container;
pub mod error;
pub mod flags;
pub mod header;
pub mod limits;
pub mod metadata;
pub mod tlv;

pub use container::{
    ContainerInfo, DecodedContainer, EncryptionKeySource, ZnfReader, ZnfValidator, ZnfWriter,
    DEFAULT_STREAM_BUFFER_SIZE, MIN_STREAM_BUFFER_SIZE, TLV_CONTAINER_BLAKE3, TLV_FOOTER_AUTH_TAG,
    TLV_PAYLOAD_BLAKE3, TLV_STORED_PAYLOAD_LEN, TLV_UNCOMPRESSED_LEN,
};
pub use error::{Error, ZnfError};
pub use flags::{Flags, ZnfFeatureFlags};
pub use header::{
    FormatId, Header, Version, ZnfCompression, ZnfEncryption, ZnfFormatVersion, ZnfHeader,
    CRC_OFFSET, HEADER_LEN,
};
pub use limits::Limits;
pub use metadata::{
    MetadataValue, ZnfMetadata, MAX_METADATA_COLLECTION_LEN, MAX_METADATA_DEPTH, TLV_COMMENT,
    TLV_CORE_ATTRIBUTES, TLV_KDF_PARAMS, TLV_METADATA_BLAKE3, TLV_PAYLOAD_NONCE,
};
pub use tlv::{
    is_critical_extension_type, Tlv, TlvReader, TlvWriter, TLV_CRITICAL_EXT_MAX,
    TLV_CRITICAL_EXT_MIN, TLV_END, TLV_RESERVED,
};

/// ZNF Core specification version implemented by this crate.
pub const CORE_SPEC_VERSION: (u16, u16) = (1, 0);

/// Magic bytes identifying a ZNF file: `ZNF\0`.
pub const MAGIC: [u8; 4] = [0x5A, 0x4E, 0x46, 0x00];

/// CRC-32 (IEEE 802.3) used for header corruption detection.
///
/// This is a checksum, not cryptographic authentication. It detects
/// accidental corruption; it does not protect against intentional modification.
/// Cryptographic integrity and authenticity are provided by `znf-integrity`
/// (BLAKE3) and `znf-crypto` (XChaCha20-Poly1305 AEAD).
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    const fn make_table() -> [u32; 256] {
        let mut table = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut crc = i as u32;
            let mut j = 0;
            while j < 8 {
                if crc & 1 != 0 {
                    crc = 0xEDB8_8320 ^ (crc >> 1);
                } else {
                    crc >>= 1;
                }
                j += 1;
            }
            table[i] = crc;
            i += 1;
        }
        table
    }
    static TABLE: [u32; 256] = make_table();
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        let idx = ((crc ^ (b as u32)) & 0xFF) as usize;
        crc = TABLE[idx] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_known_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }
}
