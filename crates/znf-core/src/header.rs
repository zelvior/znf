//! Fixed-size ZNF Core header (`ZnfHeader` / `Header`, 64 bytes, little-endian).
//!
//! Wire layout (all multi-byte integers little-endian):
//!
//! ```text
//! Offset  Size  Field
//! 0       4     Magic: "ZNF\0" ([0x5A, 0x4E, 0x46, 0x00])
//! 4       4     Format ID (u32 LE)
//! 8       2     Major version (u16 LE)
//! 10      2     Minor version (u16 LE)
//! 12      8     Feature flags (u64 LE)
//! 20      8     Header length (u64 LE) — total header incl. extensions (>= 64)
//! 28      8     Payload offset (u64 LE) — from file start (>= header_len)
//! 36      8     Payload length (u64 LE)
//! 44      4     Header CRC-32 (u32 LE) — IEEE CRC-32 over bytes 0..44 || bytes 48..64
//! 48      1     Compression ID (u8) — 0=None, 1=Zstd, 2=Lz4
//! 49      1     Encryption ID (u8)  — 0=None, 1=XChaCha20-Poly1305
//! 50      14    Reserved ([u8; 14], must be all zero)
//! Total: 64 bytes.
//! ```
//!
//! Encoding is explicit and deterministic. Native Rust struct layout is
//! never serialized directly.

use znf_compression::Algorithm;

use crate::error::{Error, ZnfError};
use crate::flags::{Flags, ZnfFeatureFlags};
use crate::limits::Limits;
use crate::MAGIC;

/// Fixed header size in bytes.
pub const HEADER_LEN: usize = 64;

/// Offset of the CRC-32 field within the header.
pub const CRC_OFFSET: usize = 44;

/// Format identifier registry (ZNF Core v1.0).
///
/// Values `0x0000_0000` and `0xFFFF_FFFF` are reserved and must not
/// be assigned. Values `0x8000_0000..=0xFFFF_FFFE` are for private
/// or vendor use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FormatId(pub u32);

impl FormatId {
    /// Reserved: invalid format.
    pub const RESERVED: FormatId = FormatId(0);
    /// ZARC (`.zarc`) archive format.
    pub const ZARC: FormatId = FormatId(1);
    /// Generic ZNF Core container (`.znf`).
    pub const CORE: FormatId = FormatId(2);
    /// Upper bound of standard ZNF format IDs.
    pub const RESERVED_MAX: FormatId = FormatId(0x7FFF_FFFF);

    /// Create from raw value (validates reserved `0` and `u32::MAX`).
    pub fn from_raw(raw: u32) -> Result<Self, Error> {
        if raw == 0 || raw == u32::MAX {
            return Err(ZnfError::UnknownFormatId(raw));
        }
        Ok(FormatId(raw))
    }

    /// Raw `u32` value.
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Whether this is a recognized standard ZNF format (`ZARC` or `CORE`).
    #[must_use]
    pub const fn is_known(self) -> bool {
        matches!(self, FormatId::ZARC | FormatId::CORE)
    }
}

/// Format version (`major`, `minor`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ZnfFormatVersion {
    /// Major version (breaking changes).
    pub major: u16,
    /// Minor version (backward-compatible additions).
    pub minor: u16,
}

/// Alias for [`ZnfFormatVersion`].
pub type Version = ZnfFormatVersion;

impl ZnfFormatVersion {
    /// Create a version.
    #[must_use]
    pub const fn new(major: u16, minor: u16) -> Self {
        ZnfFormatVersion { major, minor }
    }

    /// ZNF Core v1.0 version constant.
    pub const V1_0: Self = ZnfFormatVersion { major: 1, minor: 0 };
}

/// Container-level compression identifier stored at header byte `48`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum ZnfCompression {
    /// Uncompressed payload (or per-entry compression in multi-entry archives).
    #[default]
    None = 0,
    /// Zstandard lossless compression (RFC 8878).
    Zstd = 1,
    /// LZ4 lossless block-framed compression.
    Lz4 = 2,
}

impl ZnfCompression {
    /// Decode from header byte `48`.
    pub fn from_byte(b: u8) -> Result<Self, ZnfError> {
        match b {
            0 => Ok(ZnfCompression::None),
            1 => Ok(ZnfCompression::Zstd),
            2 => Ok(ZnfCompression::Lz4),
            other => Err(ZnfError::UnsupportedCompression(other)),
        }
    }

    /// Wire byte representation.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    /// Convert to [`znf_compression::Algorithm`].
    #[must_use]
    pub const fn to_algorithm(self) -> Algorithm {
        match self {
            ZnfCompression::None => Algorithm::None,
            ZnfCompression::Zstd => Algorithm::Zstd,
            ZnfCompression::Lz4 => Algorithm::Lz4,
        }
    }

    /// Convert from [`znf_compression::Algorithm`].
    #[must_use]
    pub const fn from_algorithm(algo: Algorithm) -> Self {
        match algo {
            Algorithm::None => ZnfCompression::None,
            Algorithm::Zstd => ZnfCompression::Zstd,
            Algorithm::Lz4 => ZnfCompression::Lz4,
        }
    }
}

/// Container-level encryption identifier stored at header byte `49`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum ZnfEncryption {
    /// Unencrypted payload.
    #[default]
    None = 0,
    /// Authenticated encryption using `XChaCha20-Poly1305` (with `Argon2id` or 256-bit key).
    XChaCha20Poly1305 = 1,
}

impl ZnfEncryption {
    /// Decode from header byte `49`.
    pub fn from_byte(b: u8) -> Result<Self, ZnfError> {
        match b {
            0 => Ok(ZnfEncryption::None),
            1 => Ok(ZnfEncryption::XChaCha20Poly1305),
            other => Err(ZnfError::UnsupportedEncryption(other)),
        }
    }

    /// Wire byte representation.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Parsed 64-byte ZNF Core header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZnfHeader {
    format_id: FormatId,
    version: ZnfFormatVersion,
    flags: ZnfFeatureFlags,
    header_len: u64,
    payload_offset: u64,
    payload_len: u64,
    compression: ZnfCompression,
    encryption: ZnfEncryption,
}

/// Alias for [`ZnfHeader`].
pub type Header = ZnfHeader;

impl ZnfHeader {
    /// Create a header for a new file with default layout (`header_len = 64`, `payload_offset = 64`).
    #[must_use]
    pub fn new(format_id: FormatId, major: u16, minor: u16) -> Self {
        ZnfHeader {
            format_id,
            version: ZnfFormatVersion::new(major, minor),
            flags: ZnfFeatureFlags::default(),
            header_len: HEADER_LEN as u64,
            payload_offset: HEADER_LEN as u64,
            payload_len: 0,
            compression: ZnfCompression::None,
            encryption: ZnfEncryption::None,
        }
    }

    /// Create a header with explicit layout offsets and lengths.
    #[must_use]
    pub fn with_layout(
        format_id: FormatId,
        major: u16,
        minor: u16,
        header_len: u64,
        payload_offset: u64,
        payload_len: u64,
    ) -> Self {
        ZnfHeader {
            format_id,
            version: ZnfFormatVersion::new(major, minor),
            flags: ZnfFeatureFlags::default(),
            header_len,
            payload_offset,
            payload_len,
            compression: ZnfCompression::None,
            encryption: ZnfEncryption::None,
        }
    }

    /// Compute the IEEE 802.3 CRC-32 over the 60 non-CRC bytes of a 64-byte header
    /// (`bytes 0..44` followed by `bytes 48..64`).
    #[must_use]
    pub fn compute_header_crc(header_bytes: &[u8]) -> u32 {
        assert!(header_bytes.len() >= HEADER_LEN);
        let mut combined = [0u8; HEADER_LEN - 4];
        combined[0..44].copy_from_slice(&header_bytes[0..44]);
        combined[44..60].copy_from_slice(&header_bytes[48..64]);
        crate::crc32(&combined)
    }

    /// Format identifier.
    #[must_use]
    pub const fn format_id(&self) -> FormatId {
        self.format_id
    }

    /// Format version.
    #[must_use]
    pub const fn version(&self) -> ZnfFormatVersion {
        self.version
    }

    /// Feature flags.
    #[must_use]
    pub const fn flags(&self) -> ZnfFeatureFlags {
        self.flags
    }

    /// Mutable flags (for builders).
    pub fn flags_mut(&mut self) -> &mut Flags {
        &mut self.flags
    }

    /// Container-level compression identifier.
    #[must_use]
    pub const fn compression(&self) -> ZnfCompression {
        self.compression
    }

    /// Set container-level compression identifier and synchronize `Flags::COMPRESSED`.
    pub fn set_compression(&mut self, compression: ZnfCompression) {
        self.compression = compression;
        if compression != ZnfCompression::None {
            self.flags.set(ZnfFeatureFlags::COMPRESSED, true);
        }
    }

    /// Container-level encryption identifier.
    #[must_use]
    pub const fn encryption(&self) -> ZnfEncryption {
        self.encryption
    }

    /// Set container-level encryption identifier and synchronize `Flags::ENCRYPTED`.
    pub fn set_encryption(&mut self, encryption: ZnfEncryption) {
        self.encryption = encryption;
        if encryption != ZnfEncryption::None {
            self.flags.set(ZnfFeatureFlags::ENCRYPTED, true);
        }
    }

    /// Total header length including extensions (`>= 64`).
    #[must_use]
    pub const fn header_len(&self) -> u64 {
        self.header_len
    }

    /// Set header length.
    pub fn set_header_len(&mut self, len: u64) {
        self.header_len = len;
    }

    /// Payload offset from file start (`>= header_len`).
    #[must_use]
    pub const fn payload_offset(&self) -> u64 {
        self.payload_offset
    }

    /// Set payload offset.
    pub fn set_payload_offset(&mut self, offset: u64) {
        self.payload_offset = offset;
    }

    /// Payload length in bytes.
    #[must_use]
    pub const fn payload_len(&self) -> u64 {
        self.payload_len
    }

    /// Set payload length.
    pub fn set_payload_len(&mut self, len: u64) {
        self.payload_len = len;
    }

    /// Encode the header into `out` (at least [`HEADER_LEN`] bytes).
    ///
    /// # Errors
    ///
    /// Returns [`ZnfError`] if `out` is too short, reserved flag bits are set,
    /// flags conflict with compression/encryption IDs, or offsets are invalid.
    pub fn encode(&self, out: &mut [u8]) -> Result<(), Error> {
        if out.len() < HEADER_LEN {
            return Err(ZnfError::TooShort {
                need: HEADER_LEN,
                have: out.len(),
            });
        }
        if self.flags.reserved_bits() != 0 {
            return Err(ZnfError::NonZeroReserved(self.flags.reserved_bits()));
        }
        if self.compression != ZnfCompression::None && !self.flags.is_compressed() {
            return Err(ZnfError::FlagHeaderInconsistency(
                "compression_id != None requires Flags::COMPRESSED",
            ));
        }
        if self.encryption != ZnfEncryption::None && !self.flags.is_encrypted() {
            return Err(ZnfError::FlagHeaderInconsistency(
                "encryption_id != None requires Flags::ENCRYPTED",
            ));
        }
        if self.header_len < HEADER_LEN as u64 {
            return Err(ZnfError::InvalidHeaderLength(self.header_len));
        }
        if self.payload_offset < self.header_len {
            return Err(ZnfError::InvalidPayloadOffset(self.payload_offset));
        }

        out[0..4].copy_from_slice(&MAGIC);
        out[4..8].copy_from_slice(&self.format_id.0.to_le_bytes());
        out[8..10].copy_from_slice(&self.version.major.to_le_bytes());
        out[10..12].copy_from_slice(&self.version.minor.to_le_bytes());
        out[12..20].copy_from_slice(&self.flags.bits().to_le_bytes());
        out[20..28].copy_from_slice(&self.header_len.to_le_bytes());
        out[28..36].copy_from_slice(&self.payload_offset.to_le_bytes());
        out[36..44].copy_from_slice(&self.payload_len.to_le_bytes());
        out[48] = self.compression.as_byte();
        out[49] = self.encryption.as_byte();
        // Reserved: bytes 50..64 must be zero.
        out[50..64].fill(0);
        // CRC-32 over bytes 0..44 and 48..64.
        let crc = Self::compute_header_crc(&out[..HEADER_LEN]);
        out[CRC_OFFSET..CRC_OFFSET + 4].copy_from_slice(&crc.to_le_bytes());
        Ok(())
    }

    /// Encode into a fixed 64-byte array.
    pub fn to_bytes(&self) -> Result<[u8; HEADER_LEN], Error> {
        let mut buf = [0u8; HEADER_LEN];
        self.encode(&mut buf)?;
        Ok(buf)
    }

    /// Decode and validate a header from the first [`HEADER_LEN`] bytes.
    ///
    /// Validates magic, CRC-32, version compatibility, critical feature flags,
    /// compression/encryption identifiers, reserved bytes `50..64`, and section
    /// bounds against `limits` and optional `file_len`.
    ///
    /// # Errors
    ///
    /// Returns a typed [`ZnfError`] for any malformed or unsupported input. Never panics.
    pub fn decode(buf: &[u8], limits: &Limits, file_len: Option<u64>) -> Result<Self, Error> {
        if buf.len() < HEADER_LEN {
            return Err(ZnfError::TooShort {
                need: HEADER_LEN,
                have: buf.len(),
            });
        }
        let h = &buf[..HEADER_LEN];

        if h[0..4] != MAGIC {
            return Err(ZnfError::InvalidMagic {
                found: h[0..4].to_vec(),
            });
        }

        // Validate CRC-32 before trusting header fields.
        let stored_crc = u32::from_le_bytes(h[CRC_OFFSET..CRC_OFFSET + 4].try_into().unwrap());
        let computed = Self::compute_header_crc(h);
        if stored_crc != computed {
            return Err(ZnfError::HeaderCrcMismatch {
                stored: stored_crc,
                computed,
            });
        }

        let format_raw = u32::from_le_bytes(h[4..8].try_into().unwrap());
        let format_id = FormatId::from_raw(format_raw)?;

        let major = u16::from_le_bytes(h[8..10].try_into().unwrap());
        let minor = u16::from_le_bytes(h[10..12].try_into().unwrap());
        if major != 1 {
            return Err(ZnfError::UnsupportedMajorVersion {
                found: major,
                supported: 1,
            });
        }

        let flags = ZnfFeatureFlags::from_bits(u64::from_le_bytes(h[12..20].try_into().unwrap()));
        if !flags.is_valid_for_read() {
            return Err(ZnfError::InvalidFlags(flags.bits()));
        }

        let header_len = u64::from_le_bytes(h[20..28].try_into().unwrap());
        let payload_offset = u64::from_le_bytes(h[28..36].try_into().unwrap());
        let payload_len = u64::from_le_bytes(h[36..44].try_into().unwrap());

        let compression = ZnfCompression::from_byte(h[48])?;
        let encryption = ZnfEncryption::from_byte(h[49])?;

        if compression != ZnfCompression::None && !flags.is_compressed() {
            return Err(ZnfError::FlagHeaderInconsistency(
                "compression_id != None without Flags::COMPRESSED",
            ));
        }
        if encryption != ZnfEncryption::None && !flags.is_encrypted() {
            return Err(ZnfError::FlagHeaderInconsistency(
                "encryption_id != None without Flags::ENCRYPTED",
            ));
        }

        // Reserved bytes 50..64 must be zero.
        if h[50..64].iter().any(|&b| b != 0) {
            let mut val: u64 = 0;
            for (i, &b) in h[50..64].iter().enumerate() {
                val |= (b as u64) << ((i * 8) % 64);
            }
            return Err(ZnfError::NonZeroReserved(val));
        }

        // Validate lengths and bounds.
        limits.check("header", header_len, limits.max_header_len)?;
        if header_len < HEADER_LEN as u64 {
            return Err(ZnfError::InvalidHeaderLength(header_len));
        }
        if payload_offset < header_len {
            return Err(ZnfError::InvalidPayloadOffset(payload_offset));
        }
        let meta_len = payload_offset - header_len;
        limits.check("metadata", meta_len, limits.max_metadata_len)?;
        if meta_len > 0 && !flags.has_metadata() {
            return Err(ZnfError::FlagHeaderInconsistency(
                "payload_offset > header_len without Flags::HAS_METADATA",
            ));
        }
        limits.check("payload", payload_len, limits.max_payload_len)?;

        let payload_end = payload_offset
            .checked_add(payload_len)
            .ok_or(ZnfError::IntegerOverflow("payload end"))?;
        if let Some(fl) = file_len {
            if payload_end > fl {
                return Err(ZnfError::InvalidPayloadLength(payload_len));
            }
            if header_len > fl {
                return Err(ZnfError::InvalidHeaderLength(header_len));
            }
            if payload_end < fl && !flags.has_footer() {
                return Err(ZnfError::FlagHeaderInconsistency(
                    "trailing bytes after payload without Flags::HAS_FOOTER",
                ));
            }
        }

        Ok(ZnfHeader {
            format_id,
            version: ZnfFormatVersion::new(major, minor),
            flags,
            header_len,
            payload_offset,
            payload_len,
            compression,
            encryption,
        })
    }

    /// Metadata section length (`payload_offset - header_len`).
    #[must_use]
    pub const fn metadata_len(&self) -> u64 {
        self.payload_offset.saturating_sub(self.header_len)
    }

    /// Byte range (`start..end`) of the payload section.
    pub fn payload_range(&self) -> Result<(u64, u64), ZnfError> {
        let end = self
            .payload_offset
            .checked_add(self.payload_len)
            .ok_or(ZnfError::IntegerOverflow("payload end"))?;
        Ok((self.payload_offset, end))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> Header {
        let mut h = Header::new(FormatId::ZARC, 1, 0);
        h.flags_mut().set(Flags::HAS_METADATA, true);
        h.set_payload_len(1234);
        h
    }

    #[test]
    fn encode_decode_roundtrip() {
        let mut h = sample_header();
        h.set_compression(ZnfCompression::Zstd);
        h.set_encryption(ZnfEncryption::XChaCha20Poly1305);
        let mut buf = [0u8; 64];
        h.encode(&mut buf).unwrap();
        let d = Header::decode(&buf, &Limits::default(), Some(64 + 1234)).unwrap();
        assert_eq!(d.format_id(), FormatId::ZARC);
        assert_eq!(d.version(), Version::new(1, 0));
        assert!(d.flags().has_metadata());
        assert_eq!(d.compression(), ZnfCompression::Zstd);
        assert_eq!(d.encryption(), ZnfEncryption::XChaCha20Poly1305);
        assert_eq!(d.payload_len(), 1234);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = [0u8; 64];
        sample_header().encode(&mut buf).unwrap();
        buf[0] = 0xFF;
        assert!(Header::decode(&buf, &Limits::default(), None).is_err());
    }

    #[test]
    fn rejects_bad_crc() {
        let mut buf = [0u8; 64];
        sample_header().encode(&mut buf).unwrap();
        buf[20] ^= 0xFF;
        let e = Header::decode(&buf, &Limits::default(), None).unwrap_err();
        assert!(matches!(e, Error::HeaderCrcMismatch { .. }));
    }

    #[test]
    fn rejects_unsupported_major() {
        let h = Header::new(FormatId::ZARC, 2, 0);
        let mut buf = [0u8; 64];
        h.encode(&mut buf).unwrap();
        let e = Header::decode(&buf, &Limits::default(), None).unwrap_err();
        assert!(matches!(e, Error::UnsupportedMajorVersion { found: 2, .. }));
    }

    #[test]
    fn rejects_truncated() {
        let buf = [0u8; 10];
        assert!(Header::decode(&buf, &Limits::default(), None).is_err());
    }

    #[test]
    fn rejects_reserved_flags_on_write() {
        let mut h = Header::new(FormatId::ZARC, 1, 0);
        *h.flags_mut() = Flags::from_bits(1 << 40);
        let mut buf = [0u8; 64];
        assert!(h.encode(&mut buf).is_err());
    }

    #[test]
    fn ignores_non_critical_advisory_flags_on_read() {
        let h = Header::new(FormatId::ZARC, 1, 0);
        let mut buf = [0u8; 64];
        h.encode(&mut buf).unwrap();
        // Set bit 40 (in byte 17, which is in the non-critical advisory range 32..=47).
        buf[17] |= 0x01;
        let crc = Header::compute_header_crc(&buf);
        buf[44..48].copy_from_slice(&crc.to_le_bytes());
        let d = Header::decode(&buf, &Limits::default(), None).unwrap();
        assert_ne!(d.flags().non_critical_advisory_bits(), 0);
    }

    #[test]
    fn rejects_unknown_critical_flags_on_read() {
        let h = Header::new(FormatId::ZARC, 1, 0);
        let mut buf = [0u8; 64];
        h.encode(&mut buf).unwrap();
        // Set bit 15 (in byte 13, critical range 0..=31).
        buf[13] |= 0x80;
        let crc = Header::compute_header_crc(&buf);
        buf[44..48].copy_from_slice(&crc.to_le_bytes());
        let err = Header::decode(&buf, &Limits::default(), None).unwrap_err();
        assert!(matches!(err, ZnfError::InvalidFlags(_)));
    }
}
