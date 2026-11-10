//! Feature and capability flags for ZNF Core headers (`ZnfFeatureFlags` / `Flags`).
//!
//! Flags are a 64-bit little-endian bitmask partitioned into three ranges:
//!
//! - **Bits `0..=31` (`0x0000_0000_FFFF_FFFF`) — Critical Capability Flags:**
//!   Bits `0..=4` are defined in ZNF Core v1.0. Bits `5..=31` are reserved for
//!   future critical capabilities. Readers **must** reject any header with an
//!   unknown critical bit set (`ZnfError::InvalidFlags`), never silently ignoring
//!   critical unsupported features.
//! - **Bits `32..=47` (`0x0000_FFFF_0000_0000`) — Non-Critical Advisory Flags:**
//!   Reserved for forward-compatible hints. Readers supporting v1.x **must**
//!   ignore unknown bits in this range, while writers of v1.0 files must leave
//!   them zero unless explicitly configured.
//! - **Bits `48..=63` (`0xFFFF_0000_0000_0000`) — Invalid / Must-Be-Zero Flags:**
//!   Must always be zero; readers reject headers with any bit in `48..=63` set.

/// Feature flags stored in the ZNF Core header (`u64` little-endian).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct ZnfFeatureFlags(u64);

/// Alias for [`ZnfFeatureFlags`].
pub type Flags = ZnfFeatureFlags;

impl ZnfFeatureFlags {
    /// Payload is compressed (`ZnfCompression != None`, or per-entry in archives).
    pub const COMPRESSED: u64 = 1 << 0;
    /// Payload (and sensitive metadata/index) is AEAD-encrypted.
    pub const ENCRYPTED: u64 = 1 << 1;
    /// Metadata TLV section is present between `header_len` and `payload_offset`.
    pub const HAS_METADATA: u64 = 1 << 2;
    /// Footer TLV section is present after `payload_offset + payload_len`.
    pub const HAS_FOOTER: u64 = 1 << 3;
    /// Payload uses chunked/streamed framing (`znf-stream` length-prefixed chunks).
    pub const STREAMING: u64 = 1 << 4;

    /// Mask of critical bits defined in ZNF Core v1.0.
    pub const DEFINED_MASK: u64 = Self::COMPRESSED
        | Self::ENCRYPTED
        | Self::HAS_METADATA
        | Self::HAS_FOOTER
        | Self::STREAMING;

    /// Mask covering all critical capability bits (`0..=31`).
    pub const CRITICAL_RANGE_MASK: u64 = 0x0000_0000_FFFF_FFFF;

    /// Mask covering forward-compatible non-critical advisory bits (`32..=47`).
    pub const NON_CRITICAL_RANGE_MASK: u64 = 0x0000_FFFF_0000_0000;

    /// Mask covering invalid must-be-zero bits (`48..=63`).
    pub const INVALID_RANGE_MASK: u64 = 0xFFFF_0000_0000_0000;

    /// Create flags from raw bits.
    #[must_use]
    pub const fn from_bits(raw: u64) -> Self {
        ZnfFeatureFlags(raw)
    }

    /// Raw 64-bit flag value.
    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Whether the payload is compressed.
    #[must_use]
    pub const fn is_compressed(self) -> bool {
        self.0 & Self::COMPRESSED != 0
    }

    /// Whether the payload is encrypted.
    #[must_use]
    pub const fn is_encrypted(self) -> bool {
        self.0 & Self::ENCRYPTED != 0
    }

    /// Whether a metadata section is present.
    #[must_use]
    pub const fn has_metadata(self) -> bool {
        self.0 & Self::HAS_METADATA != 0
    }

    /// Whether a footer section is present.
    #[must_use]
    pub const fn has_footer(self) -> bool {
        self.0 & Self::HAS_FOOTER != 0
    }

    /// Whether the payload uses streaming/chunked encoding.
    #[must_use]
    pub const fn is_streaming(self) -> bool {
        self.0 & Self::STREAMING != 0
    }

    /// Set or clear a flag bit.
    pub fn set(&mut self, bit: u64, value: bool) {
        if value {
            self.0 |= bit;
        } else {
            self.0 &= !bit;
        }
    }

    /// All undefined bits (`!DEFINED_MASK`). Writers must ensure this is zero.
    #[must_use]
    pub const fn reserved_bits(self) -> u64 {
        self.0 & !Self::DEFINED_MASK
    }

    /// Unknown critical bits (`bits 0..=31` outside `DEFINED_MASK`).
    #[must_use]
    pub const fn unsupported_critical_bits(self) -> u64 {
        (self.0 & Self::CRITICAL_RANGE_MASK) & !Self::DEFINED_MASK
    }

    /// Non-critical advisory extension bits (`bits 32..=47`).
    #[must_use]
    pub const fn non_critical_advisory_bits(self) -> u64 {
        self.0 & Self::NON_CRITICAL_RANGE_MASK
    }

    /// Invalid upper bits (`bits 48..=63`).
    #[must_use]
    pub const fn invalid_upper_bits(self) -> u64 {
        self.0 & Self::INVALID_RANGE_MASK
    }

    /// Validate flags for reading: rejects unknown critical bits (`5..=31`) and
    /// invalid upper bits (`48..=63`), while allowing non-critical advisory bits (`32..=47`).
    #[must_use]
    pub const fn is_valid_for_read(self) -> bool {
        self.unsupported_critical_bits() == 0 && self.invalid_upper_bits() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_roundtrip() {
        let mut f = ZnfFeatureFlags::default();
        assert!(!f.is_compressed());
        f.set(ZnfFeatureFlags::COMPRESSED, true);
        assert!(f.is_compressed());
        assert_eq!(f.reserved_bits(), 0);
        assert!(f.is_valid_for_read());
        f.set(ZnfFeatureFlags::COMPRESSED, false);
        assert!(!f.is_compressed());
    }

    #[test]
    fn critical_vs_non_critical_flag_validation() {
        // Non-critical advisory bit (bit 40) is valid for read.
        let advisory = ZnfFeatureFlags::from_bits(1 << 40);
        assert_ne!(advisory.reserved_bits(), 0);
        assert!(advisory.is_valid_for_read());

        // Unknown critical bit (bit 15) is rejected on read.
        let critical = ZnfFeatureFlags::from_bits(1 << 15);
        assert!(!critical.is_valid_for_read());

        // Invalid upper bit (bit 55) is rejected on read.
        let upper = ZnfFeatureFlags::from_bits(1 << 55);
        assert!(!upper.is_valid_for_read());
    }
}
