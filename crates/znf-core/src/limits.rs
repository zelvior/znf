//! Configurable resource limits.
//!
//! Every parser in ZNF validates lengths against these limits before
//! allocating or reading. Limits protect against decompression bombs,
//! memory exhaustion, and malformed headers. Defaults are conservative
//! but generous enough for legitimate use; applications handling
//! untrusted input should tighten them.

/// Resource limits for parsing ZNF files.
///
/// All limits are in bytes unless noted. A limit of `u64::MAX` means
/// "no explicit limit" (still bounded by file size and `usize`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum total header size (fixed header + extensions).
    pub max_header_len: u64,
    /// Maximum metadata section size.
    pub max_metadata_len: u64,
    /// Maximum single TLV value length.
    pub max_tlv_len: u64,
    /// Maximum payload length.
    pub max_payload_len: u64,
    /// Maximum expanded (decompressed) size for bomb protection.
    pub max_expanded_len: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_header_len: 1024 * 1024,        // 1 MiB
            max_metadata_len: 16 * 1024 * 1024, // 16 MiB
            max_tlv_len: 16 * 1024 * 1024,      // 16 MiB
            max_payload_len: u64::MAX,
            max_expanded_len: 10 * 1024 * 1024 * 1024, // 10 GiB
        }
    }
}

impl Limits {
    /// Strict limits for untrusted input (e.g. network-facing parsers).
    #[must_use]
    pub fn strict() -> Self {
        Limits {
            max_header_len: 64 * 1024,
            max_metadata_len: 1024 * 1024,
            max_tlv_len: 1024 * 1024,
            max_payload_len: 1024 * 1024 * 1024,  // 1 GiB
            max_expanded_len: 1024 * 1024 * 1024, // 1 GiB
        }
    }

    /// Check that `len` does not exceed `limit`, returning a typed error.
    pub fn check(&self, what: &'static str, len: u64, limit: u64) -> Result<(), crate::Error> {
        if len > limit {
            return Err(crate::Error::LengthExceedsLimit { what, len, limit });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_sane() {
        let l = Limits::default();
        assert!(l.max_header_len >= 64);
        assert!(l.max_metadata_len >= l.max_header_len);
        assert!(l.max_tlv_len <= l.max_metadata_len);
    }

    #[test]
    fn check_rejects_over_limit() {
        let l = Limits::default();
        assert!(l.check("header", 100, 1000).is_ok());
        assert!(l.check("header", 2000, 1000).is_err());
    }
}
