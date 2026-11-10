//! Structured metadata encoding, decoding, extension preservation, and BLAKE3 integrity.
//!
//! The ZNF Core Metadata Section (`header_len..payload_offset`) is a sequence of
//! TLV records terminated by `TLV_END (0xFFFF)`.
//!
//! Standard Core Metadata TLV Types:
//! - `0x0001` (`TLV_CORE_ATTRIBUTES`): Deterministic nested key-value map (`BTreeMap<String, MetadataValue>`).
//! - `0x0010` (`TLV_KDF_PARAMS`): 28-byte Argon2id key derivation parameters.
//! - `0x0011` (`TLV_PAYLOAD_NONCE`): 24-byte `XChaCha20-Poly1305` base nonce.
//! - `0x0020` (`TLV_COMMENT`): Optional UTF-8 comment string.
//! - `0x0030` (`TLV_METADATA_BLAKE3`): 32-byte BLAKE3 hash over all preceding bytes in the metadata section
//!   (`metadata_bytes[0..tlv_start_offset]`), avoiding circular hashing.
//! - `0x4000..=0x6FFF`: Critical extensions (rejected if unrecognized).
//! - `0x7000..=0xFFFE`: Non-critical extensions (preserved verbatim in `unknown_extensions`).

use std::collections::BTreeMap;

use znf_crypto::{KdfParams, NONCE_LEN};
use znf_integrity::{hash, Hash, HASH_LEN};

use crate::error::ZnfError;
use crate::limits::Limits;
use crate::tlv::{is_critical_extension_type, TlvReader, TlvWriter, TLV_END, TLV_RESERVED};

/// TLV type: Structured key-value metadata map (`BTreeMap<String, MetadataValue>`).
pub const TLV_CORE_ATTRIBUTES: u16 = 0x0001;
/// TLV type: Argon2id KDF parameters (`28` bytes).
pub const TLV_KDF_PARAMS: u16 = 0x0010;
/// TLV type: 24-byte `XChaCha20-Poly1305` payload nonce.
pub const TLV_PAYLOAD_NONCE: u16 = 0x0011;
/// TLV type: Optional UTF-8 comment string.
pub const TLV_COMMENT: u16 = 0x0020;
/// TLV type: 32-byte BLAKE3 digest over all preceding metadata TLV bytes.
pub const TLV_METADATA_BLAKE3: u16 = 0x0030;

/// Maximum nesting depth for structured [`MetadataValue`] trees.
pub const MAX_METADATA_DEPTH: usize = 16;

///Maximum number of entries in a single metadata map or list.
pub const MAX_METADATA_COLLECTION_LEN: usize = 65_536;

/// Strongly-typed metadata value supporting Unicode strings, binary data,
/// integers, booleans, and nested lists/maps with deterministic binary encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataValue {
    /// UTF-8 Unicode string (`tag = 1`).
    Text(String),
    /// Arbitrary binary byte slice (`tag = 2`).
    Bytes(Vec<u8>),
    /// Unsigned 64-bit integer (`tag = 3`, little-endian).
    Uint(u64),
    /// Signed 64-bit integer (`tag = 4`, little-endian).
    Int(i64),
    /// Boolean (`tag = 5`, `0u8` or `1u8`).
    Bool(bool),
    /// Ordered list of nested values (`tag = 6`).
    List(Vec<MetadataValue>),
    /// Deterministically sorted UTF-8 key -> value map (`tag = 7`).
    Map(BTreeMap<String, MetadataValue>),
}

impl MetadataValue {
    fn encode_into(
        &self,
        out: &mut Vec<u8>,
        depth: usize,
        limits: &Limits,
    ) -> Result<(), ZnfError> {
        if depth > MAX_METADATA_DEPTH {
            return Err(ZnfError::InvalidMetadata(format!(
                "metadata nesting depth exceeds maximum {MAX_METADATA_DEPTH}"
            )));
        }
        match self {
            MetadataValue::Text(s) => {
                let bytes = s.as_bytes();
                limits.check("metadata string", bytes.len() as u64, limits.max_tlv_len)?;
                out.push(1);
                out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                out.extend_from_slice(bytes);
            }
            MetadataValue::Bytes(b) => {
                limits.check("metadata bytes", b.len() as u64, limits.max_tlv_len)?;
                out.push(2);
                out.extend_from_slice(&(b.len() as u32).to_le_bytes());
                out.extend_from_slice(b);
            }
            MetadataValue::Uint(v) => {
                out.push(3);
                out.extend_from_slice(&v.to_le_bytes());
            }
            MetadataValue::Int(v) => {
                out.push(4);
                out.extend_from_slice(&v.to_le_bytes());
            }
            MetadataValue::Bool(b) => {
                out.push(5);
                out.push(u8::from(*b));
            }
            MetadataValue::List(items) => {
                if items.len() > MAX_METADATA_COLLECTION_LEN {
                    return Err(ZnfError::InvalidMetadata(
                        "metadata list exceeds max collection length".into(),
                    ));
                }
                out.push(6);
                out.extend_from_slice(&(items.len() as u32).to_le_bytes());
                for item in items {
                    item.encode_into(out, depth + 1, limits)?;
                }
            }
            MetadataValue::Map(map) => {
                if map.len() > MAX_METADATA_COLLECTION_LEN {
                    return Err(ZnfError::InvalidMetadata(
                        "metadata map exceeds max collection length".into(),
                    ));
                }
                out.push(7);
                encode_btree_map(map, out, depth + 1, limits)?;
            }
        }
        Ok(())
    }

    fn decode_from(
        buf: &[u8],
        offset: &mut usize,
        depth: usize,
        limits: &Limits,
    ) -> Result<Self, ZnfError> {
        if depth > MAX_METADATA_DEPTH {
            return Err(ZnfError::InvalidMetadata(format!(
                "metadata nesting depth exceeds maximum {MAX_METADATA_DEPTH}"
            )));
        }
        if *offset >= buf.len() {
            return Err(ZnfError::InvalidMetadata(
                "unexpected EOF reading metadata value tag".into(),
            ));
        }
        let tag = buf[*offset];
        *offset += 1;
        match tag {
            1 => {
                let len = read_u32_le(buf, offset)? as usize;
                limits.check("metadata string", len as u64, limits.max_tlv_len)?;
                let slice = read_slice(buf, offset, len)?;
                let s = std::str::from_utf8(slice).map_err(|_| {
                    ZnfError::InvalidMetadata("invalid UTF-8 in metadata Text value".into())
                })?;
                Ok(MetadataValue::Text(s.to_string()))
            }
            2 => {
                let len = read_u32_le(buf, offset)? as usize;
                limits.check("metadata bytes", len as u64, limits.max_tlv_len)?;
                let slice = read_slice(buf, offset, len)?;
                Ok(MetadataValue::Bytes(slice.to_vec()))
            }
            3 => {
                let slice = read_slice(buf, offset, 8)?;
                Ok(MetadataValue::Uint(u64::from_le_bytes(
                    slice.try_into().unwrap(),
                )))
            }
            4 => {
                let slice = read_slice(buf, offset, 8)?;
                Ok(MetadataValue::Int(i64::from_le_bytes(
                    slice.try_into().unwrap(),
                )))
            }
            5 => {
                let slice = read_slice(buf, offset, 1)?;
                match slice[0] {
                    0 => Ok(MetadataValue::Bool(false)),
                    1 => Ok(MetadataValue::Bool(true)),
                    other => Err(ZnfError::InvalidMetadata(format!(
                        "invalid boolean byte in metadata: {other}"
                    ))),
                }
            }
            6 => {
                let count = read_u32_le(buf, offset)? as usize;
                if count > MAX_METADATA_COLLECTION_LEN || count > (buf.len() - *offset) {
                    return Err(ZnfError::InvalidMetadata(format!(
                        "invalid metadata list count: {count}"
                    )));
                }
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    items.push(Self::decode_from(buf, offset, depth + 1, limits)?);
                }
                Ok(MetadataValue::List(items))
            }
            7 => {
                let map = decode_btree_map(buf, offset, depth + 1, limits)?;
                Ok(MetadataValue::Map(map))
            }
            other => Err(ZnfError::InvalidMetadata(format!(
                "unknown metadata value tag: {other}"
            ))),
        }
    }
}

fn encode_btree_map(
    map: &BTreeMap<String, MetadataValue>,
    out: &mut Vec<u8>,
    depth: usize,
    limits: &Limits,
) -> Result<(), ZnfError> {
    if map.len() > MAX_METADATA_COLLECTION_LEN {
        return Err(ZnfError::InvalidMetadata(
            "metadata map exceeds max collection length".into(),
        ));
    }
    out.extend_from_slice(&(map.len() as u32).to_le_bytes());
    for (k, v) in map {
        let kb = k.as_bytes();
        if kb.is_empty() || kb.len() > u16::MAX as usize {
            return Err(ZnfError::InvalidMetadata(
                "metadata key must be 1..=65535 UTF-8 bytes".into(),
            ));
        }
        out.extend_from_slice(&(kb.len() as u16).to_le_bytes());
        out.extend_from_slice(kb);
        v.encode_into(out, depth, limits)?;
    }
    Ok(())
}

fn decode_btree_map(
    buf: &[u8],
    offset: &mut usize,
    depth: usize,
    limits: &Limits,
) -> Result<BTreeMap<String, MetadataValue>, ZnfError> {
    let count = read_u32_le(buf, offset)? as usize;
    // Each entry requires at least 2 bytes (key_len) + 1 byte (key) + 2 bytes (val).
    if count > MAX_METADATA_COLLECTION_LEN || count > (buf.len() - *offset) / 4 {
        return Err(ZnfError::InvalidMetadata(format!(
            "impossible metadata map entry count: {count}"
        )));
    }
    let mut map = BTreeMap::new();
    for _ in 0..count {
        let klen_slice = read_slice(buf, offset, 2)?;
        let klen = u16::from_le_bytes(klen_slice.try_into().unwrap()) as usize;
        if klen == 0 {
            return Err(ZnfError::InvalidMetadata(
                "empty key in metadata map".into(),
            ));
        }
        let k_slice = read_slice(buf, offset, klen)?;
        let key = std::str::from_utf8(k_slice)
            .map_err(|_| ZnfError::InvalidMetadata("invalid UTF-8 in metadata map key".into()))?
            .to_string();
        let val = MetadataValue::decode_from(buf, offset, depth, limits)?;
        if map.insert(key.clone(), val).is_some() {
            return Err(ZnfError::InvalidMetadata(format!(
                "duplicate metadata key: {key}"
            )));
        }
    }
    Ok(map)
}

fn read_u32_le(buf: &[u8], offset: &mut usize) -> Result<u32, ZnfError> {
    let s = read_slice(buf, offset, 4)?;
    Ok(u32::from_le_bytes(s.try_into().unwrap()))
}

fn read_slice<'a>(buf: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8], ZnfError> {
    let end = offset
        .checked_add(len)
        .ok_or(ZnfError::IntegerOverflow("metadata slice"))?;
    if end > buf.len() {
        return Err(ZnfError::InvalidMetadata("truncated metadata value".into()));
    }
    let s = &buf[*offset..end];
    *offset = end;
    Ok(s)
}

/// Structured ZNF Core metadata container.
///
/// Supports typed key-value attributes (including Unicode and nested maps/lists),
/// optional comment, cryptographic parameters (`KdfParams`, `payload_nonce`),
/// non-critical extension preservation (`unknown_extensions`), and non-circular
/// BLAKE3 integrity verification (`metadata_blake3`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ZnfMetadata {
    /// Structured key-value attributes (`TLV_CORE_ATTRIBUTES = 0x0001`).
    pub attributes: BTreeMap<String, MetadataValue>,
    /// Optional human-readable UTF-8 comment (`TLV_COMMENT = 0x0020`).
    pub comment: Option<String>,
    /// Optional Argon2id KDF parameters (`TLV_KDF_PARAMS = 0x0010`).
    pub kdf_params: Option<KdfParams>,
    /// Optional 24-byte `XChaCha20-Poly1305` payload nonce (`TLV_PAYLOAD_NONCE = 0x0011`).
    pub payload_nonce: Option<[u8; NONCE_LEN]>,
    /// Preserved non-critical extension TLVs (`0x7000..=0xFFFE`).
    pub unknown_extensions: Vec<(u16, Vec<u8>)>,
    /// Verified or computed BLAKE3 digest over the metadata TLVs preceding `TLV_METADATA_BLAKE3`.
    pub metadata_blake3: Option<Hash>,
}

impl ZnfMetadata {
    /// Create an empty metadata structure.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if no attributes, comment, crypto parameters, or extensions are set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.attributes.is_empty()
            && self.comment.is_none()
            && self.kdf_params.is_none()
            && self.payload_nonce.is_none()
            && self.unknown_extensions.is_empty()
    }

    /// Insert a UTF-8 text attribute.
    pub fn insert_text(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.attributes
            .insert(key.into(), MetadataValue::Text(value.into()));
    }

    /// Insert a binary attribute.
    pub fn insert_bytes(&mut self, key: impl Into<String>, value: Vec<u8>) {
        self.attributes
            .insert(key.into(), MetadataValue::Bytes(value));
    }

    /// Insert an unsigned integer attribute.
    pub fn insert_uint(&mut self, key: impl Into<String>, value: u64) {
        self.attributes
            .insert(key.into(), MetadataValue::Uint(value));
    }

    /// Insert an arbitrary [`MetadataValue`] (such as a nested `Map` or `List`).
    pub fn insert(&mut self, key: impl Into<String>, value: MetadataValue) {
        self.attributes.insert(key.into(), value);
    }

    /// Retrieve an attribute by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&MetadataValue> {
        self.attributes.get(key)
    }

    /// Add a non-critical extension TLV (`0x7000..=0xFFFE`).
    ///
    /// # Errors
    ///
    /// Returns [`ZnfError`] if `ty` is reserved (`0x0000` or `0xFFFF`).
    pub fn push_extension(&mut self, ty: u16, value: Vec<u8>) -> Result<(), ZnfError> {
        if ty == TLV_RESERVED || ty == TLV_END {
            return Err(ZnfError::ReservedTlvType(ty));
        }
        self.unknown_extensions.push((ty, value));
        Ok(())
    }

    /// Encode this metadata section into deterministic TLV bytes, automatically
    /// appending `TLV_METADATA_BLAKE3 (0x0030)` (computed over all preceding
    /// metadata TLV bytes) and `TLV_END (0xFFFF)`.
    ///
    /// If `self.is_empty()` is `true` and `always_emit` is `false`, returns an
    /// empty `Vec<u8>`.
    ///
    /// # Errors
    ///
    /// Returns [`ZnfError`] if any attribute or TLV exceeds `limits`.
    pub fn encode(&self, limits: &Limits) -> Result<Vec<u8>, ZnfError> {
        if self.is_empty() {
            return Ok(Vec::new());
        }
        let mut w = TlvWriter::new();
        if !self.attributes.is_empty() {
            let mut attr_bytes = Vec::new();
            encode_btree_map(&self.attributes, &mut attr_bytes, 0, limits)?;
            w.push(TLV_CORE_ATTRIBUTES, &attr_bytes, limits)?;
        }
        if let Some(ref kdf) = self.kdf_params {
            w.push(TLV_KDF_PARAMS, &kdf.encode(), limits)?;
        }
        if let Some(ref nonce) = self.payload_nonce {
            w.push(TLV_PAYLOAD_NONCE, nonce, limits)?;
        }
        if let Some(ref comment) = self.comment {
            w.push(TLV_COMMENT, comment.as_bytes(), limits)?;
        }
        for (ty, val) in &self.unknown_extensions {
            w.push(*ty, val, limits)?;
        }

        // Compute non-circular BLAKE3 digest over all preceding metadata TLV bytes.
        let digest = hash(w.as_bytes());
        w.push(TLV_METADATA_BLAKE3, digest.as_bytes(), limits)?;
        w.push_end();

        let bytes = w.into_bytes();
        limits.check("metadata", bytes.len() as u64, limits.max_metadata_len)?;
        Ok(bytes)
    }

    /// Decode and verify a metadata TLV section from `buf`.
    ///
    /// - Verifies `TLV_METADATA_BLAKE3 (0x0030)` (if present) against the exact
    ///   preceding bytes `buf[0..tlv.start_offset]`.
    /// - Rejects any unrecognized critical extension TLV (`0x4000..=0x6FFF`)
    ///   with [`ZnfError::UnsupportedCriticalExtension`].
    /// - Preserves unrecognized non-critical extension TLVs in `unknown_extensions`.
    /// - Requires `TLV_END (0xFFFF)` with no trailing unparsed bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ZnfError`] on corruption, truncation, invalid UTF-8, or unsupported
    /// critical extension.
    pub fn decode(buf: &[u8], limits: &Limits) -> Result<Self, ZnfError> {
        if buf.is_empty() {
            return Ok(ZnfMetadata::new());
        }
        limits.check("metadata", buf.len() as u64, limits.max_metadata_len)?;

        let mut reader = TlvReader::new(buf, *limits);
        let mut tlvs = Vec::new();
        let mut saw_end = false;

        while let Some(tlv) = reader.next_tlv()? {
            if tlv.is_end() {
                saw_end = true;
                break;
            }
            if tlv.ty == TLV_METADATA_BLAKE3 {
                if tlv.value.len() != HASH_LEN {
                    return Err(ZnfError::InvalidMetadata(
                        "invalid TLV_METADATA_BLAKE3 length".into(),
                    ));
                }
                let mut expected_bytes = [0u8; HASH_LEN];
                expected_bytes.copy_from_slice(tlv.value);
                let expected = Hash::from_bytes(expected_bytes);
                let computed = hash(&buf[..tlv.start_offset]);
                if computed != expected {
                    return Err(ZnfError::MetadataHashMismatch {
                        expected: expected.to_hex(),
                        computed: computed.to_hex(),
                    });
                }
            }
            tlvs.push(tlv);
        }

        if !saw_end {
            return Err(ZnfError::InvalidMetadata(
                "metadata section missing TLV_END marker".into(),
            ));
        }
        if reader.remaining() != 0 {
            return Err(ZnfError::InvalidMetadata(
                "trailing bytes after TLV_END in metadata section".into(),
            ));
        }

        let mut meta = ZnfMetadata::new();
        for tlv in tlvs {
            match tlv.ty {
                TLV_CORE_ATTRIBUTES => {
                    let mut off = 0;
                    let map = decode_btree_map(tlv.value, &mut off, 0, limits)?;
                    if off != tlv.value.len() {
                        return Err(ZnfError::InvalidMetadata(
                            "trailing bytes in TLV_CORE_ATTRIBUTES".into(),
                        ));
                    }
                    meta.attributes = map;
                }
                TLV_KDF_PARAMS => {
                    if tlv.value.len() != znf_crypto::KDF_PARAMS_LEN {
                        return Err(ZnfError::InvalidMetadata(format!(
                            "invalid TLV_KDF_PARAMS length: {}",
                            tlv.value.len()
                        )));
                    }
                    meta.kdf_params = Some(KdfParams::decode(tlv.value)?);
                }
                TLV_PAYLOAD_NONCE => {
                    if tlv.value.len() != NONCE_LEN {
                        return Err(ZnfError::InvalidMetadata(format!(
                            "invalid TLV_PAYLOAD_NONCE length: {}",
                            tlv.value.len()
                        )));
                    }
                    let mut n = [0u8; NONCE_LEN];
                    n.copy_from_slice(tlv.value);
                    meta.payload_nonce = Some(n);
                }
                TLV_COMMENT => {
                    let s = std::str::from_utf8(tlv.value).map_err(|_| {
                        ZnfError::InvalidMetadata("invalid UTF-8 in TLV_COMMENT".into())
                    })?;
                    meta.comment = Some(s.to_string());
                }
                TLV_METADATA_BLAKE3 => {
                    let mut expected_bytes = [0u8; HASH_LEN];
                    expected_bytes.copy_from_slice(tlv.value);
                    meta.metadata_blake3 = Some(Hash::from_bytes(expected_bytes));
                }
                other if is_critical_extension_type(other) => {
                    return Err(ZnfError::UnsupportedCriticalExtension(other));
                }
                other => {
                    meta.unknown_extensions.push((other, tlv.value.to_vec()));
                }
            }
        }
        Ok(meta)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unicode_and_nested_metadata_deterministic_roundtrip() {
        let limits = Limits::default();
        let mut m = ZnfMetadata::new();
        m.insert_text("title", "Zelvior Native Format — پاکستان / 日本語 / 🚀");
        m.insert_uint("revision", 42);
        m.insert_bytes("thumb", vec![0xDE, 0xAD, 0xBE, 0xEF]);

        let mut nested = BTreeMap::new();
        nested.insert(
            "author".to_string(),
            MetadataValue::Text("Zelvior Labs".into()),
        );
        nested.insert("lossless".to_string(), MetadataValue::Bool(true));
        nested.insert(
            "tags".to_string(),
            MetadataValue::List(vec![
                MetadataValue::Text("privacy".into()),
                MetadataValue::Int(-100),
            ]),
        );
        m.insert("nested_info", MetadataValue::Map(nested));
        m.comment = Some("unicode comment: سلام".into());
        m.push_extension(0x8001, b"preserved-vendor-ext".to_vec())
            .unwrap();

        let enc1 = m.encode(&limits).unwrap();
        let enc2 = m.encode(&limits).unwrap();
        assert_eq!(enc1, enc2, "encoding must be 100% deterministic");

        let dec = ZnfMetadata::decode(&enc1, &limits).unwrap();
        assert_eq!(dec.attributes, m.attributes);
        assert_eq!(dec.comment, m.comment);
        assert_eq!(dec.unknown_extensions, m.unknown_extensions);
        assert!(dec.metadata_blake3.is_some());
    }

    #[test]
    fn metadata_tampering_caught_by_blake3() {
        let limits = Limits::default();
        let mut m = ZnfMetadata::new();
        m.insert_text("key", "original-value");
        let mut enc = m.encode(&limits).unwrap();

        // Flip a byte inside the encoded attribute value.
        enc[15] ^= 0x01;
        let err = ZnfMetadata::decode(&enc, &limits).unwrap_err();
        assert!(matches!(err, ZnfError::MetadataHashMismatch { .. }));
    }

    #[test]
    fn critical_extension_rejected_in_metadata() {
        let limits = Limits::default();
        let mut w = TlvWriter::new();
        w.push(0x4001, b"unknown critical extension", &limits)
            .unwrap();
        w.push_end();
        let err = ZnfMetadata::decode(w.as_bytes(), &limits).unwrap_err();
        assert_eq!(err, ZnfError::UnsupportedCriticalExtension(0x4001));
    }
}
