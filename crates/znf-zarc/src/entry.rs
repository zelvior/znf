//! ZARC entry index records and binary encoding.
//!
//! Each entry in a `.zarc` archive is described by an [`EntryRecord`] stored
//! in the Footer Index TLV (`TLV_ZARC_INDEX = 0x0100` or
//! `TLV_ZARC_ENCRYPTED_INDEX = 0x0101`).
//!
//! Wire format of one `EntryRecord` (all integers little-endian):
//!
//! ```text
//! Offset  Size   Field
//! 0       1      entry_kind: 0 = regular file, 1 = directory
//! 1       1      compression: 0 = Store, 1 = Zstd, 2 = LZ4
//! 2       2      flags (u16 LE):
//!                  bit 0 (0x0001) = ENTRY_FLAG_ENCRYPTED
//!                  bit 1 (0x0002) = ENTRY_FLAG_HAS_USER_METADATA
//!                  bits 2..=15    = reserved (must be 0 in v1.0)
//! 4       4      unix_mode (u32 LE, e.g. 0o644 or 0o755; 0 if unspecified)
//! 8       8      mtime_unix_secs (i64 LE, UTC seconds since Unix epoch)
//! 16      8      uncompressed_size (u64 LE)
//! 24      8      stored_size (u64 LE, bytes in payload section)
//! 32      8      payload_rel_offset (u64 LE, offset relative to payload start)
//! 40      32     blake3_hash ([u8; 32], BLAKE3 of uncompressed file data)
//! 72      24     entry_nonce ([u8; 24], XChaCha20-Poly1305 nonce if encrypted, else 0)
//! 96      2      path_len (u16 LE, UTF-8 byte length)
//! 98      N      path (UTF-8 canonical relative path, no NUL)
//! [Optional, present iff flags & ENTRY_FLAG_HAS_USER_METADATA != 0]:
//! 98+N    2      meta_count (u16 LE)
//! ...     M      meta_count sorted (key_len: u16 LE, key_utf8, val_len: u16 LE, val_utf8)
//! ```
//!
//! Fixed prefix size: 98 bytes (`ENTRY_FIXED_LEN`).

use std::collections::{BTreeMap, HashSet};

use znf_compression::Algorithm;
use znf_crypto::NONCE_LEN;
use znf_integrity::{Hash, HASH_LEN};

use crate::error::ZarcError;
use crate::path::validate_archive_path;

/// Fixed prefix size of an encoded [`EntryRecord`].
pub const ENTRY_FIXED_LEN: usize = 98;

/// Maximum number of entries allowed in a single archive by default.
pub const DEFAULT_MAX_ENTRIES: usize = 1_000_000;

/// Entry flag bit 0: entry payload is encrypted with `XChaCha20-Poly1305`.
pub const ENTRY_FLAG_ENCRYPTED: u16 = 1 << 0;

/// Entry flag bit 1: entry record includes trailing user-defined metadata key-value pairs.
pub const ENTRY_FLAG_HAS_USER_METADATA: u16 = 1 << 1;

/// Mask of defined entry flags in ZARC v1.0.
pub const ENTRY_FLAGS_DEFINED_MASK: u16 = ENTRY_FLAG_ENCRYPTED | ENTRY_FLAG_HAS_USER_METADATA;

/// Kind of archive entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EntryKind {
    /// Regular file.
    File = 0,
    /// Directory.
    Directory = 1,
}

impl EntryKind {
    /// Parse from byte.
    pub fn from_byte(b: u8) -> Result<Self, ZarcError> {
        match b {
            0 => Ok(EntryKind::File),
            1 => Ok(EntryKind::Directory),
            other => Err(ZarcError::MalformedArchive(format!(
                "unknown entry kind: {other}"
            ))),
        }
    }
}

/// Metadata and location record for a single entry in a `.zarc` archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryRecord {
    /// Canonical relative UTF-8 path (`a/b/c.txt`).
    pub path: String,
    /// File or directory.
    pub kind: EntryKind,
    /// Compression algorithm used for this entry's payload.
    pub compression: Algorithm,
    /// Entry flags (`ENTRY_FLAG_ENCRYPTED`, `ENTRY_FLAG_HAS_USER_METADATA`).
    pub flags: u16,
    /// POSIX permission bits (e.g. `0o644` or `0o755`), or 0 if not recorded.
    pub unix_mode: u32,
    /// Modification time in UTC seconds since Unix epoch.
    pub mtime_unix_secs: i64,
    /// Original uncompressed byte length.
    pub uncompressed_size: u64,
    /// Stored byte length in the payload section (after compression and AEAD tag).
    pub stored_size: u64,
    /// Byte offset of this entry's stored data relative to `header.payload_offset()`.
    pub payload_rel_offset: u64,
    /// BLAKE3 digest of the original uncompressed bytes (all-zero for directories).
    pub blake3_hash: Hash,
    /// Per-entry 24-byte nonce when archive is encrypted; all-zero when unencrypted.
    pub entry_nonce: [u8; NONCE_LEN],
    /// Optional user-defined UTF-8 key-value metadata for this entry.
    pub user_metadata: BTreeMap<String, String>,
}

impl EntryRecord {
    /// Original file or directory name (final component of `self.path`).
    #[must_use]
    pub fn file_name(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }

    /// Directory depth (number of `/` path components).
    #[must_use]
    pub fn depth(&self) -> usize {
        self.path.split('/').count()
    }

    /// Whether this entry's payload is encrypted.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        (self.flags & ENTRY_FLAG_ENCRYPTED != 0) || self.entry_nonce.iter().any(|&b| b != 0)
    }

    /// Append this record's deterministic binary representation to `out`.
    ///
    /// # Errors
    ///
    /// Returns [`ZarcError`] if the path is invalid, flags contain undefined bits,
    /// or lengths exceed `u16::MAX`.
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), ZarcError> {
        let canonical = validate_archive_path(&self.path)?;
        let path_bytes = canonical.as_bytes();
        if path_bytes.len() > u16::MAX as usize {
            return Err(ZarcError::MalformedArchive("path too long for u16".into()));
        }
        if self.flags & !ENTRY_FLAGS_DEFINED_MASK != 0 {
            return Err(ZarcError::MalformedArchive(format!(
                "reserved entry flags must be zero: {:#06x}",
                self.flags
            )));
        }
        let mut effective_flags = self.flags;
        if !self.user_metadata.is_empty() {
            effective_flags |= ENTRY_FLAG_HAS_USER_METADATA;
        } else {
            effective_flags &= !ENTRY_FLAG_HAS_USER_METADATA;
        }

        out.push(self.kind as u8);
        out.push(self.compression.as_byte());
        out.extend_from_slice(&effective_flags.to_le_bytes());
        out.extend_from_slice(&self.unix_mode.to_le_bytes());
        out.extend_from_slice(&self.mtime_unix_secs.to_le_bytes());
        out.extend_from_slice(&self.uncompressed_size.to_le_bytes());
        out.extend_from_slice(&self.stored_size.to_le_bytes());
        out.extend_from_slice(&self.payload_rel_offset.to_le_bytes());
        out.extend_from_slice(self.blake3_hash.as_bytes());
        out.extend_from_slice(&self.entry_nonce);
        out.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(path_bytes);

        if !self.user_metadata.is_empty() {
            if self.user_metadata.len() > u16::MAX as usize {
                return Err(ZarcError::MalformedArchive(
                    "too many user metadata entries".into(),
                ));
            }
            out.extend_from_slice(&(self.user_metadata.len() as u16).to_le_bytes());
            for (k, v) in &self.user_metadata {
                let kb = k.as_bytes();
                let vb = v.as_bytes();
                if kb.is_empty() || kb.len() > u16::MAX as usize || vb.len() > u16::MAX as usize {
                    return Err(ZarcError::MalformedArchive(
                        "user metadata key/value length out of bounds".into(),
                    ));
                }
                out.extend_from_slice(&(kb.len() as u16).to_le_bytes());
                out.extend_from_slice(kb);
                out.extend_from_slice(&(vb.len() as u16).to_le_bytes());
                out.extend_from_slice(vb);
            }
        }
        Ok(())
    }

    /// Decode one record from `buf`, returning `(record, bytes_consumed)`.
    ///
    /// # Errors
    ///
    /// Returns [`ZarcError`] on truncation, invalid UTF-8, unknown flags, or unsafe path.
    pub fn decode_one(buf: &[u8]) -> Result<(Self, usize), ZarcError> {
        if buf.len() < ENTRY_FIXED_LEN {
            return Err(ZarcError::MalformedArchive(format!(
                "entry record truncated: need {ENTRY_FIXED_LEN}, have {}",
                buf.len()
            )));
        }
        let kind = EntryKind::from_byte(buf[0])?;
        let compression = Algorithm::from_byte(buf[1])?;
        let flags = u16::from_le_bytes(buf[2..4].try_into().unwrap());
        if flags & !ENTRY_FLAGS_DEFINED_MASK != 0 {
            return Err(ZarcError::MalformedArchive(format!(
                "unsupported critical entry flags: {flags:#06x}"
            )));
        }
        let unix_mode = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let mtime_unix_secs = i64::from_le_bytes(buf[8..16].try_into().unwrap());
        let uncompressed_size = u64::from_le_bytes(buf[16..24].try_into().unwrap());
        let stored_size = u64::from_le_bytes(buf[24..32].try_into().unwrap());
        let payload_rel_offset = u64::from_le_bytes(buf[32..40].try_into().unwrap());
        let mut hash_bytes = [0u8; HASH_LEN];
        hash_bytes.copy_from_slice(&buf[40..72]);
        let mut entry_nonce = [0u8; NONCE_LEN];
        entry_nonce.copy_from_slice(&buf[72..96]);
        let path_len = u16::from_le_bytes(buf[96..98].try_into().unwrap()) as usize;

        let path_end = ENTRY_FIXED_LEN
            .checked_add(path_len)
            .ok_or_else(|| ZarcError::MalformedArchive("entry length overflow".into()))?;
        if buf.len() < path_end {
            return Err(ZarcError::MalformedArchive(
                "entry path truncated in index".into(),
            ));
        }
        let raw_path = std::str::from_utf8(&buf[ENTRY_FIXED_LEN..path_end])
            .map_err(|_| crate::path::PathError::InvalidUtf8)?;
        let path = validate_archive_path(raw_path)?;

        let mut offset = path_end;
        let mut user_metadata = BTreeMap::new();
        if flags & ENTRY_FLAG_HAS_USER_METADATA != 0 {
            if buf.len() < offset + 2 {
                return Err(ZarcError::MalformedArchive(
                    "truncated entry user metadata count".into(),
                ));
            }
            let count = u16::from_le_bytes(buf[offset..offset + 2].try_into().unwrap()) as usize;
            offset += 2;
            for _ in 0..count {
                if buf.len() < offset + 2 {
                    return Err(ZarcError::MalformedArchive(
                        "truncated entry user metadata key len".into(),
                    ));
                }
                let klen = u16::from_le_bytes(buf[offset..offset + 2].try_into().unwrap()) as usize;
                offset += 2;
                if klen == 0 || buf.len() < offset + klen + 2 {
                    return Err(ZarcError::MalformedArchive(
                        "truncated entry user metadata key".into(),
                    ));
                }
                let key = std::str::from_utf8(&buf[offset..offset + klen])
                    .map_err(|_| crate::path::PathError::InvalidUtf8)?
                    .to_string();
                offset += klen;

                let vlen = u16::from_le_bytes(buf[offset..offset + 2].try_into().unwrap()) as usize;
                offset += 2;
                if buf.len() < offset + vlen {
                    return Err(ZarcError::MalformedArchive(
                        "truncated entry user metadata value".into(),
                    ));
                }
                let val = std::str::from_utf8(&buf[offset..offset + vlen])
                    .map_err(|_| crate::path::PathError::InvalidUtf8)?
                    .to_string();
                offset += vlen;

                if user_metadata.insert(key, val).is_some() {
                    return Err(ZarcError::MalformedArchive(
                        "duplicate key in entry user metadata".into(),
                    ));
                }
            }
        }

        Ok((
            EntryRecord {
                path,
                kind,
                compression,
                flags,
                unix_mode,
                mtime_unix_secs,
                uncompressed_size,
                stored_size,
                payload_rel_offset,
                blake3_hash: Hash::from_bytes(hash_bytes),
                entry_nonce,
                user_metadata,
            },
            offset,
        ))
    }
}

/// Encode a slice of [`EntryRecord`]s into a ZARC index table (`u32` entry count + records).
///
/// # Errors
///
/// Returns [`ZarcError`] if any record fails validation.
pub fn encode_index(entries: &[EntryRecord]) -> Result<Vec<u8>, ZarcError> {
    if entries.len() > u32::MAX as usize {
        return Err(ZarcError::ResourceLimitExceeded(
            "too many entries for u32 count".into(),
        ));
    }
    let mut out = Vec::with_capacity(4 + entries.len() * 128);
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for entry in entries {
        entry.encode_into(&mut out)?;
    }
    Ok(out)
}

/// Decode a ZARC index table (`u32` entry count + records), enforcing `max_entries`.
///
/// # Errors
///
/// Returns [`ZarcError`] on truncation, duplicate paths, or limit violation.
pub fn decode_index(buf: &[u8], max_entries: usize) -> Result<Vec<EntryRecord>, ZarcError> {
    if buf.len() < 4 {
        return Err(ZarcError::MalformedArchive(
            "index table shorter than 4-byte count".into(),
        ));
    }
    let count = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
    if count > max_entries {
        return Err(ZarcError::ResourceLimitExceeded(format!(
            "entry count {count} exceeds limit {max_entries}"
        )));
    }
    let max_possible = (buf.len() - 4) / ENTRY_FIXED_LEN;
    if count > max_possible {
        return Err(ZarcError::MalformedArchive(format!(
            "declared entry count {count} impossible in {}-byte index",
            buf.len()
        )));
    }

    let mut entries = Vec::with_capacity(count);
    let mut seen = HashSet::with_capacity(count);
    let mut offset = 4;
    for _ in 0..count {
        let (rec, used) = EntryRecord::decode_one(&buf[offset..])?;
        if !seen.insert(rec.path.clone()) {
            return Err(ZarcError::DuplicateEntry(rec.path));
        }
        entries.push(rec);
        offset += used;
    }
    if offset != buf.len() {
        return Err(ZarcError::MalformedArchive(
            "trailing bytes in index table".into(),
        ));
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_index_roundtrip_with_user_metadata() {
        let mut user_metadata = BTreeMap::new();
        user_metadata.insert("mime".to_string(), "text/plain".to_string());
        user_metadata.insert("author".to_string(), "Zelvior Labs".to_string());

        let rec = EntryRecord {
            path: "docs/readme.txt".to_string(),
            kind: EntryKind::File,
            compression: Algorithm::Zstd,
            flags: ENTRY_FLAG_ENCRYPTED | ENTRY_FLAG_HAS_USER_METADATA,
            unix_mode: 0o644,
            mtime_unix_secs: 1_700_000_000,
            uncompressed_size: 42,
            stored_size: 50,
            payload_rel_offset: 0,
            blake3_hash: znf_integrity::hash(b"hello"),
            entry_nonce: [7u8; NONCE_LEN],
            user_metadata,
        };
        assert_eq!(rec.file_name(), "readme.txt");
        assert!(rec.is_encrypted());

        let bytes = encode_index(std::slice::from_ref(&rec)).unwrap();
        let decoded = decode_index(&bytes, 100).unwrap();
        assert_eq!(decoded, vec![rec]);
    }

    #[test]
    fn rejects_impossible_entry_count() {
        let mut bad = Vec::new();
        bad.extend_from_slice(&999_999u32.to_le_bytes());
        assert!(decode_index(&bad, 1_000_000).is_err());
    }
}
