//! ZARC entry index records and binary encoding.
//!
//! Each entry in a `.zarc` archive is described by an [`EntryRecord`] stored
//! in the Footer Index TLV (`TLV_ZARC_INDEX = 0x0100`).
//!
//! Wire format of one `EntryRecord` (all integers little-endian):
//!
//! ```text
//! Offset  Size   Field
//! 0       1      entry_kind: 0 = regular file, 1 = directory
//! 1       1      compression: 0 = Store, 1 = Zstd, 2 = LZ4
//! 2       2      flags (u16, reserved = 0 in v1.0)
//! 4       4      unix_mode (u32, e.g. 0o644 or 0o755; 0 if unspecified)
//! 8       8      mtime_unix_secs (i64, UTC seconds since Unix epoch)
//! 16      8      uncompressed_size (u64)
//! 24      8      stored_size (u64, bytes in payload section)
//! 32      8      payload_rel_offset (u64, offset relative to payload start)
//! 40      32     blake3_hash ([u8; 32], BLAKE3 of uncompressed file data)
//! 72      24     entry_nonce ([u8; 24], XChaCha20-Poly1305 nonce if encrypted, else 0)
//! 96      2      path_len (u16, UTF-8 byte length)
//! 98      N      path (UTF-8 canonical relative path, no NUL)
//! ```
//!
//! Fixed prefix size: 98 bytes (`ENTRY_FIXED_LEN`).

use znf_compression::Algorithm;
use znf_crypto::NONCE_LEN;
use znf_integrity::{Hash, HASH_LEN};

use crate::error::ZarcError;
use crate::path::validate_archive_path;

/// Fixed prefix size of an encoded [`EntryRecord`].
pub const ENTRY_FIXED_LEN: usize = 98;

/// Maximum number of entries allowed in a single archive by default.
pub const DEFAULT_MAX_ENTRIES: usize = 1_000_000;

/// Kind of archive entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// Reserved entry flags (0 in v1.0).
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
}

impl EntryRecord {
    /// Append this record's deterministic binary representation to `out`.
    ///
    /// # Errors
    ///
    /// Returns [`ZarcError`] if the path is invalid or exceeds `u16::MAX`.
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), ZarcError> {
        let canonical = validate_archive_path(&self.path)?;
        let path_bytes = canonical.as_bytes();
        if path_bytes.len() > u16::MAX as usize {
            return Err(ZarcError::MalformedArchive("path too long for u16".into()));
        }
        if self.flags != 0 {
            return Err(ZarcError::MalformedArchive(
                "reserved entry flags must be zero".into(),
            ));
        }

        out.push(self.kind as u8);
        out.push(self.compression.as_byte());
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&self.unix_mode.to_le_bytes());
        out.extend_from_slice(&self.mtime_unix_secs.to_le_bytes());
        out.extend_from_slice(&self.uncompressed_size.to_le_bytes());
        out.extend_from_slice(&self.stored_size.to_le_bytes());
        out.extend_from_slice(&self.payload_rel_offset.to_le_bytes());
        out.extend_from_slice(self.blake3_hash.as_bytes());
        out.extend_from_slice(&self.entry_nonce);
        out.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(path_bytes);
        Ok(())
    }

    /// Decode one record from `buf`, returning `(record, bytes_consumed)`.
    ///
    /// # Errors
    ///
    /// Returns [`ZarcError`] on truncation, invalid UTF-8, or unsafe path.
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

        let total_len = ENTRY_FIXED_LEN
            .checked_add(path_len)
            .ok_or_else(|| ZarcError::MalformedArchive("entry length overflow".into()))?;
        if buf.len() < total_len {
            return Err(ZarcError::MalformedArchive(
                "entry path truncated in index".into(),
            ));
        }
        let raw_path = std::str::from_utf8(&buf[ENTRY_FIXED_LEN..total_len])
            .map_err(|_| crate::path::PathError::InvalidUtf8)?;
        let path = validate_archive_path(raw_path)?;

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
            },
            total_len,
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
    // Cap initial allocation to what the buffer could possibly hold.
    let max_possible = (buf.len() - 4) / ENTRY_FIXED_LEN;
    if count > max_possible {
        return Err(ZarcError::MalformedArchive(format!(
            "declared entry count {count} impossible in {}-byte index",
            buf.len()
        )));
    }

    let mut entries = Vec::with_capacity(count);
    let mut seen = std::collections::HashSet::with_capacity(count);
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
    fn entry_index_roundtrip() {
        let rec = EntryRecord {
            path: "docs/readme.txt".to_string(),
            kind: EntryKind::File,
            compression: Algorithm::Zstd,
            flags: 0,
            unix_mode: 0o644,
            mtime_unix_secs: 1_700_000_000,
            uncompressed_size: 42,
            stored_size: 50,
            payload_rel_offset: 0,
            blake3_hash: znf_integrity::hash(b"hello"),
            entry_nonce: [7u8; NONCE_LEN],
        };
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
