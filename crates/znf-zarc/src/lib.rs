//! ZARC (`.zarc`) Archive Container Format.
//!
//! `znf-zarc` is the first production multi-entry archive format built on `znf-core`.
//! It provides:
//!
//! - Lossless file and directory archiving (`Store`, `Zstandard`, `LZ4`) with both
//!   global and per-entry compression configuration and statistics.
//! - Optional authenticated encryption (`XChaCha20-Poly1305` + `Argon2id`)
//!   covering file contents, the entry index (filenames, sizes, hashes, user metadata),
//!   and the archive comment (`TLV_ZARC_ENCRYPTED_METADATA`).
//! - Per-file and whole-archive `BLAKE3` integrity verification.
//! - Optional XOR block parity (`znf-recovery`) for single-block repair, plus
//!   per-entry corruption diagnosis and partial extraction of verified entries.
//! - Strict path traversal, UNC path, symlink, case-collision, directory-depth,
//!   overwrite, and decompression-bomb defenses.
//!
//! See `specifications/zarc/ZARC-SPEC.md` for the normative format specification.
//!
//! # Example
//!
//! ```
//! use znf_compression::Config as CompConfig;
//! use znf_zarc::{
//!     inspect_archive, ReadOptions, WriteOptions, ZarcArchive, ZarcWriter,
//! };
//!
//! let mut writer = ZarcWriter::new(WriteOptions {
//!     compression: CompConfig::zstd(3),
//!     comment: Some("example archive".into()),
//!     ..WriteOptions::default()
//! });
//! writer.add_directory("src", 0o755, 1_700_000_000).unwrap();
//! writer
//!     .add_bytes("src/lib.rs", b"pub fn hello() {}", 0o644, 1_700_000_001)
//!     .unwrap();
//!
//! let mut bytes = Vec::new();
//! writer.finish(&mut bytes).unwrap();
//!
//! let inspection = inspect_archive(&bytes, None, &znf_core::Limits::default()).unwrap();
//! assert_eq!(inspection.entries.len(), 2);
//!
//! let archive = ZarcArchive::open(&bytes, ReadOptions::default()).unwrap();
//! archive.verify_all().unwrap();
//! assert_eq!(
//!     archive.read_entry_bytes(&archive.entries()[1]).unwrap(),
//!     b"pub fn hello() {}"
//! );
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::all)]

pub mod archive;
pub mod entry;
pub mod error;
pub mod path;

pub use archive::{
    add_paths_to_archive_file, attempt_parity_repair, inspect_archive,
    remove_entries_from_archive_file, ArchiveProgress, CompressionStats, EntryDiagnosis,
    ExtractOptions, ReadOptions, RecoveryExtractionReport, WriteOptions, ZarcArchive,
    ZarcInspection, ZarcWriter, TLV_ARCHIVE_BLAKE3, TLV_COMMENT, TLV_KDF_PARAMS, TLV_PARITY_STRIPE,
    TLV_ZARC_ENCRYPTED_INDEX, TLV_ZARC_ENCRYPTED_METADATA, TLV_ZARC_INDEX,
};
pub use entry::{
    decode_index, encode_index, EntryKind, EntryRecord, DEFAULT_MAX_ENTRIES, ENTRY_FIXED_LEN,
    ENTRY_FLAGS_DEFINED_MASK, ENTRY_FLAG_ENCRYPTED, ENTRY_FLAG_HAS_USER_METADATA,
};
pub use error::ZarcError;
pub use path::{
    case_fold_path, normalize_fs_path, safe_join, safe_join_with_depth, validate_archive_path,
    validate_archive_path_with_depth, PathError, DEFAULT_MAX_DEPTH, MAX_COMPONENT_LEN,
    MAX_PATH_LEN,
};

/// ZARC specification version implemented by this crate.
pub const ZARC_SPEC_VERSION: (u16, u16) = (1, 0);

#[cfg(test)]
mod tests {
    use super::*;
    use znf_compression::Config as CompConfig;
    use znf_crypto::KdfParams;

    #[test]
    fn unencrypted_archive_roundtrip_and_verify() {
        let opts = WriteOptions {
            compression: CompConfig::zstd(3),
            comment: Some("test archive".into()),
            include_parity: true,
            ..WriteOptions::default()
        };
        let mut writer = ZarcWriter::new(opts);
        writer.add_directory("docs", 0o755, 1_700_000_000).unwrap();
        writer
            .add_bytes("docs/hello.txt", b"Hello, ZNF world!", 0o644, 1_700_000_001)
            .unwrap();
        writer
            .add_bytes("empty.bin", b"", 0o644, 1_700_000_002)
            .unwrap();

        let mut archive_bytes = Vec::new();
        writer.finish(&mut archive_bytes).unwrap();

        let arch = ZarcArchive::open(&archive_bytes, ReadOptions::default()).unwrap();
        assert_eq!(arch.comment(), Some("test archive"));
        assert_eq!(arch.entries().len(), 3);
        arch.verify_all().unwrap();

        let stats = arch.compression_stats();
        assert_eq!(stats.total_entries, 3);
        assert_eq!(stats.file_count, 2);
        assert_eq!(stats.dir_count, 1);

        let content = arch.read_entry_bytes(&arch.entries()[1]).unwrap();
        assert_eq!(content, b"Hello, ZNF world!");
    }

    #[test]
    fn encrypted_archive_hides_filenames_and_comment_until_authenticated() {
        let opts = WriteOptions {
            compression: CompConfig::lz4(),
            password: Some(b"s3cret-passphrase".to_vec()),
            kdf_params: Some(KdfParams::new_interactive_test().unwrap()),
            comment: Some("top-secret-comment".into()),
            ..WriteOptions::default()
        };
        let mut writer = ZarcWriter::new(opts);
        writer
            .add_bytes("secret/notes.txt", b"classified payload", 0o600, 100)
            .unwrap();

        let mut buf = Vec::new();
        writer.finish(&mut buf).unwrap();

        // Neither plaintext filename nor comment may appear in raw archive bytes!
        assert!(
            !buf.windows(b"notes.txt".len()).any(|w| w == b"notes.txt"),
            "encrypted archive leaked filename in cleartext"
        );
        assert!(
            !buf.windows(b"top-secret-comment".len())
                .any(|w| w == b"top-secret-comment"),
            "encrypted archive leaked comment in cleartext"
        );

        // Unauthenticated inspection succeeds on structure/BLAKE3, with index_locked = true.
        let locked_insp = inspect_archive(&buf, None, &znf_core::Limits::default()).unwrap();
        assert!(locked_insp.index_locked);
        assert!(locked_insp.archive_blake3_verified);
        assert!(locked_insp.entries.is_empty());
        assert!(locked_insp.comment.is_none());

        // Wrong password fails authentication.
        let bad_opts = ReadOptions {
            password: Some(b"wrong-password".to_vec()),
            ..ReadOptions::default()
        };
        let err = ZarcArchive::open(&buf, bad_opts).unwrap_err();
        assert!(err.is_authentication_failure());

        // Correct password unlocks entries and comment.
        let ok_opts = ReadOptions {
            password: Some(b"s3cret-passphrase".to_vec()),
            ..ReadOptions::default()
        };
        let arch = ZarcArchive::open(&buf, ok_opts).unwrap();
        assert_eq!(arch.comment(), Some("top-secret-comment"));
        arch.verify_all().unwrap();
        assert_eq!(
            arch.read_entry_bytes(&arch.entries()[0]).unwrap(),
            b"classified payload"
        );
    }

    #[test]
    fn parity_repairs_corrupted_payload_byte() {
        let opts = WriteOptions {
            compression: CompConfig::stored(),
            include_parity: true,
            ..WriteOptions::default()
        };
        let mut writer = ZarcWriter::new(opts);
        writer
            .add_bytes("data.bin", &[0x55u8; 8192], 0o644, 0)
            .unwrap();
        let mut buf = Vec::new();
        writer.finish(&mut buf).unwrap();

        let arch_ok = ZarcArchive::open(&buf, ReadOptions::default()).unwrap();
        let p_off = arch_ok.header().payload_offset() as usize;
        let mut damaged = buf.clone();
        damaged[p_off + 100] ^= 0xFF;

        let arch_bad = ZarcArchive::open(&damaged, ReadOptions::default()).unwrap();
        assert!(arch_bad.verify_all().is_err());

        let repaired = attempt_parity_repair(&damaged, &znf_core::Limits::default())
            .unwrap()
            .expect("should repair 1 block");
        assert_eq!(repaired, buf);
        let arch_fixed = ZarcArchive::open(&repaired, ReadOptions::default()).unwrap();
        arch_fixed.verify_all().unwrap();
    }
}
