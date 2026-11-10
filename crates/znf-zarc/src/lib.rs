//! ZARC (`.zarc`) Archive Container Format.
//!
//! `znf-zarc` is the first production container format built on `znf-core`.
//! It provides:
//!
//! - Lossless file and directory archiving (Store, Zstandard, LZ4).
//! - Optional authenticated encryption (`XChaCha20-Poly1305` + `Argon2id`)
//!   covering both file contents and the entry index (filenames, sizes, hashes).
//! - Per-file and whole-archive `BLAKE3` integrity verification.
//! - Optional XOR block parity (`znf-recovery`) for single-block repair.
//! - Strict path traversal and decompression-bomb defenses.
//!
//! See `specifications/zarc/ZARC-SPEC.md` for the normative format specification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::all)]

pub mod archive;
pub mod entry;
pub mod error;
pub mod path;

pub use archive::{
    attempt_parity_repair, ReadOptions, WriteOptions, ZarcArchive, ZarcWriter, TLV_ARCHIVE_BLAKE3,
    TLV_COMMENT, TLV_KDF_PARAMS, TLV_PARITY_STRIPE, TLV_ZARC_ENCRYPTED_INDEX, TLV_ZARC_INDEX,
};
pub use entry::{
    decode_index, encode_index, EntryKind, EntryRecord, DEFAULT_MAX_ENTRIES, ENTRY_FIXED_LEN,
};
pub use error::ZarcError;
pub use path::{normalize_fs_path, safe_join, validate_archive_path, PathError, MAX_PATH_LEN};

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

        let content = arch.read_entry_bytes(&arch.entries()[1]).unwrap();
        assert_eq!(content, b"Hello, ZNF world!");
    }

    #[test]
    fn encrypted_archive_roundtrip_and_wrong_password_rejected() {
        let opts = WriteOptions {
            compression: CompConfig::lz4(),
            password: Some(b"s3cret-passphrase".to_vec()),
            kdf_params: Some(KdfParams::new_interactive_test().unwrap()),
            ..WriteOptions::default()
        };
        let mut writer = ZarcWriter::new(opts);
        writer
            .add_bytes("secret/notes.txt", b"classified payload", 0o600, 100)
            .unwrap();

        let mut buf = Vec::new();
        writer.finish(&mut buf).unwrap();

        // Plaintext filename must NOT appear in raw archive bytes (index is encrypted).
        assert!(
            !buf.windows(b"notes.txt".len()).any(|w| w == b"notes.txt"),
            "encrypted archive leaked filename in cleartext"
        );

        // Wrong password fails authentication.
        let bad_opts = ReadOptions {
            password: Some(b"wrong-password".to_vec()),
            ..ReadOptions::default()
        };
        assert!(matches!(
            ZarcArchive::open(&buf, bad_opts),
            Err(ZarcError::Crypto(_))
        ));

        // Correct password succeeds.
        let ok_opts = ReadOptions {
            password: Some(b"s3cret-passphrase".to_vec()),
            ..ReadOptions::default()
        };
        let arch = ZarcArchive::open(&buf, ok_opts).unwrap();
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

        // Corrupt a byte inside the payload.
        let arch_ok = ZarcArchive::open(&buf, ReadOptions::default()).unwrap();
        let p_off = arch_ok.header().payload_offset() as usize;
        let mut damaged = buf.clone();
        damaged[p_off + 100] ^= 0xFF;

        // Verification fails on damaged archive.
        let arch_bad = ZarcArchive::open(&damaged, ReadOptions::default()).unwrap();
        assert!(arch_bad.verify_all().is_err());

        // Repair via parity stripe restores exact bytes.
        let repaired = attempt_parity_repair(&damaged, &znf_core::Limits::default())
            .unwrap()
            .expect("should repair 1 block");
        assert_eq!(repaired, buf);
        let arch_fixed = ZarcArchive::open(&repaired, ReadOptions::default()).unwrap();
        arch_fixed.verify_all().unwrap();
    }
}
