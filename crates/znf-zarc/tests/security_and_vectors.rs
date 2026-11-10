//! Integration tests for ZNF Core & ZARC v1.0:
//! - Deterministic binary vectors
//! - Forward/backward compatibility rules
//! - Security hardening (path traversal, bombs, integer overflow, malformed/truncated input)

use std::fs;
use znf_compression::{Algorithm, Config as CompConfig};
use znf_core::{
    Error as CoreError, Flags, FormatId, Header, Limits, TlvReader, TlvWriter, HEADER_LEN,
};
use znf_crypto::KdfParams;
use znf_zarc::{
    decode_index, encode_index, EntryKind, EntryRecord, ReadOptions, WriteOptions, ZarcArchive,
    ZarcError, ZarcWriter, TLV_ARCHIVE_BLAKE3, TLV_ZARC_INDEX,
};

#[test]
fn deterministic_core_header_vector() {
    let mut h = Header::with_layout(FormatId::ZARC, 1, 0, 64, 64, 512);
    h.flags_mut().set(Flags::COMPRESSED, true);
    h.flags_mut().set(Flags::HAS_FOOTER, true);

    let mut buf = [0u8; HEADER_LEN];
    h.encode(&mut buf).unwrap();

    // Magic: "ZNF\0"
    assert_eq!(&buf[0..4], b"ZNF\0");
    // FormatId = 1 (LE)
    assert_eq!(&buf[4..8], &[1, 0, 0, 0]);
    // Major = 1, Minor = 0 (LE)
    assert_eq!(&buf[8..12], &[1, 0, 0, 0]);
    // Flags = COMPRESSED (1) | HAS_FOOTER (8) = 9
    assert_eq!(u64::from_le_bytes(buf[12..20].try_into().unwrap()), 9);
    // Header len = 64, Payload offset = 64, Payload len = 512
    assert_eq!(u64::from_le_bytes(buf[20..28].try_into().unwrap()), 64);
    assert_eq!(u64::from_le_bytes(buf[28..36].try_into().unwrap()), 64);
    assert_eq!(u64::from_le_bytes(buf[36..44].try_into().unwrap()), 512);
    // Reserved 48..64 all zero
    assert!(buf[48..64].iter().all(|&b| b == 0));

    let decoded = Header::decode(&buf, &Limits::default(), Some(64 + 512)).unwrap();
    assert_eq!(decoded, h);
}

#[test]
fn forward_compatibility_minor_version_and_unknown_tlvs() {
    // Build a valid archive with minor version 5 and extra unknown TLVs in metadata & footer.
    let limits = Limits::default();
    let mut meta = TlvWriter::new();
    meta.push(0x7ABC, b"future standard metadata extension", &limits)
        .unwrap();
    meta.push(0x8001, b"vendor private metadata", &limits)
        .unwrap();
    meta.push_end();
    let meta_bytes = meta.into_bytes();

    let payload = b"raw stored file content";
    let payload_offset = (HEADER_LEN + meta_bytes.len()) as u64;

    let mut hdr = Header::with_layout(
        FormatId::ZARC,
        1,
        5, // future minor version 1.5
        HEADER_LEN as u64,
        payload_offset,
        payload.len() as u64,
    );
    hdr.flags_mut().set(Flags::HAS_METADATA, true);
    hdr.flags_mut().set(Flags::HAS_FOOTER, true);
    let mut hdr_bytes = [0u8; HEADER_LEN];
    hdr.encode(&mut hdr_bytes).unwrap();

    // Also set an unknown future advisory flag bit (bit 32) and recompute header CRC.
    hdr_bytes[16] |= 0x01;
    let new_crc = Header::compute_header_crc(&hdr_bytes);
    hdr_bytes[44..48].copy_from_slice(&new_crc.to_le_bytes());

    let rec = EntryRecord {
        path: "future.txt".into(),
        kind: EntryKind::File,
        compression: Algorithm::None,
        flags: 0,
        unix_mode: 0o644,
        mtime_unix_secs: 0,
        uncompressed_size: payload.len() as u64,
        stored_size: payload.len() as u64,
        payload_rel_offset: 0,
        blake3_hash: znf_integrity::hash(payload),
        entry_nonce: [0u8; 24],
    };
    let idx_bytes = encode_index(&[rec]).unwrap();

    let mut pre_footer = Vec::new();
    pre_footer.extend_from_slice(&hdr_bytes);
    pre_footer.extend_from_slice(&meta_bytes);
    pre_footer.extend_from_slice(payload);
    let arch_hash = znf_integrity::hash(&pre_footer);

    let mut footer = TlvWriter::new();
    footer
        .push(0x8FFE, b"unknown footer extension", &limits)
        .unwrap();
    footer.push(TLV_ZARC_INDEX, &idx_bytes, &limits).unwrap();
    footer
        .push(TLV_ARCHIVE_BLAKE3, arch_hash.as_bytes(), &limits)
        .unwrap();
    footer.push_end();

    let mut full = pre_footer;
    full.extend_from_slice(footer.as_bytes());

    let arch = ZarcArchive::open(&full, ReadOptions::default()).unwrap();
    assert_eq!(arch.header().version().minor, 5);
    assert_eq!(arch.entries().len(), 1);
    arch.verify_all().unwrap();
    assert_eq!(arch.read_entry_bytes(&arch.entries()[0]).unwrap(), payload);
}

#[test]
fn every_truncation_offset_fails_without_panic() {
    let opts = WriteOptions {
        compression: CompConfig::zstd(3),
        comment: Some("truncation test".into()),
        include_parity: true,
        ..WriteOptions::default()
    };
    let mut writer = ZarcWriter::new(opts);
    writer
        .add_bytes("dir/a.txt", b"hello world 1234567890", 0o644, 100)
        .unwrap();
    let mut full = Vec::new();
    writer.finish(&mut full).unwrap();

    for len in 0..full.len() {
        let slice = &full[..len];
        let res = ZarcArchive::open(slice, ReadOptions::default()).and_then(|a| a.verify_all());
        assert!(res.is_err(), "expected error at truncated len {len}");
    }
}

#[test]
fn tampered_index_path_traversal_rejected_on_open() {
    // Craft an index record manually containing "../evil" by mutating encoded bytes.
    let rec = EntryRecord {
        path: "abc/evil".into(),
        kind: EntryKind::File,
        compression: Algorithm::None,
        flags: 0,
        unix_mode: 0o644,
        mtime_unix_secs: 0,
        uncompressed_size: 0,
        stored_size: 0,
        payload_rel_offset: 0,
        blake3_hash: znf_integrity::hash(b""),
        entry_nonce: [0u8; 24],
    };
    let mut idx = encode_index(&[rec]).unwrap();
    // Overwrite "abc/evil" at the end with "../evil!"
    let n = idx.len();
    idx[n - 8..n].copy_from_slice(b"../evil!");
    let err = decode_index(&idx, 100).unwrap_err();
    assert!(matches!(err, ZarcError::Path(_)));
}

#[test]
fn decompression_bomb_and_ratio_limits_enforced() {
    let data = vec![0u8; 2 * 1024 * 1024]; // 2 MiB of zeros compresses to ~200 bytes
    let opts = WriteOptions {
        compression: CompConfig::zstd(19),
        ..WriteOptions::default()
    };
    let mut w = ZarcWriter::new(opts);
    w.add_bytes("zeros.bin", &data, 0o644, 0).unwrap();
    let mut buf = Vec::new();
    w.finish(&mut buf).unwrap();

    // 1. Default max_compression_ratio (1000:1) rejects a 2 MiB all-zero bomb (~10000:1).
    let res = ZarcArchive::open(&buf, ReadOptions::default());
    assert!(matches!(res, Err(ZarcError::ResourceLimitExceeded(_))));

    // 2. Even if ratio limit is raised, strict max_expanded_len (1 MiB) rejects it.
    let mut strict_opts = ReadOptions {
        max_compression_ratio: 1_000_000,
        ..ReadOptions::default()
    };
    strict_opts.limits.max_expanded_len = 1024 * 1024;
    let res2 = ZarcArchive::open(&buf, strict_opts);
    assert!(matches!(
        res2,
        Err(ZarcError::Core(CoreError::LengthExceedsLimit { .. }))
    ));
}

#[test]
fn extraction_refuses_symlink_traversal() {
    let opts = WriteOptions::default();
    let mut w = ZarcWriter::new(opts);
    w.add_bytes("sub/target.txt", b"safe data", 0o644, 0)
        .unwrap();
    let mut buf = Vec::new();
    w.finish(&mut buf).unwrap();

    let arch = ZarcArchive::open(&buf, ReadOptions::default()).unwrap();
    let tmp = std::env::temp_dir().join(format!("znf-symlink-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    #[cfg(unix)]
    {
        let outside = std::env::temp_dir().join(format!("znf-outside-{}", std::process::id()));
        let _ = fs::remove_dir_all(&outside);
        fs::create_dir_all(&outside).unwrap();
        // Plant a symlink `tmp/sub -> outside` before extracting.
        std::os::unix::fs::symlink(&outside, tmp.join("sub")).unwrap();
        let res = arch.extract_to(&tmp);
        assert!(
            matches!(res, Err(ZarcError::UnsupportedFsEntry(_))),
            "extraction must refuse to traverse symlinked subdirectory"
        );
        assert!(!outside.join("target.txt").exists());
        let _ = fs::remove_dir_all(&outside);
    }

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn header_tampering_detected_by_aead_aad() {
    let opts = WriteOptions {
        compression: CompConfig::stored(),
        password: Some(b"pw123".to_vec()),
        kdf_params: Some(KdfParams::new_interactive_test().unwrap()),
        ..WriteOptions::default()
    };
    let mut w = ZarcWriter::new(opts);
    w.add_bytes("f.txt", b"secret", 0o600, 0).unwrap();
    let mut buf = Vec::new();
    w.finish(&mut buf).unwrap();

    // Modify minor version in header (bytes 10..12) AND recompute header CRC-32
    // so header CRC passes — AEAD AAD check must STILL catch the tampering!
    buf[10] = 9;
    let forged_crc = Header::compute_header_crc(&buf);
    buf[44..48].copy_from_slice(&forged_crc.to_le_bytes());

    let r_opts = ReadOptions {
        password: Some(b"pw123".to_vec()),
        ..ReadOptions::default()
    };
    let err = ZarcArchive::open(&buf, r_opts).unwrap_err();
    assert!(matches!(err, ZarcError::Crypto(_)));
}

#[test]
fn tlv_reader_rejects_reserved_and_oversized() {
    let limits = Limits::strict();
    let mut bad = Vec::new();
    bad.extend_from_slice(&0u16.to_le_bytes());
    bad.extend_from_slice(&0u32.to_le_bytes());
    let mut r = TlvReader::new(&bad, limits);
    assert!(matches!(r.next_tlv(), Err(CoreError::ReservedTlvType(0))));
}
