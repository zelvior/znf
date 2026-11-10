//! Comprehensive functional, security, round-trip, recovery, and fuzz-smoke
//! integration tests for ZARC (`.zarc`) v1.0.

use std::collections::BTreeMap;
use std::fs;
use std::sync::atomic::AtomicBool;

use znf_compression::{Algorithm, Config as CompConfig};
use znf_core::{Flags, FormatId, Header, Limits, TlvWriter, HEADER_LEN};
use znf_crypto::KdfParams;
use znf_integrity::hash;
use znf_zarc::{
    add_paths_to_archive_file, attempt_parity_repair, decode_index, encode_index, inspect_archive,
    remove_entries_from_archive_file, validate_archive_path, validate_archive_path_with_depth,
    EntryKind, EntryRecord, ExtractOptions, PathError, ReadOptions, WriteOptions, ZarcArchive,
    ZarcError, ZarcWriter, TLV_ARCHIVE_BLAKE3, TLV_ZARC_INDEX,
};

#[test]
fn rejects_all_malicious_traversal_unc_and_windows_paths() {
    let malicious = [
        "",
        "/",
        "/etc/passwd",
        "\\Windows\\System32\\cmd.exe",
        "//server/share/secret.txt",
        "\\\\server\\share\\secret.txt",
        "../secret.txt",
        "a/../../secret.txt",
        "C:/Windows/win.ini",
        "D:relative",
        "bad\0null.txt",
        "bad\x07bell.txt",
    ];
    for p in malicious {
        assert!(
            validate_archive_path(p).is_err(),
            "expected malicious path {p:?} to be rejected"
        );
    }
}

#[test]
fn rejects_excessive_directory_depth_and_long_components() {
    // 65 levels deep exceeds DEFAULT_MAX_DEPTH (64)
    let deep = vec!["d"; 65].join("/");
    assert_eq!(
        validate_archive_path(&deep),
        Err(PathError::ExcessiveDepth { depth: 65, max: 64 })
    );
    // Custom depth limit of 3
    assert_eq!(
        validate_archive_path_with_depth("a/b/c/d.txt", 3),
        Err(PathError::ExcessiveDepth { depth: 4, max: 3 })
    );

    // Single path component > 255 bytes
    let long_comp = format!("dir/{}.txt", "a".repeat(256));
    assert!(matches!(
        validate_archive_path(&long_comp),
        Err(PathError::ComponentTooLong { .. })
    ));
}

#[test]
fn rejects_decompression_bomb_by_size_and_ratio() {
    let bomb_data = vec![b'A'; 512 * 1024]; // 512 KiB of 'A' compresses to < 100 bytes
    let mut writer = ZarcWriter::new(WriteOptions {
        compression: CompConfig::zstd(9),
        ..WriteOptions::default()
    });
    writer.add_bytes("bomb.txt", &bomb_data, 0o644, 0).unwrap();
    let mut raw = Vec::new();
    writer.finish(&mut raw).unwrap();

    // 1. Reject via limits.max_expanded_len (128 KiB)
    let strict_size_opts = ReadOptions {
        limits: Limits {
            max_expanded_len: 128 * 1024,
            ..Limits::default()
        },
        ..ReadOptions::default()
    };
    assert!(
        ZarcArchive::open(&raw, strict_size_opts).is_err(),
        "must reject entry exceeding max_expanded_len"
    );

    // 2. Reject via max_compression_ratio limit (ratio 10x)
    let strict_ratio_opts = ReadOptions {
        max_compression_ratio: 10,
        ..ReadOptions::default()
    };
    assert!(
        ZarcArchive::open(&raw, strict_ratio_opts).is_err(),
        "must reject entry exceeding max_compression_ratio"
    );
}

#[test]
fn rejects_overlapping_or_out_of_bounds_entry_offsets() {
    let rec1 = EntryRecord {
        path: "a.bin".into(),
        kind: EntryKind::File,
        compression: Algorithm::None,
        flags: 0,
        uncompressed_size: 10,
        stored_size: 10,
        payload_rel_offset: 0,
        mtime_unix_secs: 0,
        unix_mode: 0o644,
        blake3_hash: hash(&[0u8; 10]),
        entry_nonce: [0u8; 24],
        user_metadata: BTreeMap::new(),
    };
    let rec2 = EntryRecord {
        path: "b.bin".into(),
        kind: EntryKind::File,
        compression: Algorithm::None,
        flags: 0,
        uncompressed_size: 10,
        stored_size: 10,
        payload_rel_offset: 5, // overlaps rec1!
        mtime_unix_secs: 0,
        unix_mode: 0o644,
        blake3_hash: hash(&[0u8; 10]),
        entry_nonce: [0u8; 24],
        user_metadata: BTreeMap::new(),
    };
    let idx_bytes = encode_index(&[rec1, rec2]).unwrap();

    let payload = [0u8; 20];
    let payload_offset = HEADER_LEN as u64;
    let payload_len = payload.len() as u64;
    let header = Header::new(FormatId::ZARC, 1, 0)
        .with_flags(Flags::from_bits(Flags::HAS_FOOTER))
        .with_payload_span(payload_offset, payload_len);
    let mut hdr_buf = [0u8; HEADER_LEN];
    header.encode(&mut hdr_buf).unwrap();

    let mut raw = Vec::new();
    raw.extend_from_slice(&hdr_buf);
    raw.extend_from_slice(&payload);
    let b3 = hash(&raw);

    let footer = {
        let mut fw = TlvWriter::new();
        fw.push(TLV_ZARC_INDEX, &idx_bytes, &Limits::default())
            .unwrap();
        fw.push(TLV_ARCHIVE_BLAKE3, b3.as_bytes(), &Limits::default())
            .unwrap();
        fw.push_end();
        fw.as_bytes().to_vec()
    };
    raw.extend_from_slice(&footer);

    let res = ZarcArchive::open(&raw, ReadOptions::default());
    assert!(res.is_err(), "overlapping entry offsets must be rejected");
}

#[test]
fn rejects_duplicate_paths_and_case_insensitive_collisions() {
    // 1. Exact duplicate path in index is rejected when opening archive
    let rec = EntryRecord {
        path: "dup.txt".into(),
        kind: EntryKind::File,
        compression: Algorithm::None,
        flags: 0,
        uncompressed_size: 0,
        stored_size: 0,
        payload_rel_offset: 0,
        mtime_unix_secs: 0,
        unix_mode: 0o644,
        blake3_hash: hash(b""),
        entry_nonce: [0u8; 24],
        user_metadata: BTreeMap::new(),
    };
    let idx_bytes = encode_index(&[rec.clone(), rec]).unwrap();
    let header = Header::new(FormatId::ZARC, 1, 0)
        .with_flags(Flags::from_bits(Flags::HAS_FOOTER))
        .with_payload_span(HEADER_LEN as u64, 0);
    let mut hdr_buf = [0u8; HEADER_LEN];
    header.encode(&mut hdr_buf).unwrap();

    let mut raw = Vec::new();
    raw.extend_from_slice(&hdr_buf);
    let b3 = hash(&raw);
    let footer = {
        let mut fw = TlvWriter::new();
        fw.push(TLV_ZARC_INDEX, &idx_bytes, &Limits::default())
            .unwrap();
        fw.push(TLV_ARCHIVE_BLAKE3, b3.as_bytes(), &Limits::default())
            .unwrap();
        fw.push_end();
        fw.as_bytes().to_vec()
    };
    raw.extend_from_slice(&footer);

    let res = ZarcArchive::open(&raw, ReadOptions::default());
    assert!(matches!(res, Err(ZarcError::DuplicateEntry(_))));

    // 2. Case-insensitive collision ("Readme.txt" vs "readme.txt") is caught on extraction
    let mut writer = ZarcWriter::new(WriteOptions::default());
    writer.add_bytes("Readme.txt", b"first", 0o644, 1).unwrap();
    writer.add_bytes("readme.txt", b"second", 0o644, 1).unwrap();
    let mut case_buf = Vec::new();
    writer.finish(&mut case_buf).unwrap();

    let arch = ZarcArchive::open(&case_buf, ReadOptions::default()).unwrap();
    let dest = std::env::temp_dir().join(format!("znf_case_collision_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dest);
    let err = arch.extract_to(&dest).unwrap_err();
    assert!(
        matches!(err, ZarcError::CaseInsensitiveCollision { .. }),
        "expected CaseInsensitiveCollision, got {err:?}"
    );
    let _ = fs::remove_dir_all(&dest);
}

#[test]
fn detects_truncated_and_bit_flipped_archives() {
    let mut writer = ZarcWriter::new(WriteOptions {
        compression: CompConfig::zstd(3),
        ..WriteOptions::default()
    });
    writer
        .add_bytes("file.txt", b"important content", 0o644, 123)
        .unwrap();
    let mut raw = Vec::new();
    writer.finish(&mut raw).unwrap();

    // 1. Truncate in the middle of header
    assert!(ZarcArchive::open(&raw[..20], ReadOptions::default()).is_err());

    // 2. Truncate in the middle of payload
    assert!(ZarcArchive::open(&raw[..HEADER_LEN + 3], ReadOptions::default()).is_err());

    // 3. Flip a bit in the payload -> open() succeeds (structure is intact),
    // but verify_all() catches the payload corruption via archive BLAKE3
    let mut flipped = raw.clone();
    flipped[HEADER_LEN + 2] ^= 0x01;
    let flipped_arch = ZarcArchive::open(&flipped, ReadOptions::default()).unwrap();
    assert!(flipped_arch.verify_all().is_err());
}

#[test]
fn rejects_unknown_critical_extension_and_accepts_noncritical() {
    // Build an archive with an unknown non-critical metadata TLV (0x7055)
    let meta_bytes = {
        let mut mw = TlvWriter::new();
        mw.push(0x7055, b"non-critical vendor note", &Limits::default())
            .unwrap();
        mw.push_end();
        mw.as_bytes().to_vec()
    };
    let payload_offset = (HEADER_LEN + meta_bytes.len()) as u64;
    let header = Header::new(FormatId::ZARC, 1, 0)
        .with_flags(Flags::from_bits(Flags::HAS_METADATA | Flags::HAS_FOOTER))
        .with_payload_span(payload_offset, 0);
    let mut hdr_buf = [0u8; HEADER_LEN];
    header.encode(&mut hdr_buf).unwrap();

    let mut raw = Vec::new();
    raw.extend_from_slice(&hdr_buf);
    raw.extend_from_slice(&meta_bytes);
    let b3 = hash(&raw);
    let idx = encode_index(&[]).unwrap();
    let footer = {
        let mut fw = TlvWriter::new();
        fw.push(TLV_ZARC_INDEX, &idx, &Limits::default()).unwrap();
        fw.push(TLV_ARCHIVE_BLAKE3, b3.as_bytes(), &Limits::default())
            .unwrap();
        fw.push_end();
        fw.as_bytes().to_vec()
    };
    raw.extend_from_slice(&footer);

    // Non-critical unknown TLV is accepted and reported in inspection warnings
    let insp = inspect_archive(&raw, None, &Limits::default()).unwrap();
    assert_eq!(insp.warnings.len(), 1);
    let arch = ZarcArchive::open(&raw, ReadOptions::default()).unwrap();
    assert_eq!(arch.preserved_metadata_extensions().len(), 1);

    // Critical unknown TLV (0x4099) MUST be rejected
    let crit_meta = {
        let mut mw_crit = TlvWriter::new();
        mw_crit
            .push(0x4099, b"critical unknown", &Limits::default())
            .unwrap();
        mw_crit.push_end();
        mw_crit.as_bytes().to_vec()
    };
    let crit_hdr = Header::new(FormatId::ZARC, 1, 0)
        .with_flags(Flags::from_bits(Flags::HAS_METADATA | Flags::HAS_FOOTER))
        .with_payload_span((HEADER_LEN + crit_meta.len()) as u64, 0);
    let mut crit_hdr_buf = [0u8; HEADER_LEN];
    crit_hdr.encode(&mut crit_hdr_buf).unwrap();

    let mut crit_raw = Vec::new();
    crit_raw.extend_from_slice(&crit_hdr_buf);
    crit_raw.extend_from_slice(&crit_meta);
    let crit_b3 = hash(&crit_raw);
    let crit_footer = {
        let mut fw_crit = TlvWriter::new();
        fw_crit
            .push(TLV_ZARC_INDEX, &idx, &Limits::default())
            .unwrap();
        fw_crit
            .push(TLV_ARCHIVE_BLAKE3, crit_b3.as_bytes(), &Limits::default())
            .unwrap();
        fw_crit.push_end();
        fw_crit.as_bytes().to_vec()
    };
    crit_raw.extend_from_slice(&crit_footer);

    let err = ZarcArchive::open(&crit_raw, ReadOptions::default()).unwrap_err();
    assert!(err.is_unsupported());
}

#[cfg(unix)]
#[test]
fn rejects_symlink_escape_during_creation_and_extraction() {
    use std::os::unix::fs::symlink;

    let tmp = std::env::temp_dir().join(format!("znf_symlink_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    let src_dir = tmp.join("src");
    let dest_dir = tmp.join("dest");
    fs::create_dir_all(&src_dir).unwrap();
    fs::create_dir_all(&dest_dir).unwrap();

    // 1. Creation: symlink inside source tree must be rejected
    symlink("/etc/passwd", src_dir.join("evil_link")).unwrap();
    let mut writer = ZarcWriter::new(WriteOptions::default());
    let err = writer.add_path(&src_dir, &src_dir.join("evil_link"));
    assert!(
        matches!(err, Err(ZarcError::SymlinkNotAllowed(_))),
        "symlink in input directory must be rejected"
    );

    // 2. Extraction: pre-existing symlink inside destination tree must be rejected
    let mut writer2 = ZarcWriter::new(WriteOptions::default());
    writer2
        .add_bytes("subdir/escape.txt", b"payload", 0o644, 0)
        .unwrap();
    let mut archive_bytes = Vec::new();
    writer2.finish(&mut archive_bytes).unwrap();

    // Create a symlink at dest_dir/subdir pointing to /tmp
    symlink("/tmp", dest_dir.join("subdir")).unwrap();
    let arch = ZarcArchive::open(&archive_bytes, ReadOptions::default()).unwrap();
    let ext_res = arch.extract_to(&dest_dir);
    assert!(
        matches!(ext_res, Err(ZarcError::SymlinkNotAllowed(_))),
        "extraction through symlinked parent directory must be rejected"
    );

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn full_filesystem_roundtrip_mixed_algorithms_metadata_and_add_remove() {
    let tmp = std::env::temp_dir().join(format!("znf_fs_roundtrip_{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    let src = tmp.join("project");
    let out_dir = tmp.join("extracted");
    let sel_dir = tmp.join("selected");
    let archive_path = tmp.join("project.zarc");

    fs::create_dir_all(src.join("src/nested/deep")).unwrap();
    fs::create_dir_all(src.join("empty_dir")).unwrap();
    fs::write(src.join("README.md"), b"# Project ZNF\nFast & Safe.\n").unwrap();
    fs::write(src.join("empty.txt"), b"").unwrap();
    fs::write(
        src.join("src/main.rs"),
        b"fn main() { println!(\"ZNF\"); }\n".repeat(200),
    )
    .unwrap();
    // Binary data
    let binary_blob: Vec<u8> = (0..=255u8).cycle().take(65_536).collect();
    fs::write(src.join("src/nested/deep/blob.bin"), &binary_blob).unwrap();

    let pw = b"correct-horse-battery-staple".to_vec();
    let mut writer = ZarcWriter::new(WriteOptions {
        compression: CompConfig::zstd(5),
        password: Some(pw.clone()),
        kdf_params: Some(KdfParams::new_interactive_test().unwrap()),
        comment: Some("v1.0 release bundle".into()),
        include_parity: true,
        overwrite: false,
        ..WriteOptions::default()
    });
    writer.add_path(&tmp, &src).unwrap();

    // Also add an in-memory entry with custom LZ4 compression and user metadata
    let mut user_meta = BTreeMap::new();
    user_meta.insert("content-type".into(), "application/json".into());
    user_meta.insert("author".into(), "zelvior".into());
    writer
        .add_bytes_with_options(
            "project/manifest.json",
            b"{\"version\":1}",
            0o644,
            1_700_000_100,
            Some(CompConfig::lz4()),
            user_meta.clone(),
        )
        .unwrap();

    writer.finish_to_path(&archive_path, None, None).unwrap();

    // Creating again to the same path with overwrite=false must fail with TargetAlreadyExists
    let mut writer_dup = ZarcWriter::new(WriteOptions::default());
    writer_dup.add_bytes("a.txt", b"x", 0o644, 0).unwrap();
    assert!(matches!(
        writer_dup.finish_to_path(&archive_path, None, None),
        Err(ZarcError::TargetAlreadyExists(_))
    ));

    // Read & verify encrypted archive
    let raw = fs::read(&archive_path).unwrap();
    let arch = ZarcArchive::open(
        &raw,
        ReadOptions {
            password: Some(pw.clone()),
            ..ReadOptions::default()
        },
    )
    .unwrap();
    arch.verify_all().unwrap();
    assert_eq!(arch.comment(), Some("v1.0 release bundle"));

    // Verify per-entry user metadata and encryption flag
    let manifest_entry = arch
        .find_entry("project/manifest.json")
        .expect("manifest.json must exist");
    assert!(manifest_entry.is_encrypted());
    assert_eq!(manifest_entry.compression, Algorithm::Lz4);
    assert_eq!(manifest_entry.user_metadata, user_meta);
    assert_eq!(manifest_entry.file_name(), "manifest.json");
    assert_eq!(manifest_entry.depth(), 2);

    // Extract to out_dir
    arch.extract_to(&out_dir).unwrap();
    assert_eq!(
        fs::read(out_dir.join("project/README.md")).unwrap(),
        b"# Project ZNF\nFast & Safe.\n"
    );
    assert_eq!(fs::read(out_dir.join("project/empty.txt")).unwrap(), b"");
    assert!(out_dir.join("project/empty_dir").is_dir());
    assert_eq!(
        fs::read(out_dir.join("project/src/nested/deep/blob.bin")).unwrap(),
        binary_blob
    );
    assert_eq!(
        fs::read(out_dir.join("project/manifest.json")).unwrap(),
        b"{\"version\":1}"
    );

    // Re-extracting to out_dir without overwrite=true must fail with TargetAlreadyExists
    let err_no_ovw = arch.extract_to(&out_dir).unwrap_err();
    assert!(matches!(err_no_ovw, ZarcError::TargetAlreadyExists(_)));

    // Re-extracting with overwrite=true succeeds
    arch.extract_with_options(
        &out_dir,
        &ExtractOptions {
            overwrite: true,
            ..ExtractOptions::default()
        },
        None,
        None,
    )
    .unwrap();

    // Selected entry extraction
    let sel_count = arch
        .extract_with_options(
            &sel_dir,
            &ExtractOptions {
                selected_paths: Some(vec!["project/README.md".into()]),
                ..ExtractOptions::default()
            },
            None,
            None,
        )
        .unwrap();
    assert_eq!(sel_count, 1);
    assert!(sel_dir.join("project/README.md").is_file());
    assert!(!sel_dir.join("project/manifest.json").exists());

    // Add a new file to the existing encrypted archive
    let extra_file = tmp.join("CHANGELOG.md");
    fs::write(&extra_file, b"## 1.0.0\nInitial ZARC release.\n").unwrap();
    add_paths_to_archive_file(&archive_path, &[&extra_file], Some(pw.clone())).unwrap();

    // Remove empty.txt from the archive
    let removed = remove_entries_from_archive_file(
        &archive_path,
        &["project/empty.txt".to_string()],
        Some(pw.clone()),
    )
    .unwrap();
    assert_eq!(removed, 1);

    let updated_raw = fs::read(&archive_path).unwrap();
    let updated_arch = ZarcArchive::open(
        &updated_raw,
        ReadOptions {
            password: Some(pw),
            ..ReadOptions::default()
        },
    )
    .unwrap();
    updated_arch.verify_all().unwrap();
    assert!(updated_arch.find_entry("CHANGELOG.md").is_some());
    assert!(updated_arch.find_entry("project/empty.txt").is_none());

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn partial_recovery_extracts_verified_entries_when_one_entry_is_corrupted() {
    let mut writer = ZarcWriter::new(WriteOptions {
        compression: CompConfig::stored(),
        ..WriteOptions::default()
    });
    writer
        .add_bytes("good1.txt", b"intact file one", 0o644, 10)
        .unwrap();
    writer
        .add_bytes("corrupt_me.txt", b"this entry will be damaged", 0o644, 10)
        .unwrap();
    writer
        .add_bytes("good2.txt", b"intact file two", 0o644, 10)
        .unwrap();

    let mut raw = Vec::new();
    writer.finish(&mut raw).unwrap();

    // Corrupt a byte inside the second entry's payload, and recompute only the container footer BLAKE3
    // (simulating an archive where an individual entry's compressed stream or hash fails).
    let arch = ZarcArchive::open(&raw, ReadOptions::default()).unwrap();
    let entry2_off =
        (arch.header().payload_offset() + arch.entries()[1].payload_rel_offset) as usize;
    let payload_end = (arch.header().payload_offset() + arch.header().payload_len()) as usize;
    let idx_bytes = encode_index(arch.entries()).unwrap();

    let mut damaged = raw[..payload_end].to_vec();
    damaged[entry2_off] ^= 0xFF;
    let new_archive_b3 = hash(&damaged);
    let footer = {
        let mut fw = TlvWriter::new();
        fw.push(TLV_ZARC_INDEX, &idx_bytes, &Limits::default())
            .unwrap();
        fw.push(
            TLV_ARCHIVE_BLAKE3,
            new_archive_b3.as_bytes(),
            &Limits::default(),
        )
        .unwrap();
        fw.push_end();
        fw.as_bytes().to_vec()
    };
    damaged.extend_from_slice(&footer);

    let damaged_arch = ZarcArchive::open(&damaged, ReadOptions::default()).unwrap();
    // Full verify_all fails because entry #2's BLAKE3 hash mismatches
    assert!(damaged_arch.verify_all().is_err());

    // Diagnose entries reports 2 intact and 1 damaged
    let diag = damaged_arch.diagnose_entries();
    assert_eq!(diag.len(), 3);
    assert!(diag[0].intact);
    assert!(!diag[1].intact);
    assert!(diag[2].intact);

    // Partial recovery extracts only the 2 verified entries and never writes the damaged entry
    let tmp = std::env::temp_dir().join(format!("znf_partial_rec_{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    let report = damaged_arch
        .extract_verified_entries(&tmp, &ExtractOptions::default())
        .unwrap();
    assert_eq!(report.extracted_paths, vec!["good1.txt", "good2.txt"]);
    assert_eq!(report.failed_entries.len(), 1);
    assert_eq!(report.failed_entries[0].0, "corrupt_me.txt");
    assert_eq!(fs::read(tmp.join("good1.txt")).unwrap(), b"intact file one");
    assert_eq!(fs::read(tmp.join("good2.txt")).unwrap(), b"intact file two");
    assert!(!tmp.join("corrupt_me.txt").exists());
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn cancellation_token_cleanly_aborts_creation_and_cleans_up_temp_file() {
    let tmp = std::env::temp_dir().join(format!("znf_cancel_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();
    let archive_path = tmp.join("aborted.zarc");

    let mut writer = ZarcWriter::new(WriteOptions::default());
    writer.add_bytes("a.txt", b"hello", 0o644, 0).unwrap();

    let cancelled = AtomicBool::new(true);
    let res = writer.finish_to_path(&archive_path, None, Some(&cancelled));
    assert!(matches!(res, Err(ZarcError::Cancelled)));
    assert!(!archive_path.exists());

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn fuzz_smoke_malformed_inputs_never_panic() {
    // Build a valid archive as a seed
    let mut writer = ZarcWriter::new(WriteOptions {
        compression: CompConfig::lz4(),
        comment: Some("fuzz seed".into()),
        include_parity: true,
        ..WriteOptions::default()
    });
    writer.add_directory("dir", 0o755, 100).unwrap();
    writer
        .add_bytes("dir/seed.txt", b"seed payload for mutation", 0o644, 101)
        .unwrap();
    let mut seed = Vec::new();
    writer.finish(&mut seed).unwrap();

    // 1. All prefixes (truncations) of a valid archive must never panic
    for len in 0..seed.len() {
        let slice = &seed[..len];
        let _ = ZarcArchive::open(slice, ReadOptions::default());
        let _ = inspect_archive(slice, None, &Limits::default());
        let _ = decode_index(slice, 64);
        let _ = attempt_parity_repair(slice, &Limits::default());
    }

    // 2. Single-byte mutations across the entire archive must never panic
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next_u64 = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    for _ in 0..250 {
        let mut mutated = seed.clone();
        let flips = (next_u64() % 6) + 1;
        for _ in 0..flips {
            let idx = (next_u64() as usize) % mutated.len();
            mutated[idx] ^= (next_u64() & 0xFF) as u8;
        }
        let _ = ZarcArchive::open(&mutated, ReadOptions::default());
        let _ = inspect_archive(&mutated, None, &Limits::default());
        let _ = decode_index(&mutated, 64);
    }

    // 3. Completely random buffers of varying lengths must never panic
    for len in [0usize, 1, 7, 63, 64, 65, 128, 512] {
        let buf: Vec<u8> = (0..len).map(|_| (next_u64() & 0xFF) as u8).collect();
        let _ = ZarcArchive::open(&buf, ReadOptions::default());
        let _ = inspect_archive(&buf, None, &Limits::default());
        let _ = decode_index(&buf, 64);
    }
}
