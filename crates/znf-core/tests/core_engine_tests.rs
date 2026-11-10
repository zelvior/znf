//! Comprehensive test suite for the ZNF Core binary-format engine (`znf-core`):
//! - Round-trip tests (empty, small, large streaming, binary, random, Unicode/nested metadata,
//!   Zstd/LZ4/Store compression, XChaCha20-Poly1305 + Argon2id encryption, combined modes)
//! - Negative tests (magic, truncated, version, critical flags, offsets, overflow, metadata,
//!   corrupted payload, bad AEAD tag, malformed compression, critical extensions, limits, cancellation)
//! - Compatibility & deterministic binary vector tests (independent encode/decode paths)

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::sync::atomic::AtomicBool;

use znf_core::{
    crc32, EncryptionKeySource, FormatId, Limits, MetadataValue, TlvReader, TlvWriter,
    ZnfCompression, ZnfEncryption, ZnfError, ZnfFeatureFlags, ZnfFormatVersion, ZnfHeader,
    ZnfMetadata, ZnfReader, ZnfValidator, ZnfWriter, HEADER_LEN, TLV_CONTAINER_BLAKE3,
    TLV_PAYLOAD_BLAKE3, TLV_STORED_PAYLOAD_LEN, TLV_UNCOMPRESSED_LEN,
};
use znf_crypto::{random_bytes, KdfParams, SecretKey};

/// Adapter that forces partial reads (at most `max_step` bytes per call) and
/// partial writes to verify streaming correctness under short I/O.
struct PartialIo<T> {
    inner: T,
    max_step: usize,
}

impl<R: Read> Read for PartialIo<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let cap = buf.len().min(self.max_step.max(1));
        self.inner.read(&mut buf[..cap])
    }
}

impl<W: Write> Write for PartialIo<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let cap = buf.len().min(self.max_step.max(1));
        self.inner.write(&buf[..cap])
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

// ============================================================================
// 1. ROUND-TRIP TESTS
// ============================================================================

#[test]
fn roundtrip_empty_and_small_payloads() {
    for payload in [
        &b""[..],
        &b"a"[..],
        &b"Build better. Preserve everything."[..],
    ] {
        let bytes = ZnfWriter::new().write_to_vec(payload).unwrap();
        let info = ZnfValidator::new().validate_structure(&bytes).unwrap();
        assert_eq!(info.format_id, FormatId::CORE);
        assert_eq!(info.version, ZnfFormatVersion::V1_0);
        assert_eq!(info.uncompressed_len, Some(payload.len() as u64));

        let decoded = ZnfReader::new().read_container(&bytes).unwrap();
        assert_eq!(decoded.payload, payload);
    }
}

#[test]
fn roundtrip_binary_and_random_payloads() {
    // All 256 byte values + embedded ZNF\0 magic bytes
    let mut binary: Vec<u8> = (0..=255u8).collect();
    binary.extend_from_slice(b"ZNF\0\x00\xFF\x00\xFE");

    let mut random = vec![0u8; 32_768];
    random_bytes(&mut random).unwrap();

    for data in [&binary, &random] {
        for comp in [
            ZnfCompression::None,
            ZnfCompression::Zstd,
            ZnfCompression::Lz4,
        ] {
            let bytes = ZnfWriter::new()
                .with_compression(comp)
                .write_to_vec(data)
                .unwrap();
            let decoded = ZnfReader::new().read_container(&bytes).unwrap();
            assert_eq!(&decoded.payload, data);
            assert_eq!(decoded.header.compression(), comp);
        }
    }
}

#[test]
fn roundtrip_large_streaming_with_partial_reads_and_writes() {
    // 1.2 MiB deterministic pattern processed with 8 KiB chunk buffer and 137-byte partial I/O steps.
    let large: Vec<u8> = (0..1_200_000)
        .map(|i| ((i * 31 + 17) % 251) as u8)
        .collect();

    let key = SecretKey::generate().unwrap();
    let writer = ZnfWriter::new()
        .with_compression(ZnfCompression::Lz4)
        .with_encryption(EncryptionKeySource::RawKey(key.clone()))
        .with_buffer_size(8192);

    let mut wire = Vec::new();
    let partial_in = PartialIo {
        inner: io::Cursor::new(&large),
        max_step: 137,
    };
    let mut partial_out = PartialIo {
        inner: &mut wire,
        max_step: 251,
    };
    let written_uncomp = writer
        .write_streaming(partial_in, &mut partial_out, None)
        .unwrap();
    assert_eq!(written_uncomp, large.len() as u64);

    // Structural validator succeeds without needing the secret key.
    let info = ZnfValidator::new().validate_structure(&wire).unwrap();
    assert!(info.flags.is_streaming());
    assert!(info.flags.is_compressed());
    assert!(info.flags.is_encrypted());
    assert_eq!(info.compression, ZnfCompression::Lz4);
    assert_eq!(info.encryption, ZnfEncryption::XChaCha20Poly1305);

    // Streaming reader with partial I/O restores exact bytes.
    let reader = ZnfReader::new().with_encryption_key(EncryptionKeySource::RawKey(key));
    let mut restored = Vec::new();
    let partial_wire_in = PartialIo {
        inner: io::Cursor::new(&wire),
        max_step: 199,
    };
    let mut partial_plain_out = PartialIo {
        inner: &mut restored,
        max_step: 509,
    };
    let (hdr, _meta, p_hash, _c_hash) = reader
        .read_streaming(partial_wire_in, &mut partial_plain_out, None)
        .unwrap();
    assert!(hdr.flags().is_streaming());
    assert_eq!(restored, large);
    assert_eq!(p_hash, znf_integrity::hash(&large));
}

#[test]
fn roundtrip_unicode_and_deep_nested_metadata_with_extensions() {
    let mut meta = ZnfMetadata::new();
    meta.insert_text("title.ur", "زیلویور نیٹو فارمیٹس — مکمل تحفظ");
    meta.insert_text("title.ja", "ゼルビオール・ネイティブ・フォーマット");
    meta.insert_text("emoji", "🔒📦🦀✨");
    meta.insert_bytes("raw_id", vec![0x00, 0x01, 0xFF, 0x80]);
    meta.insert_uint("created_epoch", 1_760_000_000);

    let mut inner_map = BTreeMap::new();
    inner_map.insert("lossless".to_string(), MetadataValue::Bool(true));
    inner_map.insert("offset_delta".to_string(), MetadataValue::Int(-987_654_321));
    inner_map.insert(
        "layers".to_string(),
        MetadataValue::List(vec![
            MetadataValue::Text("core".into()),
            MetadataValue::Text("integrity".into()),
            MetadataValue::Uint(1),
        ]),
    );
    meta.insert("architecture", MetadataValue::Map(inner_map));
    meta.comment = Some("Multilingual container comment — لاہور".into());
    meta.push_extension(0x7100, b"optional-future-hint".to_vec())
        .unwrap();
    meta.push_extension(0x8ABC, vec![1, 2, 3, 4, 5]).unwrap();

    let writer = ZnfWriter::new()
        .with_compression(ZnfCompression::Zstd)
        .with_metadata(meta.clone());
    let container = writer.write_to_vec(b"payload with rich metadata").unwrap();

    let decoded = ZnfReader::new().read_container(&container).unwrap();
    assert_eq!(decoded.payload, b"payload with rich metadata");
    assert_eq!(decoded.metadata.attributes, meta.attributes);
    assert_eq!(decoded.metadata.comment, meta.comment);
    assert_eq!(decoded.metadata.unknown_extensions, meta.unknown_extensions);
    assert!(decoded.metadata.metadata_blake3.is_some());
}

#[test]
fn roundtrip_combined_compression_and_password_encryption() {
    let kdf = KdfParams::new_interactive_test().unwrap();
    let payload = b"Authenticated and compressed ZNF Core container payload!".repeat(100);

    for comp in [ZnfCompression::Zstd, ZnfCompression::Lz4] {
        let writer = ZnfWriter::new().with_compression(comp).with_encryption(
            EncryptionKeySource::PasswordWithParams(b"correct-passphrase".to_vec(), kdf.clone()),
        );
        let wire = writer.write_to_vec(&payload).unwrap();

        let decoded = ZnfReader::new()
            .with_encryption_key(EncryptionKeySource::Password(
                b"correct-passphrase".to_vec(),
            ))
            .read_container(&wire)
            .unwrap();
        assert_eq!(decoded.payload, payload);
    }
}

// ============================================================================
// 2. NEGATIVE & ADVERSARIAL TESTS
// ============================================================================

#[test]
fn negative_invalid_magic_and_truncated_inputs() {
    let mut meta = ZnfMetadata::new();
    meta.insert_text("k", "v");
    let valid = ZnfWriter::new()
        .with_compression(ZnfCompression::Zstd)
        .with_metadata(meta)
        .write_to_vec(b"some payload bytes for truncation testing")
        .unwrap();

    // Bad magic
    let mut bad_magic = valid.clone();
    bad_magic[0] = b'X';
    assert!(matches!(
        ZnfReader::new().read_container(&bad_magic),
        Err(ZnfError::InvalidMagic { .. })
    ));

    // Every single truncation length 0..valid.len() must fail cleanly without panicking.
    for len in 0..valid.len() {
        let res = ZnfReader::new().read_container(&valid[..len]);
        assert!(res.is_err(), "expected error at truncated length {len}");
    }
}

#[test]
fn negative_invalid_versions_flags_and_offsets() {
    let limits = Limits::default();

    // Unsupported major version 0 and 99
    for bad_major in [0u16, 2, 99] {
        let h = ZnfHeader::new(FormatId::CORE, bad_major, 0);
        let bytes = h.to_bytes().unwrap();
        let err = ZnfHeader::decode(&bytes, &limits, None).unwrap_err();
        assert!(err.is_unsupported());
        assert_eq!(
            err,
            ZnfError::UnsupportedMajorVersion {
                found: bad_major,
                supported: 1
            }
        );
    }

    // Unknown critical flag bit (bit 12) rejected on decode
    let mut buf = ZnfHeader::new(FormatId::CORE, 1, 0).to_bytes().unwrap();
    buf[13] |= 0x10; // bit 12
    let crc = ZnfHeader::compute_header_crc(&buf);
    buf[44..48].copy_from_slice(&crc.to_le_bytes());
    let err = ZnfHeader::decode(&buf, &limits, None).unwrap_err();
    assert!(err.is_unsupported());
    assert!(matches!(err, ZnfError::InvalidFlags(_)));

    // Invalid offsets: header_len < 64
    let mut bad_hlen = ZnfHeader::new(FormatId::CORE, 1, 0).to_bytes().unwrap();
    bad_hlen[20..28].copy_from_slice(&32u64.to_le_bytes());
    let crc = ZnfHeader::compute_header_crc(&bad_hlen);
    bad_hlen[44..48].copy_from_slice(&crc.to_le_bytes());
    assert_eq!(
        ZnfHeader::decode(&bad_hlen, &limits, None).unwrap_err(),
        ZnfError::InvalidHeaderLength(32)
    );

    // Invalid offsets: payload_offset < header_len
    let mut bad_poff = ZnfHeader::with_layout(FormatId::CORE, 1, 0, 128, 64, 0);
    let mut out = [0u8; 64];
    assert_eq!(
        bad_poff.encode(&mut out).unwrap_err(),
        ZnfError::InvalidPayloadOffset(64)
    );
    bad_poff.set_payload_offset(128);
    bad_poff.encode(&mut out).unwrap();

    // Integer overflow: payload_offset + payload_len > u64::MAX
    let mut overflow_hdr = ZnfHeader::new(FormatId::CORE, 1, 0).to_bytes().unwrap();
    overflow_hdr[12] |= ZnfFeatureFlags::HAS_METADATA as u8;
    overflow_hdr[28..36].copy_from_slice(&1024u64.to_le_bytes());
    overflow_hdr[36..44].copy_from_slice(&u64::MAX.to_le_bytes());
    let crc = ZnfHeader::compute_header_crc(&overflow_hdr);
    overflow_hdr[44..48].copy_from_slice(&crc.to_le_bytes());
    assert_eq!(
        ZnfHeader::decode(&overflow_hdr, &limits, None).unwrap_err(),
        ZnfError::IntegerOverflow("payload end")
    );
}

#[test]
fn negative_corrupted_payload_and_authentication_failures() {
    let key = SecretKey::generate().unwrap();
    let enc_container = ZnfWriter::new()
        .with_compression(ZnfCompression::Zstd)
        .with_encryption(EncryptionKeySource::RawKey(key.clone()))
        .write_to_vec(b"sensitive payload data")
        .unwrap();

    // 1. Wrong key fails with AuthenticationFailed
    let wrong_key = SecretKey::generate().unwrap();
    let err = ZnfReader::new()
        .with_encryption_key(EncryptionKeySource::RawKey(wrong_key))
        .read_container(&enc_container)
        .unwrap_err();
    assert!(err.is_authentication_failure());

    // 2. Flipping a bit in the encrypted payload / tag fails with AuthenticationFailed
    let hdr = ZnfHeader::decode(&enc_container, &Limits::default(), None).unwrap();
    let p_off = hdr.payload_offset() as usize;
    let mut tampered_ct = enc_container.clone();
    tampered_ct[p_off + 2] ^= 0x80;
    let err2 = ZnfReader::new()
        .with_encryption_key(EncryptionKeySource::RawKey(key.clone()))
        .read_container(&tampered_ct)
        .unwrap_err();
    assert!(err2.is_authentication_failure());

    // 3. Modifying header minor version and recomputing header CRC still fails AEAD AAD check!
    let mut tampered_hdr = enc_container.clone();
    tampered_hdr[10] = 7;
    let new_crc = ZnfHeader::compute_header_crc(&tampered_hdr[..HEADER_LEN]);
    tampered_hdr[44..48].copy_from_slice(&new_crc.to_le_bytes());
    let err3 = ZnfReader::new()
        .with_encryption_key(EncryptionKeySource::RawKey(key))
        .read_container(&tampered_hdr)
        .unwrap_err();
    assert!(err3.is_authentication_failure());

    // 4. Unencrypted container with corrupted payload byte fails with corruption error
    let plain_container = ZnfWriter::new()
        .with_compression(ZnfCompression::None)
        .write_to_vec(b"plain payload bytes")
        .unwrap();
    let mut corrupted = plain_container.clone();
    corrupted[HEADER_LEN + 3] ^= 0xFF;
    let err4 = ZnfReader::new().read_container(&corrupted).unwrap_err();
    assert!(err4.is_corruption());
}

#[test]
fn negative_malformed_compressed_stream_and_unsupported_critical_extensions() {
    // 1.Unsupported critical extension in metadata (0x4500)
    let limits = Limits::default();
    let mut meta_w = TlvWriter::new();
    meta_w
        .push(0x4500, b"critical-future-feature", &limits)
        .unwrap();
    meta_w.push_end();
    let meta_bytes = meta_w.into_bytes();

    let mut hdr = ZnfHeader::with_layout(
        FormatId::CORE,
        1,
        0,
        HEADER_LEN as u64,
        (HEADER_LEN + meta_bytes.len()) as u64,
        0,
    );
    hdr.flags_mut().set(ZnfFeatureFlags::HAS_METADATA, true);
    hdr.flags_mut().set(ZnfFeatureFlags::HAS_FOOTER, true);
    let mut wire = hdr.to_bytes().unwrap().to_vec();
    wire.extend_from_slice(&meta_bytes);
    let mut footer = TlvWriter::new();
    footer.push_end();
    wire.extend_from_slice(footer.as_bytes());

    let err = ZnfReader::new().read_container(&wire).unwrap_err();
    assert!(err.is_unsupported());
    assert_eq!(err, ZnfError::UnsupportedCriticalExtension(0x4500));

    // 2. Malformed compressed stream inside container
    let valid_zstd = ZnfWriter::new()
        .with_compression(ZnfCompression::Zstd)
        .write_to_vec(b"some compressible text payload")
        .unwrap();
    let mut bad_zstd = valid_zstd.clone();
    // Overwrite Zstd magic bytes at payload start (offset 64)
    bad_zstd[64] = 0x00;
    bad_zstd[65] = 0x00;
    let err2 = ZnfReader::new().read_container(&bad_zstd).unwrap_err();
    assert!(err2.is_corruption());
    assert!(matches!(err2, ZnfError::CorruptCompressedPayload(_)));
}

#[test]
fn negative_excessive_declared_lengths_and_cancellation() {
    // Strict limit of 128 bytes expanded
    let mut strict = Limits::strict();
    strict.max_expanded_len = 128;

    let big_container = ZnfWriter::new()
        .with_compression(ZnfCompression::Zstd)
        .write_to_vec(&vec![b'A'; 4096])
        .unwrap();

    let err = ZnfReader::new()
        .with_limits(strict)
        .read_container(&big_container)
        .unwrap_err();
    assert!(matches!(
        err,
        ZnfError::LengthExceedsLimit {
            what: "expanded",
            ..
        }
    ));

    // Cooperative cancellation
    let cancel = AtomicBool::new(true);
    let mut out = Vec::new();
    let cancel_err = ZnfWriter::new()
        .write_streaming(&b"hello"[..], &mut out, Some(&cancel))
        .unwrap_err();
    assert_eq!(cancel_err, ZnfError::Cancelled);
}

// ============================================================================
// 3. COMPATIBILITY & INDEPENDENT CODE PATH TESTS
// ============================================================================

#[test]
fn independent_manual_encode_decoded_by_znf_reader_and_vice_versa() {
    // Path A: Manually construct a valid ZNF Core v1.0 container from raw byte slices
    // according to ZNF-CORE-SPEC.md without using ZnfWriter, then decode with ZnfReader.
    let payload = b"independent vector payload";
    let payload_hash = znf_integrity::hash(payload);

    let mut hdr = ZnfHeader::with_layout(FormatId::CORE, 1, 0, 64, 64, payload.len() as u64);
    hdr.flags_mut().set(ZnfFeatureFlags::HAS_FOOTER, true);
    let hdr_bytes = hdr.to_bytes().unwrap();

    let mut pre_footer = Vec::new();
    pre_footer.extend_from_slice(&hdr_bytes);
    pre_footer.extend_from_slice(payload);
    let container_hash = znf_integrity::hash(&pre_footer);

    let limits = Limits::default();
    let mut footer = TlvWriter::new();
    footer
        .push(TLV_PAYLOAD_BLAKE3, payload_hash.as_bytes(), &limits)
        .unwrap();
    footer
        .push(
            TLV_UNCOMPRESSED_LEN,
            &(payload.len() as u64).to_le_bytes(),
            &limits,
        )
        .unwrap();
    footer
        .push(
            TLV_STORED_PAYLOAD_LEN,
            &(payload.len() as u64).to_le_bytes(),
            &limits,
        )
        .unwrap();
    footer
        .push(TLV_CONTAINER_BLAKE3, container_hash.as_bytes(), &limits)
        .unwrap();
    footer.push_end();

    let mut manual_container = pre_footer;
    manual_container.extend_from_slice(footer.as_bytes());

    // Decode using ZnfReader AND verify byte-for-byte equality with ZnfWriter::write_to_vec!
    let writer_container = ZnfWriter::new().write_to_vec(payload).unwrap();
    assert_eq!(
        manual_container, writer_container,
        "independent manual construction must match ZnfWriter byte-for-byte"
    );

    let decoded = ZnfReader::new().read_container(&manual_container).unwrap();
    assert_eq!(decoded.payload, payload);
    assert_eq!(decoded.payload_blake3, payload_hash);
    assert_eq!(decoded.container_blake3, container_hash);

    // Path B: Manually parse `writer_container` using only raw slice offsets and TlvReader.
    assert_eq!(&writer_container[0..4], b"ZNF\0");
    assert_eq!(
        u32::from_le_bytes(writer_container[4..8].try_into().unwrap()),
        FormatId::CORE.raw()
    );
    let manual_crc = crc32(&[&writer_container[0..44], &writer_container[48..64]].concat());
    let stored_crc = u32::from_le_bytes(writer_container[44..48].try_into().unwrap());
    assert_eq!(manual_crc, stored_crc);

    let footer_start = 64 + payload.len();
    let mut f_reader = TlvReader::new(&writer_container[footer_start..], limits);
    let mut count = 0;
    while let Some(tlv) = f_reader.next_tlv().unwrap() {
        count += 1;
        if tlv.is_end() {
            break;
        }
    }
    assert_eq!(count, 5); // 4 footer TLVs + TLV_END
}

#[test]
fn canonical_core_header_hex_vector() {
    let mut hdr = ZnfHeader::with_layout(FormatId::CORE, 1, 0, 64, 64, 128);
    hdr.set_compression(ZnfCompression::Zstd);
    hdr.flags_mut().set(ZnfFeatureFlags::HAS_FOOTER, true);
    let bytes = hdr.to_bytes().unwrap();

    let expected_hex = "5a4e460002000000010000000900000000000000400000000000000040000000000000008000000000000000cd4965cd01000000000000000000000000000000";
    let actual_hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(actual_hex, expected_hex);
}
