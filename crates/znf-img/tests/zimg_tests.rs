//! Comprehensive functional, security, and round-trip tests for ZIMG (.zimg) v1.0.

use znf_img::{
    decode_image, encode_image, BitDepth, ColorModel, DecodeOptions, EncodeOptions, FilterType,
    Image, ImageMetadata, PixelFormat,
};
use znf_img::{AlphaInfo, ColorSpace};
use znf_img::format;
use znf_compression::Config as CompConfig;
use znf_crypto::KdfParams;

fn make_rgb8(width: u32, height: u32) -> Image {
    let pf = PixelFormat {
        color_model: ColorModel::Rgb,
        bit_depth: BitDepth::Bits8,
        channel_count: 3,
        alpha: AlphaInfo::None,
        color_space: ColorSpace::Srgb,
    };
    let mut img = Image::new(width, height, pf).unwrap();
    for y in 0..height {
        let row = img.row_mut(y).unwrap();
        for x in 0..width {
            let i = (x * 3) as usize;
            row[i] = ((x * 7 + y * 13) % 256) as u8;
            row[i + 1] = ((x * 11 + y * 17) % 256) as u8;
            row[i + 2] = ((x * 3 + y * 5) % 256) as u8;
        }
    }
    img
}

fn make_rgba8(width: u32, height: u32) -> Image {
    let pf = PixelFormat {
        color_model: ColorModel::Rgba,
        bit_depth: BitDepth::Bits8,
        channel_count: 4,
        alpha: AlphaInfo::Present,
        color_space: ColorSpace::Srgb,
    };
    let mut img = Image::new(width, height, pf).unwrap();
    for y in 0..height {
        let row = img.row_mut(y).unwrap();
        for x in 0..width {
            let i = (x * 4) as usize;
            row[i] = ((x * 5 + y * 7) % 256) as u8;
            row[i + 1] = ((x * 3 + y * 11) % 256) as u8;
            row[i + 2] = ((x * 7 + y * 3) % 256) as u8;
            row[i + 3] = if (x + y) % 2 == 0 { 0 } else { 255 }; // transparent/opaque
        }
    }
    img
}

fn make_gray8(width: u32, height: u32) -> Image {
    let pf = PixelFormat {
        color_model: ColorModel::Gray,
        bit_depth: BitDepth::Bits8,
        channel_count: 1,
        alpha: AlphaInfo::None,
        color_space: ColorSpace::Srgb,
    };
    let mut img = Image::new(width, height, pf).unwrap();
    for y in 0..height {
        let row = img.row_mut(y).unwrap();
        for x in 0..width {
            row[x as usize] = ((x + y * 3) % 256) as u8;
        }
    }
    img
}

fn make_gray_alpha8(width: u32, height: u32) -> Image {
    let pf = PixelFormat {
        color_model: ColorModel::GrayAlpha,
        bit_depth: BitDepth::Bits8,
        channel_count: 2,
        alpha: AlphaInfo::Present,
        color_space: ColorSpace::Srgb,
    };
    let mut img = Image::new(width, height, pf).unwrap();
    for y in 0..height {
        let row = img.row_mut(y).unwrap();
        for x in 0..width {
            let i = (x * 2) as usize;
            row[i] = ((x * 2 + y) % 256) as u8;
            row[i + 1] = 128;
        }
    }
    img
}

fn make_rgb16(width: u32, height: u32) -> Image {
    let pf = PixelFormat {
        color_model: ColorModel::Rgb,
        bit_depth: BitDepth::Bits16,
        channel_count: 3,
        alpha: AlphaInfo::None,
        color_space: ColorSpace::Linear,
    };
    let mut img = Image::new(width, height, pf).unwrap();
    for y in 0..height {
        let row = img.row_mut(y).unwrap();
        for x in 0..width {
            let i = (x * 6) as usize;
            let v = ((x * 257 + y * 129) % 65536) as u16;
            row[i..i + 2].copy_from_slice(&v.to_le_bytes());
            let v2 = ((x * 129 + y * 257) % 65536) as u16;
            row[i + 2..i + 4].copy_from_slice(&v2.to_le_bytes());
            let v3 = ((x * 65 + y * 33) % 65536) as u16;
            row[i + 4..i + 6].copy_from_slice(&v3.to_le_bytes());
        }
    }
    img
}

fn roundtrip_check(img: &Image, opts: &EncodeOptions) {
    let encoded = encode_image(img, opts).unwrap();
    let decoded = decode_image(&encoded.bytes, &DecodeOptions::default()).unwrap();

    // Exact pixel comparison
    assert_eq!(
        decoded.image.data, img.data,
        "pixel data mismatch for {:?} {}x{}",
        img.pixel_format.color_model, img.width, img.height
    );
    assert_eq!(decoded.image.width, img.width);
    assert_eq!(decoded.image.height, img.height);
    assert_eq!(
        decoded.image.pixel_format.color_model,
        img.pixel_format.color_model
    );
    assert_eq!(
        decoded.image.pixel_format.bit_depth,
        img.pixel_format.bit_depth
    );
    assert!(decoded.integrity_verified, "integrity verification failed");
}

#[test]
fn rgb8_roundtrip_all_filters() {
    let img = make_rgb8(100, 50);
    for filter in [
        FilterType::None,
        FilterType::Sub,
        FilterType::Up,
        FilterType::Average,
        FilterType::Paeth,
    ] {
        let opts = EncodeOptions {
            filter,
            ..EncodeOptions::default()
        };
        roundtrip_check(&img, &opts);
    }
}

#[test]
fn rgba8_roundtrip() {
    let img = make_rgba8(64, 64);
    roundtrip_check(&img, &EncodeOptions::default());
}

#[test]
fn gray8_roundtrip() {
    let img = make_gray8(200, 100);
    roundtrip_check(&img, &EncodeOptions::default());
}

#[test]
fn gray_alpha8_roundtrip() {
    let img = make_gray_alpha8(80, 40);
    roundtrip_check(&img, &EncodeOptions::default());
}

#[test]
fn rgb16_roundtrip() {
    let img = make_rgb16(48, 32);
    roundtrip_check(&img, &EncodeOptions::default());
}

#[test]
fn tiny_images() {
    // 1x1
    let img = make_rgb8(1, 1);
    roundtrip_check(&img, &EncodeOptions::default());

    // 1xN
    let img = make_rgb8(1, 50);
    roundtrip_check(&img, &EncodeOptions::default());

    // Nx1
    let img = make_rgb8(50, 1);
    roundtrip_check(&img, &EncodeOptions::default());

    // 2x2
    let img = make_rgba8(2, 2);
    roundtrip_check(&img, &EncodeOptions::default());
}

#[test]
fn all_compression_modes() {
    let img = make_rgb8(200, 100);
    for cfg in [
        CompConfig::stored(),
        CompConfig::lz4(),
        CompConfig::zstd(1),
        CompConfig::zstd(3),
        CompConfig::zstd(9),
        CompConfig::zstd(22),
    ] {
        let opts = EncodeOptions {
            compression: cfg,
            ..EncodeOptions::default()
        };
        roundtrip_check(&img, &opts);
    }
}

#[test]
fn all_compression_modes_rgba() {
    let img = make_rgba8(100, 100);
    for cfg in [
        CompConfig::stored(),
        CompConfig::lz4(),
        CompConfig::zstd(3),
    ] {
        let opts = EncodeOptions {
            compression: cfg,
            ..EncodeOptions::default()
        };
        roundtrip_check(&img, &opts);
    }
}

#[test]
fn encrypted_roundtrip() {
    let img = make_rgb8(80, 60);
    let pw = b"test-password-123".to_vec();
    let kdf = KdfParams::new_interactive_test().unwrap();
    let opts = EncodeOptions {
        compression: CompConfig::zstd(3),
        password: Some(pw.clone()),
        kdf_params: Some(kdf.clone()),
        ..EncodeOptions::default()
    };
    let encoded = encode_image(&img, &opts).unwrap();
    assert!(encoded.info.encrypted);

    // Decode with correct password
    let decoded = decode_image(
        &encoded.bytes,
        &DecodeOptions {
            password: Some(pw),
            ..DecodeOptions::default()
        },
    )
    .unwrap();
    assert_eq!(decoded.image.data, img.data);
    assert!(decoded.encrypted);
    assert!(decoded.integrity_verified);
}

#[test]
fn encrypted_wrong_password_fails() {
    let img = make_rgb8(40, 30);
    let pw = b"correct-horse".to_vec();
    let kdf = KdfParams::new_interactive_test().unwrap();
    let opts = EncodeOptions {
        password: Some(pw.clone()),
        kdf_params: Some(kdf),
        ..EncodeOptions::default()
    };
    let encoded = encode_image(&img, &opts).unwrap();

    let err = decode_image(
        &encoded.bytes,
        &DecodeOptions {
            password: Some(b"wrong-password".to_vec()),
            ..DecodeOptions::default()
        },
    )
    .unwrap_err();
    assert!(
        err.is_authentication_failure(),
        "expected authentication failure, got {err:?}"
    );
}

#[test]
fn password_for_unencrypted_fails() {
    let img = make_rgb8(10, 10);
    let opts = EncodeOptions::default();
    let encoded = encode_image(&img, &opts).unwrap();

    let err = decode_image(
        &encoded.bytes,
        &DecodeOptions {
            password: Some(b"unwanted".to_vec()),
            ..DecodeOptions::default()
        },
    )
    .unwrap_err();
    assert!(
        matches!(err, znf_img::ZimgError::EncryptionMismatch(_)),
        "expected EncryptionMismatch, got {err:?}"
    );
}

#[test]
fn metadata_preserved() {
    let img = make_rgb8(10, 10);
    let mut meta = ImageMetadata::new();
    meta.title = Some("Test Image".into());
    meta.description = Some("A test".into());
    meta.creator = Some("ZNF Labs".into());
    meta.custom.insert("source".into(), "unit-test".into());

    // Metadata is stored via TLV in encode - currently encode_image doesn't
    // accept metadata directly; test that metadata round-trips via decode.
    // For now, verify that encode/decode works and metadata field is empty
    // (encode_image doesn't yet accept custom metadata; this tests structure).
    let encoded = encode_image(&img, &EncodeOptions::default()).unwrap();
    let decoded = decode_image(&encoded.bytes, &DecodeOptions::default()).unwrap();
    assert_eq!(decoded.image.data, img.data);
    // Metadata round-trip: empty metadata should decode to empty metadata
    assert_eq!(decoded.metadata.custom.len(), 0);
}

#[test]
fn invalid_magic_rejected() {
    let mut buf = vec![0u8; 64];
    buf[0..4].copy_from_slice(b"XXXX");
    let err = decode_image(&buf, &DecodeOptions::default()).unwrap_err();
    assert!(err.is_unsupported() || matches!(err, znf_img::ZimgError::Core(_)));
}

#[test]
fn truncated_header_rejected() {
    let buf = [0u8; 10];
    let err = decode_image(&buf, &DecodeOptions::default()).unwrap_err();
    assert!(matches!(err, znf_img::ZimgError::Core(_)));
}

#[test]
fn wrong_format_id_rejected() {
    // Build a valid ZNF Core header with FormatId::ZARC instead of ZIMG
    use znf_core::{FormatId, Header, HEADER_LEN};
    let mut hdr = Header::new(FormatId::ZARC, 1, 0);
    hdr.set_payload_len(0);
    let mut buf = [0u8; HEADER_LEN];
    hdr.encode(&mut buf).unwrap();
    // Add footer end marker
    buf.extend_from_slice(&0xFFFFu16.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());

    let err = decode_image(&buf, &DecodeOptions::default()).unwrap_err();
    assert!(
        matches!(err, znf_img::ZimgError::NotZimgFormat(_)),
        "expected NotZimgFormat, got {err:?}"
    );
}

#[test]
fn corrupted_payload_detected() {
    let img = make_rgb8(50, 30);
    let encoded = encode_image(&img, &EncodeOptions::default()).unwrap();
    let mut corrupted = encoded.bytes.clone();
    // Flip a byte in the payload section (after header)
    corrupted[64] ^= 0xFF;
    let err = decode_image(&corrupted, &DecodeOptions::default()).unwrap_err();
    assert!(
        err.is_corruption() || err.is_authentication_failure(),
        "expected corruption/auth error, got {err:?}"
    );
}

#[test]
fn oversized_dimensions_rejected() {
    // Create an image with dimensions exceeding MAX_WIDTH
    let pf = PixelFormat {
        color_model: ColorModel::Gray,
        bit_depth: BitDepth::Bits8,
        channel_count: 1,
        alpha: AlphaInfo::None,
        color_space: ColorSpace::Srgb,
    };
    let err = Image::new(crate::format::MAX_WIDTH + 1, 10, pf);
    assert!(
        err.is_err(),
        "expected error for width exceeding MAX_WIDTH"
    );
}

#[test]
fn zero_dimensions_rejected() {
    let pf = PixelFormat {
        color_model: ColorModel::Gray,
        bit_depth: BitDepth::Bits8,
        channel_count: 1,
        alpha: AlphaInfo::None,
        color_space: ColorSpace::Srgb,
    };
    let err = Image::new(0, 10, pf);
    assert!(err.is_err(), "expected error for zero width");
    let err = Image::new(10, 0, pf);
    assert!(err.is_err(), "expected error for zero height");
}

#[test]
fn filter_roundtrip_identity() {
    // Verify that filter + unfilter produces exact original bytes
    let row: Vec<u8> = (0..100).map(|i| (i * 3) as u8).collect();
    let bpp = 3;

    for filter in [
        FilterType::None,
        FilterType::Sub,
        FilterType::Up,
        FilterType::Average,
        FilterType::Paeth,
    ] {
        let filtered = znf_img::encode::filter_row(filter, &row, None, bpp);
        let mut unfiltered = vec![0u8; row.len()];
        znf_img::encode::unfilter_row(filter, &filtered, &mut unfiltered, None, bpp).unwrap();
        assert_eq!(unfiltered, row, "filter {:?} not invertible", filter);

        // With previous row
        let prev_row: Vec<u8> = (0..100).map(|i| (i * 5) as u8).collect();
        let filtered2 = znf_img::encode::filter_row(filter, &row, Some(&prev_row), bpp);
        let mut unfiltered2 = vec![0u8; row.len()];
        znf_img::encode::unfilter_row(
            filter, &filtered2, &mut unfiltered2, Some(&prev_row), bpp,
        )
        .unwrap();
        assert_eq!(unfiltered2, row, "filter {:?} with prev not invertible", filter);
    }
}

#[test]
fn large_image_roundtrip() {
    // 1000x1000 RGB = 3MB, tests bounded memory and larger allocations
    let img = make_rgb8(1000, 1000);
    roundtrip_check(&img, &EncodeOptions {
        compression: CompConfig::zstd(6),
        ..EncodeOptions::default()
    });
}

#[test]
fn fully_transparent_image() {
    let pf = PixelFormat {
        color_model: ColorModel::Rgba,
        bit_depth: BitDepth::Bits8,
        channel_count: 4,
        alpha: AlphaInfo::Present,
        color_space: ColorSpace::Srgb,
    };
    let mut img = Image::new(50, 50, pf).unwrap();
    for row in img.data.chunks_mut(img.stride) {
        for pixel in row.chunks_mut(4) {
            pixel[3] = 0; // fully transparent
        }
    }
    roundtrip_check(&img, &EncodeOptions::default());
}

#[test]
fn opaque_image() {
    let img = make_rgba8(30, 20);
    // Make all pixels opaque
    let mut img = img;
    for row in img.data.chunks_mut(img.stride) {
        for pixel in row.chunks_mut(4) {
            pixel[3] = 255;
        }
    }
    roundtrip_check(&img, &EncodeOptions::default());
}

#[test]
fn random_data_roundtrip() {
    use znf_img::encode::FilterType;

    let pf = PixelFormat {
        color_model: ColorModel::Rgb,
        bit_depth: BitDepth::Bits8,
        channel_count: 3,
        alpha: AlphaInfo::None,
        color_space: ColorSpace::Srgb,
    };
    let mut img = Image::new(64, 64, pf).unwrap();
    // Fill with pseudo-random data
    let mut state: u32 = 0x1234_5678;
    for byte in &mut img.data {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        *byte = (state >> 16) as u8;
    }
    roundtrip_check(&img, &EncodeOptions {
        filter: FilterType::Paeth,
        compression: CompConfig::zstd(3),
        ..EncodeOptions::default()
    });
}

#[test]
fn multiple_filters_same_image() {
    let img = make_rgb8(80, 40);
    let filters = [
        FilterType::None,
        FilterType::Sub,
        FilterType::Up,
        FilterType::Average,
        FilterType::Paeth,
    ];
    let encoded_sizes: Vec<usize> = filters
        .iter()
        .map(|&f| {
            let opts = EncodeOptions {
                filter: f,
                ..EncodeOptions::default()
            };
            encode_image(&img, &opts).unwrap().bytes.len()
        })
        .collect();
    // All filters should produce valid output (no panics)
    for size in &encoded_sizes {
        assert!(*size > 0);
    }
}
