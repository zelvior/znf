//! Reproducible release-mode benchmark for ZIMG (.zimg) v1.0.
//!
//! Run with:
//!   cargo run --release -p znf-img --example zimg_bench --offline

use std::time::Instant;
use znf_compression::Config as CompConfig;
use znf_img::{
    decode_image, encode_image, BitDepth, ColorModel, DecodeOptions, EncodeOptions, FilterType,
    Image, ImageMetadata, PixelFormat,
};
use znf_img::{AlphaInfo, ColorSpace};

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
            row[i + 3] = if (x + y) % 2 == 0 { 0 } else { 255 };
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

fn bench(name: &str, img: &Image, opts: &EncodeOptions) {
    let input_bytes = img.data.len();

    // Encode
    let t0 = Instant::now();
    let encoded = encode_image(img, opts).unwrap();
    let enc_elapsed = t0.elapsed();
    let enc_speed = input_bytes as f64 / enc_elapsed.as_secs_f64() / 1_048_576.0;

    // Decode
    let t0 = Instant::now();
    let decoded = decode_image(&encoded.bytes, &DecodeOptions::default()).unwrap();
    let dec_elapsed = t0.elapsed();
    let dec_speed = input_bytes as f64 / dec_elapsed.as_secs_f64() / 1_048_576.0;

    // Verify
    let t0 = Instant::now();
    assert!(decoded.integrity_verified, "integrity failed for {name}");
    assert_eq!(decoded.image.data, img.data, "pixel mismatch for {name}");
    let verify_elapsed = t0.elapsed();
    let verify_speed = input_bytes as f64 / verify_elapsed.as_secs_f64() / 1_048_576.0;

    // Extract speed (decode is effectively extraction)
    let extract_speed = dec_speed;

    let ratio = input_bytes as f64 / encoded.bytes.len() as f64;

    println!(
        "{:<12} {:>12} B {:>13} B {:>8.2}:1 {:>12.1} MiB/s {:>10.0} us {:>13.1} MiB/s {:>13.1} MiB/s",
        name,
        input_bytes,
        encoded.bytes.len(),
        ratio,
        enc_speed,
        enc_elapsed.as_micros(),
        verify_speed,
        extract_speed
    );
}

fn main() {
    println!("ZIMG v1.0 Benchmark (release mode)");
    println!("====================================");
    println!();

    // Corpus: mixed synthetic images
    let images: Vec<(&str, Image)> = vec![
        ("rgb8-64x64", make_rgb8(64, 64)),
        ("rgb8-512x512", make_rgb8(512, 512)),
        ("rgba8-256x256", make_rgba8(256, 256)),
        ("gray8-512x512", make_gray8(512, 512)),
    ];

    let configs: Vec<(&str, EncodeOptions)> = vec![
        (
            "Store",
            EncodeOptions {
                compression: CompConfig::stored(),
                filter: FilterType::None,
                ..EncodeOptions::default()
            },
        ),
        (
            "LZ4",
            EncodeOptions {
                compression: CompConfig::lz4(),
                filter: FilterType::None,
                ..EncodeOptions::default()
            },
        ),
        (
            "Zstd-1",
            EncodeOptions {
                compression: CompConfig::zstd(1),
                filter: FilterType::None,
                ..EncodeOptions::default()
            },
        ),
        (
            "Zstd-3",
            EncodeOptions {
                compression: CompConfig::zstd(3),
                filter: FilterType::None,
                ..EncodeOptions::default()
            },
        ),
        (
            "Zstd-9",
            EncodeOptions {
                compression: CompConfig::zstd(9),
                filter: FilterType::None,
                ..EncodeOptions::default()
            },
        ),
    ];

    println!(
        "{:<12} {:>12} {:>13} {:>8} {:>12} {:>10} {:>13} {:>13}",
        "Mode",
        "Input Size",
        "Archive Size",
        "Ratio",
        "Create Speed",
        "Verify",
        "Extract Speed",
        ""
    );
    println!(
        "{:<12} {:>12} {:>13} {:>8} {:>12} {:>10} {:>13} {:>13}",
        "------------",
        "------------",
        "-------------",
        "--------",
        "------------",
        "----------",
        "-------------",
        "------------"
    );

    for (img_name, img) in &images {
        println!("  Image: {img_name} ({}x{} pixels)", img.width, img.height);
        for (cfg_name, opts) in &configs {
            bench(cfg_name, img, opts);
        }
        println!();
    }
}
