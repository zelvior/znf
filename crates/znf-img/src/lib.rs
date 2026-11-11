//! ZIMG (`.zimg`) Lossless Image Format.
//!
//! `znf-img` implements a modern, privacy-focused, lossless-first image format
//! built on the ZNF Core v1.0 binary foundation. It provides:
//!
//! - **Lossless image preservation:** exact pixel sample round-trip for RGB, RGBA,
//!   grayscale, and grayscale+alpha at 8-bit and 16-bit depths.
//! - **Excellent compression:** Zstandard and LZ4 integration with optional scanline
//!   filtering (None, Sub, Up, Average, Paeth) for improved ratios.
//! - **Fast encoding and decoding:** streaming-friendly chunked architecture with
//!   bounded memory usage.
//! - **Color accuracy:** sRGB, linear RGB, and embedded ICC profile support.
//! - **Metadata privacy:** optional, user-controlled metadata; no automatic collection
//!   of device, location, or identity information.
//! - **Optional encryption:** XChaCha20-Poly1305 + Argon2id for payload and metadata.
//! - **Integrity verification:** BLAKE3 per-chunk and whole-file hashing.
//! - **Resource limits:** configurable bounds against decompression bombs and
//!   oversized dimensions.
//!
//! See `specifications/zimg/ZIMG-SPEC.md` for the normative binary specification.
//!
//! # Example
//!
//! ```rust
//! use znf_img::{encode_image, decode_image, EncodeOptions, DecodeOptions};
//! use znf_img::{Image, PixelFormat, ColorModel, BitDepth, AlphaInfo, ColorSpace};
//!
//! // Create a 2x2 RGB image.
//! let pf = PixelFormat {
//!     color_model: ColorModel::Rgb,
//!     bit_depth: BitDepth::Bits8,
//!     channel_count: 3,
//!     alpha: AlphaInfo::None,
//!     color_space: ColorSpace::Srgb,
//! };
//! let mut image = Image::new(2, 2, pf).unwrap();
//! // Row 0: red, green
//! image.row_mut(0).unwrap().copy_from_slice(&[255, 0, 0, 0, 255, 0]);
//! // Row 1: blue, white
//! image.row_mut(1).unwrap().copy_from_slice(&[0, 0, 255, 255, 255, 255]);
//!
//! let encoded = encode_image(&image, &EncodeOptions::default()).unwrap();
//! let decoded = decode_image(&encoded.bytes, &DecodeOptions::default()).unwrap();
//! assert_eq!(decoded.image.data, image.data);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::all)]

pub mod chunk;
pub mod decode;
pub mod encode;
pub mod error;
pub mod format;
pub mod image;
pub mod metadata;

pub use chunk::{Chunk, ChunkStrategy};
pub use decode::{decode_image, DecodeOptions, DecodedImage};
pub use encode::{encode_image, CompressionStrategy, EncodeOptions, FilterType, ImageInfo};
pub use error::ZimgError;
pub use format::{
    COMPRESSION_LZ4, COMPRESSION_STORED, COMPRESSION_ZSTD, DEFAULT_COMPRESSION_LEVEL, MAX_HEIGHT,
    MAX_TOTAL_PIXELS, MAX_WIDTH, TLV_ARCHIVE_BLAKE3, TLV_ZIMG_CHUNK_INDEX, TLV_ZIMG_COLOR_SPACE,
    TLV_ZIMG_COMPRESSION, TLV_ZIMG_DIMENSIONS, TLV_ZIMG_ENCRYPTED_METADATA, TLV_ZIMG_ICC_PROFILE,
    TLV_ZIMG_METADATA, TLV_ZIMG_PIXEL_BLAKE3, TLV_ZIMG_PIXEL_FORMAT, ZIMG_SPEC_VERSION,
};
pub use image::{AlphaInfo, BitDepth, ColorModel, ColorSpace, Image, PixelFormat};
pub use metadata::ImageMetadata;
