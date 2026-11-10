//! ZIMG (.zimg) binary format constants and TLV type definitions.
//!
//! All multi-byte integers are little-endian. The file uses the ZNF Core
//! 64-byte header with `FormatId::ZIMG` (3).

/// ZIMG specification version implemented by this crate.
pub const ZIMG_SPEC_VERSION: (u16, u16) = (1, 0);

/// Magic bytes: ZIMG files reuse the ZNF Core magic `ZNF\0`; the format is
/// identified by `FormatId::ZIMG` in the header.

/// --- TLV Types for the Metadata Section (between header and payload) ---

/// Image dimensions: `width: u32 LE` || `height: u32 LE`.
pub const TLV_ZIMG_DIMENSIONS: u16 = 0x0100;

/// Pixel format descriptor:
/// `color_model: u8` || `bit_depth: u8` || `channel_count: u8` || `alpha_info: u8`.
pub const TLV_ZIMG_PIXEL_FORMAT: u16 = 0x0101;

/// Color space identifier:
/// `color_space: u8` (0=sRGB, 1=Linear RGB, 2=ICC profile follows in separate TLV).
pub const TLV_ZIMG_COLOR_SPACE: u16 = 0x0102;

/// Embedded ICC profile: raw ICC profile bytes.
pub const TLV_ZIMG_ICC_PROFILE: u16 = 0x0103;

/// Compression configuration:
/// `algorithm: u8` || `level: u8` (Zstd level 1-22, ignored for others).
pub const TLV_ZIMG_COMPRESSION: u16 = 0x0104;

/// Structured image metadata (title, description, creator, etc. as UTF-8 key-value).
pub const TLV_ZIMG_METADATA: u16 = 0x0105;

/// Encrypted metadata (nonce(24B) || XChaCha20-Poly1305(plaintext, aad=header)).
pub const TLV_ZIMG_ENCRYPTED_METADATA: u16 = 0x0106;

/// --- TLV Types for the Footer Section (after payload) ---

/// Chunk index table: sequence of `chunk_index` records.
pub const TLV_ZIMG_CHUNK_INDEX: u16 = 0x0200;

/// Per-chunk BLAKE3 hashes for pixel data verification.
pub const TLV_ZIMG_PIXEL_BLAKE3: u16 = 0x0201;

/// Whole-archive BLAKE3 over `header || metadata || payload`.
pub const TLV_ARCHIVE_BLAKE3: u16 = 0x0202;

/// --- Color Model Identifiers ---

/// Grayscale (single channel).
pub const COLOR_MODEL_GRAY: u8 = 0;
/// Grayscale + Alpha (two channels).
pub const COLOR_MODEL_GRAY_ALPHA: u8 = 1;
/// RGB (three channels).
pub const COLOR_MODEL_RGB: u8 = 2;
/// RGBA (four channels).
pub const COLOR_MODEL_RGBA: u8 = 3;

/// --- Alpha Info Identifiers ---

/// No alpha channel present.
pub const ALPHA_NONE: u8 = 0;
/// Alpha channel is present (associated/premultiplied not assumed).
pub const ALPHA_PRESENT: u8 = 1;

/// --- Color Space Identifiers ---

/// sRGB color space.
pub const COLOR_SPACE_SRGB: u8 = 0;
/// Linear RGB color space.
pub const COLOR_SPACE_LINEAR: u8 = 1;
/// ICC profile embedded (see TLV_ZIMG_ICC_PROFILE).
pub const COLOR_SPACE_ICC: u8 = 2;

/// --- Bit Depths ---

pub const BIT_DEPTH_8: u8 = 8;
pub const BIT_DEPTH_16: u8 = 16;

/// --- Compression Algorithm Identifiers (match znf_compression::Algorithm) ---

pub const COMPRESSION_STORED: u8 = 0;
pub const COMPRESSION_ZSTD: u8 = 1;
pub const COMPRESSION_LZ4: u8 = 2;

/// Default Zstandard compression level.
pub const DEFAULT_COMPRESSION_LEVEL: u8 = 3;

/// Maximum image width (prevents overflow in stride calculations).
pub const MAX_WIDTH: u32 = 1_000_000;

/// Maximum image height.
pub const MAX_HEIGHT: u32 = 1_000_000;

/// Maximum total pixels (width * height).
pub const MAX_TOTAL_PIXELS: u64 = 256_000_000; // ~16K x 16K equivalent ceiling

/// Default maximum chunk size for pixel data (1 MiB uncompressed per chunk).
pub const DEFAULT_CHUNK_UNCOMPRESSED_MAX: usize = 1_048_576;

/// Chunk index entry wire format (all LE):
///   chunk_index: u32 | uncompressed_offset: u64 | stored_offset: u64 |
///   uncompressed_len: u32 | stored_len: u32 | blake3_hash: [u8; 32]
pub const CHUNK_INDEX_ENTRY_LEN: usize = 4 + 8 + 8 + 4 + 4 + 32; // 60 bytes
