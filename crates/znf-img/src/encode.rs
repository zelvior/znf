//! ZIMG encoding pipeline: scanline filtering + compression.

use znf_compression::{compress_bytes, Algorithm, Config as CompConfig};
use znf_core::{Flags, FormatId, Header, ZnfCompression, ZnfEncryption, HEADER_LEN};
use znf_crypto::{encrypt, generate_nonce, KdfParams, NONCE_LEN};
use znf_integrity::{hash, Hash, Hasher, HASH_LEN};

use crate::chunk::{compute_chunks, Chunk, ChunkStrategy};
use crate::error::ZimgError;
use crate::format::*;
use crate::image::{Image, PixelFormat};
use crate::metadata::ImageMetadata;

/// Scanline filter type (matches PNG filter semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FilterType {
    /// No filtering.
    None = 0,
    /// Sub: difference from the pixel to the left.
    Sub = 1,
    /// Up: difference from the pixel above.
    Up = 2,
    /// Average: average of left and above.
    Average = 3,
    /// Paeth predictor.
    Paeth = 4,
}

impl FilterType {
    #[must_use]
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(FilterType::None),
            1 => Some(FilterType::Sub),
            2 => Some(FilterType::Up),
            3 => Some(FilterType::Average),
            4 => Some(FilterType::Paeth),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Automatic compression strategy selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionStrategy {
    /// Use the configured algorithm exactly as specified.
    Fixed,
    /// Try each available algorithm and pick the smallest output for each chunk.
    Adaptive,
}

/// Encoding configuration.
#[derive(Debug, Clone)]
pub struct EncodeOptions {
    /// Compression algorithm.
    pub compression: CompConfig,
    /// Filter type to apply before compression.
    pub filter: FilterType,
    /// When `true`, selects the best filter per row (Sub/Up/Average/Paeth)
    /// based on which produces the smallest filtered output for that row.
    pub adaptive_filter: bool,
    /// Chunking strategy.
    pub chunk_strategy: ChunkStrategy,
    /// Compression strategy: fixed algorithm or adaptive per-chunk selection.
    pub compression_strategy: CompressionStrategy,
    /// Optional encryption password.
    pub password: Option<Vec<u8>>,
    /// Optional KDF parameters (required if password is set).
    pub kdf_params: Option<KdfParams>,
    /// Optional structured metadata to store in the metadata TLV section.
    pub metadata: Option<ImageMetadata>,
    /// Optional ICC profile bytes to embed (sets color space to ICC).
    pub icc_profile: Option<Vec<u8>>,
    /// Whether to include per-chunk integrity in footer.
    pub include_integrity: bool,
}

impl Default for EncodeOptions {
    fn default() -> Self {
        EncodeOptions {
            compression: CompConfig::zstd(DEFAULT_COMPRESSION_LEVEL as i32),
            filter: FilterType::None,
            adaptive_filter: false,
            chunk_strategy: ChunkStrategy::default(),
            compression_strategy: CompressionStrategy::Fixed,
            password: None,
            kdf_params: None,
            metadata: None,
            icc_profile: None,
            include_integrity: true,
        }
    }
}

/// Apply a scanline filter to a row, producing filtered bytes.
/// `prev_row` may be empty for the first row.
pub(crate) fn filter_row(
    filter: FilterType,
    row: &[u8],
    prev_row: Option<&[u8]>,
    bpp: usize,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(row.len() + 1);
    out.push(filter.as_byte());
    match filter {
        FilterType::None => {
            out.extend_from_slice(row);
        }
        FilterType::Sub => {
            for (i, &byte) in row.iter().enumerate() {
                let left = if i >= bpp { row[i - bpp] } else { 0 };
                out.push(byte.wrapping_sub(left));
            }
        }
        FilterType::Up => {
            if let Some(prev) = prev_row {
                for (i, &byte) in row.iter().enumerate() {
                    out.push(byte.wrapping_sub(prev[i]));
                }
            } else {
                out.extend_from_slice(row);
            }
        }
        FilterType::Average => {
            for (i, &byte) in row.iter().enumerate() {
                let left = if i >= bpp { row[i - bpp] } else { 0 };
                let up = prev_row.map_or(0, |p| p[i]);
                out.push(byte.wrapping_sub(((left as u16 + up as u16) / 2) as u8));
            }
        }
        FilterType::Paeth => {
            for (i, &byte) in row.iter().enumerate() {
                let left = if i >= bpp { row[i - bpp] } else { 0 };
                let up = prev_row.map_or(0, |p| p[i]);
                let up_left = if i >= bpp {
                    prev_row.map_or(0, |p| p[i - bpp])
                } else {
                    0
                };
                let p = left as i32 + up as i32 - up_left as i32;
                let pa = (p - left as i32).abs();
                let pb = (p - up as i32).abs();
                let pc = (p - up_left as i32).abs();
                let predictor = if pa <= pb && pa <= pc {
                    left
                } else if pb <= pc {
                    up
                } else {
                    up_left
                };
                out.push(byte.wrapping_sub(predictor));
            }
        }
    }
    out
}

/// Unfilter a row, reconstructing original bytes.
pub(crate) fn unfilter_row(
    filter: FilterType,
    filtered: &[u8],
    row: &mut [u8],
    prev_row: Option<&[u8]>,
    bpp: usize,
) -> Result<(), ZimgError> {
    if filtered.is_empty() {
        return Err(ZimgError::MalformedImage("empty filtered row".into()));
    }
    let data = &filtered[1..];
    match filter {
        FilterType::None => {
            row.copy_from_slice(data);
        }
        FilterType::Sub => {
            for (i, &byte) in data.iter().enumerate() {
                let left = if i >= bpp { row[i - bpp] } else { 0 };
                row[i] = byte.wrapping_add(left);
            }
        }
        FilterType::Up => {
            if let Some(prev) = prev_row {
                for (i, &byte) in data.iter().enumerate() {
                    row[i] = byte.wrapping_add(prev[i]);
                }
            } else {
                row.copy_from_slice(data);
            }
        }
        FilterType::Average => {
            for (i, &byte) in data.iter().enumerate() {
                let left = if i >= bpp { row[i - bpp] } else { 0 };
                let up = prev_row.map_or(0, |p| p[i]);
                row[i] = byte.wrapping_add(((left as u16 + up as u16) / 2) as u8);
            }
        }
        FilterType::Paeth => {
            for (i, &byte) in data.iter().enumerate() {
                let left = if i >= bpp { row[i - bpp] } else { 0 };
                let up = prev_row.map_or(0, |p| p[i]);
                let up_left = if i >= bpp {
                    prev_row.map_or(0, |p| p[i - bpp])
                } else {
                    0
                };
                let p = left as i32 + up as i32 - up_left as i32;
                let pa = (p - left as i32).abs();
                let pb = (p - up as i32).abs();
                let pc = (p - up_left as i32).abs();
                let predictor = if pa <= pb && pa <= pc {
                    left
                } else if pb <= pc {
                    up
                } else {
                    up_left
                };
                row[i] = byte.wrapping_add(predictor);
            }
        }
    }
    Ok(())
}

/// Select the best filter for a single row by trying all filters and picking
/// the one that produces the smallest filtered output. Ties resolve to the
/// first filter in this order: None, Sub, Up, Average, Paeth.
#[must_use]
pub(crate) fn select_best_filter(row: &[u8], prev_row: Option<&[u8]>, bpp: usize) -> FilterType {
    let filters = [
        FilterType::None,
        FilterType::Sub,
        FilterType::Up,
        FilterType::Average,
        FilterType::Paeth,
    ];
    let mut best = FilterType::None;
    let mut best_len = usize::MAX;
    for f in filters {
        let filtered = filter_row(f, row, prev_row, bpp);
        if filtered.len() < best_len {
            best_len = filtered.len();
            best = f;
        }
    }
    best
}

/// Try compressing `data` with each algorithm and return the smallest result
/// along with the chosen algorithm.
///
/// When `strategy` is `Fixed`, uses the configured algorithm as-is.
/// When `Adaptive`, tests all algorithms and picks the smallest output.
///
/// Returns `(compressed_bytes, chosen_algorithm)`.
#[must_use]
pub(crate) fn compress_with_strategy(
    data: &[u8],
    opts: &EncodeOptions,
) -> Result<(Vec<u8>, Algorithm), ZimgError> {
    match opts.compression_strategy {
        CompressionStrategy::Fixed => {
            let c = compress_bytes(data, &opts.compression)?;
            Ok((c, opts.compression.algorithm))
        }
        CompressionStrategy::Adaptive => {
            let mut best: Option<(Vec<u8>, Algorithm)> = None;
            for algo in [Algorithm::None, Algorithm::Zstd, Algorithm::Lz4] {
                let cfg = match algo {
                    Algorithm::None => CompConfig::stored(),
                    Algorithm::Zstd => CompConfig::zstd(opts.compression.zstd_level),
                    Algorithm::Lz4 => CompConfig::lz4(),
                };
                match compress_bytes(data, &cfg) {
                    Ok(c) => {
                        let is_better = best.as_ref().map_or(true, |b| c.len() < b.0.len());
                        if is_better {
                            best = Some((c, algo));
                        }
                    }
                    Err(_) => continue,
                }
            }
            best.ok_or_else(|| {
                ZimgError::Compression(znf_compression::CompressionError::CorruptData(
                    "all compression strategies failed".into(),
                ))
            })
        }
    }
}

/// Pick the single best compression algorithm globally by testing on the
/// first chunk's uncompressed data, so the header algorithm stays consistent
/// across all chunks. Returns the chosen algorithm.
#[must_use]
pub(crate) fn select_global_algorithm(first_chunk_data: &[u8], opts: &EncodeOptions) -> Algorithm {
    let mut best_algo = opts.compression.algorithm;
    let mut best_len = usize::MAX;
    for algo in [Algorithm::None, Algorithm::Zstd, Algorithm::Lz4] {
        let cfg = match algo {
            Algorithm::None => CompConfig::stored(),
            Algorithm::Zstd => CompConfig::zstd(opts.compression.zstd_level),
            Algorithm::Lz4 => CompConfig::lz4(),
        };
        if let Ok(c) = compress_bytes(first_chunk_data, &cfg) {
            if c.len() < best_len {
                best_len = c.len();
                best_algo = algo;
            }
        }
    }
    best_algo
}

/// Encoded image output, ready to be written to a file.
#[derive(Debug, Clone)]
pub struct EncodedImage {
    /// Raw file bytes (header + metadata + payload + footer).
    pub bytes: Vec<u8>,
    /// Image info.
    pub info: ImageInfo,
}

/// Image information returned after encoding.
#[derive(Debug, Clone)]
pub struct ImageInfo {
    pub width: u32,
    pub height: u32,
    pub pixel_format: PixelFormat,
    pub compression: CompConfig,
    pub uncompressed_len: u64,
    pub stored_len: u64,
    pub encrypted: bool,
}

/// Encode an `Image` into ZIMG file bytes.
pub fn encode_image(image: &Image, opts: &EncodeOptions) -> Result<EncodedImage, ZimgError> {
    let width = image.width;
    let height = image.height;
    let pf = image.pixel_format;
    let bpp = pf.bytes_per_pixel();
    let row_bytes = width as usize * bpp;

    // Validate dimensions.
    if width == 0 || height == 0 {
        return Err(ZimgError::InvalidDimensions(
            "width and height must be non-zero".into(),
        ));
    }
    if width > MAX_WIDTH || height > MAX_HEIGHT {
        return Err(ZimgError::InvalidDimensions(format!(
            "dimensions {}x{} exceed limits ({}x{})",
            width, height, MAX_WIDTH, MAX_HEIGHT
        )));
    }

    // Compute chunks.
    let chunk_specs = compute_chunks(width, height, bpp, image.stride, opts.chunk_strategy);

    // When using adaptive compression, select a single global algorithm from
    // the first chunk so the header stays consistent across all chunks.
    let mut effective_compression = opts.compression;
    if opts.compression_strategy == CompressionStrategy::Adaptive && !chunk_specs.is_empty() {
        // Build the first chunk's uncompressed data to test algorithms on.
        let first = &chunk_specs[0];
        let rows_this_chunk = first.2 as usize;
        let mut first_chunk_data = Vec::with_capacity((1 + row_bytes) * rows_this_chunk);
        for r in 0..rows_this_chunk {
            let y = first.0 + r as u32;
            let row_data = image.row(y)?;
            let prev = if y > 0 { Some(image.row(y - 1)?) } else { None };
            let filter = if opts.adaptive_filter {
                select_best_filter(row_data, prev, bpp)
            } else {
                opts.filter
            };
            let filtered = filter_row(filter, row_data, prev, bpp);
            first_chunk_data.extend_from_slice(&filtered);
        }
        let chosen = select_global_algorithm(&first_chunk_data, opts);
        effective_compression = CompConfig {
            algorithm: chosen,
            ..opts.compression
        };
    }

    // Filter + compress each chunk.
    let mut stored_chunks: Vec<Vec<u8>> = Vec::with_capacity(chunk_specs.len());
    let mut chunk_hashes: Vec<Hash> = Vec::with_capacity(chunk_specs.len());
    let mut total_stored: u64 = 0;
    let mut total_uncompressed: u64 = 0;

    for (_row_start, _offset, row_count) in &chunk_specs {
        let rows_this_chunk = *row_count as usize;
        let mut chunk_uncompressed = Vec::with_capacity((1 + row_bytes) * rows_this_chunk);

        for r in 0..rows_this_chunk {
            let y = _row_start + r as u32;
            let row_data = image.row(y)?;
            let prev = if y > 0 { Some(image.row(y - 1)?) } else { None };
            let filter = if opts.adaptive_filter {
                select_best_filter(row_data, prev, bpp)
            } else {
                opts.filter
            };
            let filtered = filter_row(filter, row_data, prev, bpp);
            chunk_uncompressed.extend_from_slice(&filtered);
        }

        let chunk_hash = hash(&chunk_uncompressed);
        chunk_hashes.push(chunk_hash);

        // Compress using the selected strategy (with global algorithm for Adaptive).
        let (stored, _chosen_algo) = compress_with_strategy(
            &chunk_uncompressed,
            &EncodeOptions {
                compression: effective_compression,
                compression_strategy: CompressionStrategy::Fixed,
                ..opts.clone()
            },
        )?;
        total_stored += stored.len() as u64;
        total_uncompressed += chunk_uncompressed.len() as u64;
        stored_chunks.push(stored);
    }

    // Encrypt if requested.
    let derived_key = if let Some(ref pw) = opts.password {
        let params = opts
            .kdf_params
            .as_ref()
            .ok_or_else(|| ZimgError::EncryptionMismatch("password set but no KDF params"))?;
        Some(params.derive_key(pw)?)
    } else {
        None
    };

    // Build payload section (compressed + optionally encrypted chunks).
    let mut payload = Vec::new();
    let mut chunk_stored_offsets: Vec<u64> = Vec::new();
    let mut chunk_stored_lens: Vec<u32> = Vec::new();

    for (ci, stored) in stored_chunks.iter().enumerate() {
        let chunk_start = payload.len() as u64;
        let stored_len = if let Some(ref key) = derived_key {
            let nonce = generate_nonce()?;
            let aad = (ci as u32).to_le_bytes().to_vec();
            let encrypted = encrypt(key, &nonce, stored, &aad)?;
            // Write nonce (24B) || ciphertext+tag.
            payload.extend_from_slice(&nonce);
            payload.extend_from_slice(&encrypted);
            (NONCE_LEN + encrypted.len()) as u32
        } else {
            payload.extend_from_slice(stored);
            stored.len() as u32
        };
        chunk_stored_offsets.push(chunk_start);
        chunk_stored_lens.push(stored_len);
    }

    // Build metadata section.
    let mut metadata_bytes = Vec::new();

    // Dimensions.
    {
        let mut dim = Vec::new();
        dim.extend_from_slice(&width.to_le_bytes());
        dim.extend_from_slice(&height.to_le_bytes());
        metadata_bytes.extend_from_slice(&(TLV_ZIMG_DIMENSIONS as u16).to_le_bytes());
        metadata_bytes.extend_from_slice(&(dim.len() as u32).to_le_bytes());
        metadata_bytes.extend_from_slice(&dim);
    }

    // Pixel format.
    {
        let pf_bytes = pf.to_wire_bytes();
        metadata_bytes.extend_from_slice(&(TLV_ZIMG_PIXEL_FORMAT as u16).to_le_bytes());
        metadata_bytes.extend_from_slice(&(pf_bytes.len() as u32).to_le_bytes());
        metadata_bytes.extend_from_slice(&pf_bytes);
    }

    // Determine effective color space: ICC profile takes precedence.
    let effective_color_space = if opts.icc_profile.is_some() {
        crate::image::ColorSpace::Icc
    } else {
        pf.color_space
    };

    // Color space.
    {
        let cs = [effective_color_space.as_byte()];
        metadata_bytes.extend_from_slice(&(TLV_ZIMG_COLOR_SPACE as u16).to_le_bytes());
        metadata_bytes.extend_from_slice(&(cs.len() as u32).to_le_bytes());
        metadata_bytes.extend_from_slice(&cs);
    }

    // Embedded ICC profile (if provided).
    if let Some(ref icc) = opts.icc_profile {
        metadata_bytes.extend_from_slice(&(TLV_ZIMG_ICC_PROFILE as u16).to_le_bytes());
        metadata_bytes.extend_from_slice(&(icc.len() as u32).to_le_bytes());
        metadata_bytes.extend_from_slice(icc);
    }

    // Structured metadata (if provided).
    if let Some(ref meta) = opts.metadata {
        let meta_bytes = meta.encode();
        metadata_bytes.extend_from_slice(&(TLV_ZIMG_METADATA as u16).to_le_bytes());
        metadata_bytes.extend_from_slice(&(meta_bytes.len() as u32).to_le_bytes());
        metadata_bytes.extend_from_slice(&meta_bytes);
    }

    // Compression.
    {
        let comp_algo = match effective_compression.algorithm {
            Algorithm::None => COMPRESSION_STORED,
            Algorithm::Zstd => COMPRESSION_ZSTD,
            Algorithm::Lz4 => COMPRESSION_LZ4,
        };
        let comp_level = effective_compression.zstd_level as u8;
        let comp_bytes = [comp_algo, comp_level];
        metadata_bytes.extend_from_slice(&(TLV_ZIMG_COMPRESSION as u16).to_le_bytes());
        metadata_bytes.extend_from_slice(&(comp_bytes.len() as u32).to_le_bytes());
        metadata_bytes.extend_from_slice(&comp_bytes);
    }

    let meta_len = metadata_bytes.len() as u64;

    // Build footer section.
    let mut footer = Vec::new();

    // Chunk index.
    {
        let mut idx = Vec::new();
        let count = chunk_specs.len() as u32;
        idx.extend_from_slice(&count.to_le_bytes());
        for (ci, spec) in chunk_specs.iter().enumerate() {
            let rows = spec.2 as usize;
            let entry = Chunk {
                index: ci as u32,
                uncompressed_offset: spec.1,
                stored_offset: chunk_stored_offsets[ci],
                // uncompressed_len includes the 1-byte filter prefix per row
                // so the decoder can reconstruct row boundaries exactly.
                uncompressed_len: ((1 + row_bytes) * rows) as u32,
                stored_len: chunk_stored_lens[ci],
                blake3_hash: chunk_hashes[ci],
            };
            idx.extend_from_slice(&entry.to_wire_bytes());
        }
        footer.extend_from_slice(&(TLV_ZIMG_CHUNK_INDEX as u16).to_le_bytes());
        footer.extend_from_slice(&(idx.len() as u32).to_le_bytes());
        footer.extend_from_slice(&idx);
    }

    // Per-chunk BLAKE3 hashes.
    if opts.include_integrity {
        let mut hashes = Vec::new();
        let count = chunk_hashes.len() as u32;
        hashes.extend_from_slice(&count.to_le_bytes());
        for h in &chunk_hashes {
            hashes.extend_from_slice(h.as_bytes());
        }
        footer.extend_from_slice(&(TLV_ZIMG_PIXEL_BLAKE3 as u16).to_le_bytes());
        footer.extend_from_slice(&(hashes.len() as u32).to_le_bytes());
        footer.extend_from_slice(&hashes);
    }

    // Build flags.
    let mut flags = Flags::default();
    flags.set(Flags::HAS_METADATA, meta_len > 0);
    flags.set(Flags::HAS_FOOTER, true);
    if opts.compression.algorithm != Algorithm::None {
        flags.set(Flags::COMPRESSED, true);
    }
    if derived_key.is_some() {
        flags.set(Flags::ENCRYPTED, true);
    }

    // Build header.
    let mut hdr = Header::new(FormatId::ZIMG, 1, 0);
    hdr.flags_mut().set(Flags::HAS_METADATA, meta_len > 0);
    hdr.flags_mut().set(Flags::HAS_FOOTER, true);
    hdr.set_compression(ZnfCompression::from_algorithm(
        effective_compression.algorithm,
    ));
    if derived_key.is_some() {
        hdr.set_encryption(ZnfEncryption::XChaCha20Poly1305);
    }
    let payload_offset = HEADER_LEN as u64 + meta_len;
    let payload_len = payload.len() as u64;
    hdr.set_payload_offset(payload_offset);
    hdr.set_payload_len(payload_len);

    let mut header_bytes = [0u8; 64];
    hdr.encode(&mut header_bytes)?;

    // Compute archive BLAKE3 over header || metadata || payload.
    let mut hasher = Hasher::new();
    hasher.update(&header_bytes);
    hasher.update(&metadata_bytes);
    hasher.update(&payload);
    let archive_hash = hasher.finalize();

    // Add archive BLAKE3 to footer.
    footer.extend_from_slice(&(TLV_ARCHIVE_BLAKE3 as u16).to_le_bytes());
    footer.extend_from_slice(&(HASH_LEN as u32).to_le_bytes());
    footer.extend_from_slice(archive_hash.as_bytes());

    // Add TLV_END.
    footer.extend_from_slice(&0xFFFFu16.to_le_bytes());
    footer.extend_from_slice(&0u32.to_le_bytes());

    // Assemble final file.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&header_bytes);
    bytes.extend_from_slice(&metadata_bytes);
    bytes.extend_from_slice(&payload);
    bytes.extend_from_slice(&footer);

    // Reflect the effective color space (ICC overrides) in the info.
    let info_pf = PixelFormat {
        color_space: effective_color_space,
        ..pf
    };

    Ok(EncodedImage {
        bytes,
        info: ImageInfo {
            width,
            height,
            pixel_format: info_pf,
            compression: opts.compression.clone(),
            uncompressed_len: total_uncompressed,
            stored_len: total_stored,
            encrypted: derived_key.is_some(),
        },
    })
}
