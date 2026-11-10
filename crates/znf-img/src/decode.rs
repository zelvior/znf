//! ZIMG decoding pipeline: parsing, decompression, integrity verification.

use znf_compression::{decompress_bytes, Algorithm, Config as CompConfig};
use znf_core::{FormatId, Header, Limits, HEADER_LEN, is_critical_extension_type, metadata::TLV_KDF_PARAMS};
use znf_crypto::{decrypt, NONCE_LEN, TAG_LEN};
use znf_integrity::{hash, Hash, Hasher, HASH_LEN};

use crate::chunk::Chunk;
use crate::encode::{unfilter_row, FilterType};
use crate::error::ZimgError;
use crate::format::*;
use crate::image::{ColorSpace, Image, PixelFormat};
use crate::metadata::ImageMetadata;

/// Decoding configuration.
#[derive(Debug, Clone)]
pub struct DecodeOptions {
    /// Optional decryption password.
    pub password: Option<Vec<u8>>,
    /// Resource limits.
    pub limits: Limits,
    /// Whether to verify per-chunk BLAKE3 hashes.
    pub verify_integrity: bool,
}

impl Default for DecodeOptions {
    fn default() -> Self {
        DecodeOptions {
            password: None,
            limits: Limits::default(),
            verify_integrity: true,
        }
    }
}

/// Decoded image result.
#[derive(Debug, Clone)]
pub struct DecodedImage {
    /// The decoded image.
    pub image: Image,
    /// Image metadata (title, description, etc.).
    pub metadata: ImageMetadata,
    /// Color space.
    pub color_space: ColorSpace,
    /// Whether the archive was encrypted.
    pub encrypted: bool,
    /// Whether integrity verification passed.
    pub integrity_verified: bool,
}

/// Determine compression algorithm from ZNF Core header.
fn compression_from_header(header: &Header) -> Result<Algorithm, ZimgError> {
    match header.compression() {
        znf_core::ZnfCompression::None => Ok(Algorithm::None),
        znf_core::ZnfCompression::Zstd => Ok(Algorithm::Zstd),
        znf_core::ZnfCompression::Lz4 => Ok(Algorithm::Lz4),
    }
}

/// Decode ZIMG file bytes into an image.
pub fn decode_image(bytes: &[u8], opts: &DecodeOptions) -> Result<DecodedImage, ZimgError> {
    if bytes.len() < HEADER_LEN {
        return Err(ZimgError::Core(znf_core::Error::TooShort {
            need: HEADER_LEN,
            have: bytes.len(),
        }));
    }

    // Decode and validate the ZNF Core header.
    let header = Header::decode(bytes, &opts.limits, Some(bytes.len() as u64))?;
    if header.format_id() != FormatId::ZIMG {
        return Err(ZimgError::NotZimgFormat(header.format_id().raw()));
    }

    let meta_start = header.header_len() as usize;
    let payload_start = header.payload_offset() as usize;
    let payload_end = header
        .payload_offset()
        .checked_add(header.payload_len())
        .ok_or_else(|| ZimgError::InvalidDimensions("payload end overflow".into()))? as usize;

    if payload_end > bytes.len() {
        return Err(ZimgError::MalformedImage("payload extends past end of file".into()));
    }

    // Derive decryption key if encrypted.
    let derived_key = if header.flags().is_encrypted() {
        let pw = opts
            .password
            .as_deref()
            .ok_or_else(|| ZimgError::EncryptionMismatch("image is encrypted; password required"))?;
        // Find KDF params in metadata section.
        let kdf_params = find_kdf_params(&bytes[meta_start..payload_start], &opts.limits)?;
        Some(kdf_params.derive_key(pw)?)
    } else {
        if opts.password.is_some() {
            return Err(ZimgError::EncryptionMismatch(
                "password supplied for unencrypted image",
            ));
        }
        None
    };

    // Parse metadata section.
    let mut width: Option<u32> = None;
    let mut height: Option<u32> = None;
    let mut pixel_format_wire: Option<[u8; 4]> = None;
    let mut color_space: ColorSpace = ColorSpace::Srgb;
    let mut metadata = ImageMetadata::new();
    let mut encryption_meta: Option<Vec<u8>> = None; // encrypted metadata TLV

    if header.flags().has_metadata() {
        parse_metadata_tlvs(
            &bytes[meta_start..payload_start],
            &opts.limits,
            &mut width,
            &mut height,
            &mut pixel_format_wire,
            &mut color_space,
            &mut metadata,
            &mut encryption_meta,
        )?;
    }

    let w = width.ok_or_else(|| ZimgError::MalformedImage("missing dimensions TLV".into()))?;
    let h = height.ok_or_else(|| ZimgError::MalformedImage("missing height TLV".into()))?;
    let pf_wire = pixel_format_wire
        .ok_or_else(|| ZimgError::MalformedImage("missing pixel format TLV".into()))?;
    let pf = PixelFormat::from_wire_bytes(pf_wire)
        .ok_or_else(|| ZimgError::UnsupportedPixelFormat("invalid pixel format bytes".into()))?;

    // If encrypted metadata was present, decrypt it now.
    if let Some(enc_meta) = encryption_meta {
        if let Some(ref key) = derived_key {
            // The encrypted metadata TLV format: nonce(24B) || ciphertext+tag.
            // AAD = header bytes.
            let nonce_arr: [u8; NONCE_LEN] = enc_meta[..NONCE_LEN]
                .try_into()
                .map_err(|_| ZimgError::MalformedImage("encrypted metadata nonce too short".into()))?;
            let ct = &enc_meta[NONCE_LEN..];
            let header_bytes = header.to_bytes()?;
            let decrypted = decrypt(key, &nonce_arr, ct, &header_bytes)?;
            metadata = ImageMetadata::decode(&decrypted)?;
        } else {
            return Err(ZimgError::EncryptionMismatch(
                "encrypted metadata present but no decryption key",
            ));
        }
    }

    // Parse payload: compressed + optionally encrypted chunks.
    let payload_bytes = &bytes[payload_start..payload_end];

    // Parse footer TLVs to get chunk index.
    let footer_start = payload_end;
    let footer_bytes = &bytes[footer_start..];

    let mut chunk_index: Option<Vec<Chunk>> = None;
    let mut pixel_hashes: Option<Vec<Hash>> = None;
    let mut archive_blake3: Option<Hash> = None;
    let mut saw_footer_end = false;

    // Simple TLV iteration over footer.
    let mut offset = 0;
    while offset + 4 <= footer_bytes.len() {
        let ty = u16::from_le_bytes(footer_bytes[offset..offset + 2].try_into().unwrap());
        let len = u32::from_le_bytes(footer_bytes[offset + 2..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if offset + len > footer_bytes.len() {
            return Err(ZimgError::MalformedImage("footer TLV length exceeds remaining bytes".into()));
        }
        let value = &footer_bytes[offset..offset + len];
        offset += len;

        if ty == 0xFFFF {
            saw_footer_end = true;
            break;
        }

        match ty {
            TLV_ZIMG_CHUNK_INDEX => {
                if len < 4 {
                    return Err(ZimgError::MalformedImage("chunk index too short".into()));
                }
                let count = u32::from_le_bytes(value[0..4].try_into().unwrap()) as usize;
                let mut chunks = Vec::with_capacity(count);
                let mut off = 4;
                for _ in 0..count {
                    if off + CHUNK_INDEX_ENTRY_LEN > value.len() {
                        return Err(ZimgError::MalformedImage("chunk index entry truncated".into()));
                    }
                    chunks.push(Chunk::from_wire_bytes(&value[off..off + CHUNK_INDEX_ENTRY_LEN])
                        .ok_or_else(|| ZimgError::MalformedImage("invalid chunk index entry".into()))?);
                    off += CHUNK_INDEX_ENTRY_LEN;
                }
                chunk_index = Some(chunks);
            }
            TLV_ZIMG_PIXEL_BLAKE3 => {
                if len < 4 {
                    return Err(ZimgError::MalformedImage("pixel hash list too short".into()));
                }
                let count = u32::from_le_bytes(value[0..4].try_into().unwrap()) as usize;
                let mut hashes = Vec::with_capacity(count);
                let mut off = 4;
                for _ in 0..count {
                    if off + HASH_LEN > value.len() {
                        return Err(ZimgError::MalformedImage("pixel hash truncated".into()));
                    }
                    hashes.push(Hash::from_bytes(value[off..off + HASH_LEN].try_into().unwrap()));
                    off += HASH_LEN;
                }
                pixel_hashes = Some(hashes);
            }
            TLV_ARCHIVE_BLAKE3 => {
                if len != HASH_LEN {
                    return Err(ZimgError::MalformedImage("archive BLAKE3 wrong length".into()));
                }
                archive_blake3 = Some(Hash::from_bytes(value.try_into().unwrap()));
            }
            _ => {
                // Unknown TLV: check if critical.
                if is_critical_extension_type(ty) {
                    return Err(ZimgError::Core(znf_core::Error::UnsupportedCriticalExtension(ty)));
                }
                // Non-critical: ignore.
            }
        }
    }

    if !saw_footer_end {
        return Err(ZimgError::MalformedImage("footer missing TLV_END marker".into()));
    }

    let chunks = chunk_index.ok_or_else(|| ZimgError::MalformedImage("missing chunk index".into()))?;

    // Verify whole-archive BLAKE3.
    if let Some(expected) = archive_blake3 {
        let mut hasher = Hasher::new();
        hasher.update(&bytes[..payload_end]);
        let computed = hasher.finalize();
        if computed != expected {
            return Err(ZimgError::Integrity(znf_integrity::IntegrityError::HashMismatch {
                expected: expected.to_hex(),
                computed: computed.to_hex(),
            }));
        }
    }

    // Decompress + decrypt each chunk and reconstruct image.
    let bpp = pf.bytes_per_pixel();
    let row_bytes = w as usize * bpp;
    let algo = compression_from_header(&header)?;

    let mut image = Image::new(w, h, pf)?;

    for chunk in &chunks {
        // Extract stored bytes for this chunk.
        let chunk_start = chunk.stored_offset as usize;
        let chunk_end = chunk_start
            .checked_add(chunk.stored_len as usize)
            .ok_or_else(|| ZimgError::InvalidDimensions("chunk stored range overflow".into()))?;
        if chunk_end > payload_bytes.len() {
            return Err(ZimgError::MalformedImage("chunk stored range exceeds payload".into()));
        }
        let stored = &payload_bytes[chunk_start..chunk_end];

        // Decrypt if needed.
        let decompressed_input: Vec<u8> = if let Some(ref key) = derived_key {
            if stored.len() < NONCE_LEN + TAG_LEN {
                return Err(ZimgError::MalformedImage("encrypted chunk too short".into()));
            }
            let nonce_arr: [u8; NONCE_LEN] = stored[..NONCE_LEN].try_into().unwrap();
            let ct = &stored[NONCE_LEN..];
            let aad = (chunk.index as u32).to_le_bytes().to_vec();
            decrypt(key, &nonce_arr, ct, &aad)?
        } else {
            stored.to_vec()
        };

        // Decompress.
        let mut uncompressed = Vec::new();
        decompress_bytes(
            &decompressed_input,
            algo,
            &CompConfig {
                algorithm: algo,
                zstd_level: 3,
                max_expanded_len: opts.limits.max_expanded_len,
            },
        )?;

        // Verify chunk hash if requested.
        if opts.verify_integrity {
            let computed_hash = hash(&uncompressed);
            if let Some(ref expected_hashes) = pixel_hashes {
                if chunk.index as usize < expected_hashes.len() {
                    if computed_hash != expected_hashes[chunk.index as usize] {
                        return Err(ZimgError::Integrity(
                            znf_integrity::IntegrityError::HashMismatch {
                                expected: expected_hashes[chunk.index as usize].to_hex(),
                                computed: computed_hash.to_hex(),
                            },
                        ));
                    }
                }
            }
        }

        // Unfilter and write rows.
        let uncompressed_offset = chunk.uncompressed_offset as usize;
        let rows_this_chunk = (chunk.uncompressed_len as usize) / row_bytes;
        let mut unfiltered_row = vec![0u8; row_bytes];
        let mut prev_row: Option<Vec<u8>> = None;

        let mut u_offset = 0;
        for r in 0..rows_this_chunk {
            let y = (uncompressed_offset as u64 / row_bytes as u64 + r as u64) as u32;
            // Each filtered row is 1 filter byte + row_bytes data bytes.
            let row_filtered_len = 1 + row_bytes;
            let row_start = u_offset;
            let row_end = row_start + row_filtered_len;
            if row_end > uncompressed.len() {
                return Err(ZimgError::MalformedImage("chunk uncompressed data truncated".into()));
            }
            let filter_byte = uncompressed[row_start];
            let filter = FilterType::from_byte(filter_byte)
                .ok_or_else(|| ZimgError::MalformedImage("invalid filter type".into()))?;
            let filtered_data = &uncompressed[row_start + 1..row_end];
            unfilter_row(filter, filtered_data, &mut unfiltered_row, prev_row.as_deref(), bpp)?;
            // Write to image.
            let img_row = image.row_mut(y)?;
            img_row.copy_from_slice(&unfiltered_row[..row_bytes]);
            prev_row = Some(unfiltered_row.clone());
            u_offset = row_end;
        }
    }

    let integrity_verified = opts.verify_integrity && archive_blake3.is_some();

    Ok(DecodedImage {
        image,
        metadata,
        color_space,
        encrypted: derived_key.is_some(),
        integrity_verified,
    })
}

/// Find KDF params TLV in the metadata section.
fn find_kdf_params(metadata: &[u8], limits: &Limits) -> Result<znf_crypto::KdfParams, ZimgError> {
    let mut offset = 0;
    while offset + 4 <= metadata.len() {
        let ty = u16::from_le_bytes(metadata[offset..offset + 2].try_into().unwrap());
        let len = u32::from_le_bytes(metadata[offset + 2..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if offset + len > metadata.len() {
            return Err(ZimgError::MalformedImage("metadata TLV length exceeds remaining".into()));
        }
        let value = &metadata[offset..offset + len];
        offset += len;

        if ty == 0xFFFF {
            break;
        }

        if ty == TLV_KDF_PARAMS {
            return znf_crypto::KdfParams::decode(value).map_err(ZimgError::from);
        }

        if is_critical_extension_type(ty) {
            return Err(ZimgError::Core(znf_core::Error::UnsupportedCriticalExtension(ty)));
        }
    }
    Err(ZimgError::MalformedImage("missing KDF params TLV".into()))
}

/// Parse all metadata TLVs from the metadata section.
fn parse_metadata_tlvs(
    metadata: &[u8],
    limits: &Limits,
    width: &mut Option<u32>,
    height: &mut Option<u32>,
    pixel_format_wire: &mut Option<[u8; 4]>,
    color_space: &mut ColorSpace,
    metadata_out: &mut ImageMetadata,
    encryption_meta: &mut Option<Vec<u8>>,
) -> Result<(), ZimgError> {
    let mut offset = 0;
    while offset + 4 <= metadata.len() {
        let ty = u16::from_le_bytes(metadata[offset..offset + 2].try_into().unwrap());
        let len = u32::from_le_bytes(metadata[offset + 2..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if offset + len > metadata.len() {
            return Err(ZimgError::MalformedImage("metadata TLV length exceeds remaining".into()));
        }
        let value = &metadata[offset..offset + len];
        offset += len;

        if ty == 0xFFFF {
            break;
        }

        match ty {
            TLV_ZIMG_DIMENSIONS => {
                if len != 8 {
                    return Err(ZimgError::MalformedImage("dimensions TLV wrong length".into()));
                }
                *width = Some(u32::from_le_bytes(value[0..4].try_into().unwrap()));
                *height = Some(u32::from_le_bytes(value[4..8].try_into().unwrap()));
            }
            TLV_ZIMG_PIXEL_FORMAT => {
                if len != 4 {
                    return Err(ZimgError::MalformedImage("pixel format TLV wrong length".into()));
                }
                *pixel_format_wire = Some(value.try_into().unwrap());
            }
            TLV_ZIMG_COLOR_SPACE => {
                if len != 1 {
                    return Err(ZimgError::MalformedImage("color space TLV wrong length".into()));
                }
                *color_space = ColorSpace::from_byte(value[0])
                    .ok_or_else(|| ZimgError::UnsupportedPixelFormat("invalid color space".into()))?;
            }
            TLV_ZIMG_ICC_PROFILE => {
                // ICC profile bytes preserved; not parsed here.
            }
            TLV_ZIMG_COMPRESSION => {
                // Compression info is informational.
            }
            TLV_ZIMG_METADATA => {
                *metadata_out = ImageMetadata::decode(value)?;
            }
            TLV_ZIMG_ENCRYPTED_METADATA => {
                *encryption_meta = Some(value.to_vec());
            }
            TLV_KDF_PARAMS => {
                // Handled separately by find_kdf_params.
            }
            _ => {
                if is_critical_extension_type(ty) {
                    return Err(ZimgError::Core(znf_core::Error::UnsupportedCriticalExtension(ty)));
                }
            }
        }
    }
    Ok(())
}
