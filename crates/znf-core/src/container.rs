//! High-level ZNF Core Container Engine (`ZnfWriter`, `ZnfReader`, `ZnfValidator`).
//!
//! Connects ZNF Core headers, structured metadata, BLAKE3 integrity, lossless
//! compression (`Store`, `Zstd`, `LZ4`), authenticated encryption
//! (`XChaCha20-Poly1305` + `Argon2id` / 256-bit `SecretKey`), and bounded-memory
//! streaming (`Read` / `Write`).
//!
//! # Integrity & Authentication Coverage
//!
//! 1. **Header CRC-32 (`header[44..48]`):** Covers `header[0..44] || header[48..64]`
//!    (all 60 non-CRC header bytes). Detects accidental header corruption before
//!    trusting offsets.
//! 2. **Metadata BLAKE3 (`TLV_METADATA_BLAKE3 = 0x0030`):** Covers all preceding
//!    bytes in the Metadata TLV section (`metadata[0..tlv_start]`). Non-circular.
//! 3. **Payload BLAKE3 (`TLV_PAYLOAD_BLAKE3 = 0x0110`):** Covers the exact original
//!    uncompressed, unencrypted payload bytes (`0..uncompressed_len`).
//! 4. **Container Pre-Footer BLAKE3 (`TLV_CONTAINER_BLAKE3 = 0x0102`):** Covers
//!    `header (64B) || metadata_section || payload_section`. Non-circular because
//!    it resides in the Footer section.
//! 5. **AEAD Authentication (`XChaCha20-Poly1305`):**
//!    - Contiguous mode (`!Flags::STREAMING`): encrypts the compressed payload with
//!      `AAD = header[0..64] || metadata_bytes`.
//!    - Streaming mode (`Flags::STREAMING`): encrypts each chunk `i` with
//!      `nonce = chunk_nonce(base_nonce, i)` and
//!      `AAD = header[0..64] || metadata_bytes || i.to_le_bytes()`, and authenticates
//!      the stream termination and footer digests via `TLV_FOOTER_AUTH_TAG (0x0113)`
//!      under `nonce = chunk_nonce(base_nonce, u64::MAX)`.

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use znf_compression::{compress_bytes, decompress_bytes, Config as CompConfig};
use znf_crypto::{
    chunk_nonce, decrypt, encrypt, generate_nonce, KdfParams, SecretKey, NONCE_LEN, TAG_LEN,
};
use znf_integrity::{hash, Hash, Hasher, HASH_LEN};
use znf_stream::{read_chunk, write_chunk, write_end_chunk, BoundedReader, MAX_CHUNK_SIZE};

use crate::error::ZnfError;
use crate::flags::ZnfFeatureFlags;
use crate::header::{
    FormatId, ZnfCompression, ZnfEncryption, ZnfFormatVersion, ZnfHeader, HEADER_LEN,
};
use crate::limits::Limits;
use crate::metadata::ZnfMetadata;
use crate::tlv::{is_critical_extension_type, TlvReader, TlvWriter};

/// Footer TLV type: 32-byte BLAKE3 digest over `header || metadata || payload`.
pub const TLV_CONTAINER_BLAKE3: u16 = 0x0102;
/// Footer TLV type: 32-byte BLAKE3 digest over original uncompressed payload bytes.
pub const TLV_PAYLOAD_BLAKE3: u16 = 0x0110;
/// Footer TLV type: `u64` LE original uncompressed payload length.
pub const TLV_UNCOMPRESSED_LEN: u16 = 0x0111;
/// Footer TLV type: `u64` LE stored payload byte length (used in streaming mode).
pub const TLV_STORED_PAYLOAD_LEN: u16 = 0x0112;
/// Footer TLV type: Authenticated AEAD footer seal (`chunk_count || uncompressed_len || payload_blake3 || container_blake3`).
pub const TLV_FOOTER_AUTH_TAG: u16 = 0x0113;

/// Default streaming chunk size (64 KiB).
pub const DEFAULT_STREAM_BUFFER_SIZE: usize = 64 * 1024;

/// Minimum streaming chunk size (1 KiB).
pub const MIN_STREAM_BUFFER_SIZE: usize = 1024;

/// Key material or password source for container encryption/decryption.
#[derive(Clone)]
pub enum EncryptionKeySource {
    /// Derive key from password using production `Argon2id` defaults (or parameters from file on read).
    Password(Vec<u8>),
    /// Derive key from password using explicit `Argon2id` parameters (for writer configuration).
    PasswordWithParams(Vec<u8>, KdfParams),
    /// Direct 256-bit `SecretKey`.
    RawKey(SecretKey),
}

impl std::fmt::Debug for EncryptionKeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptionKeySource::Password(_) => {
                f.write_str("EncryptionKeySource::Password([REDACTED])")
            }
            EncryptionKeySource::PasswordWithParams(_, params) => f
                .debug_tuple("EncryptionKeySource::PasswordWithParams")
                .field(&"[REDACTED]")
                .field(params)
                .finish(),
            EncryptionKeySource::RawKey(_) => {
                f.write_str("EncryptionKeySource::RawKey([REDACTED])")
            }
        }
    }
}

/// Safe, redacted diagnostic summary of a ZNF container.
///
/// Never exposes secret keys, passwords, or sensitive metadata values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerInfo {
    /// Format identifier (`FormatId::CORE`, `FormatId::ZARC`, etc.).
    pub format_id: FormatId,
    /// Format version (`major.minor`).
    pub version: ZnfFormatVersion,
    /// Feature flags.
    pub flags: ZnfFeatureFlags,
    /// Compression identifier from header.
    pub compression: ZnfCompression,
    /// Encryption identifier from header.
    pub encryption: ZnfEncryption,
    /// Total header length in bytes.
    pub header_len: u64,
    /// Payload start offset in bytes.
    pub payload_offset: u64,
    /// Stored payload length in bytes.
    pub payload_len: u64,
    /// Uncompressed payload length (from footer, if available).
    pub uncompressed_len: Option<u64>,
    /// Number of top-level metadata attributes.
    pub metadata_attribute_count: usize,
    /// Number of preserved non-critical extension TLVs in metadata.
    pub metadata_extension_count: usize,
    /// Verified metadata BLAKE3 digest.
    pub metadata_blake3: Option<Hash>,
    /// Verified payload BLAKE3 digest.
    pub payload_blake3: Option<Hash>,
    /// Verified pre-footer container BLAKE3 digest.
    pub container_blake3: Option<Hash>,
}

/// Builder and encoder for ZNF Core binary containers.
#[derive(Debug, Clone)]
pub struct ZnfWriter {
    format_id: FormatId,
    version: ZnfFormatVersion,
    compression: ZnfCompression,
    zstd_level: i32,
    encryption: Option<EncryptionKeySource>,
    metadata: ZnfMetadata,
    limits: Limits,
    buffer_size: usize,
}

impl Default for ZnfWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl ZnfWriter {
    /// Create a new `ZnfWriter` for `FormatId::CORE` v1.0 with default settings.
    #[must_use]
    pub fn new() -> Self {
        ZnfWriter {
            format_id: FormatId::CORE,
            version: ZnfFormatVersion::V1_0,
            compression: ZnfCompression::None,
            zstd_level: 3,
            encryption: None,
            metadata: ZnfMetadata::new(),
            limits: Limits::default(),
            buffer_size: DEFAULT_STREAM_BUFFER_SIZE,
        }
    }

    /// Set the container `FormatId`.
    #[must_use]
    pub fn with_format_id(mut self, format_id: FormatId) -> Self {
        self.format_id = format_id;
        self
    }

    /// Set the container `ZnfFormatVersion`.
    #[must_use]
    pub fn with_version(mut self, version: ZnfFormatVersion) -> Self {
        self.version = version;
        self
    }

    /// Configure payload compression algorithm.
    #[must_use]
    pub fn with_compression(mut self, compression: ZnfCompression) -> Self {
        self.compression = compression;
        self
    }

    /// Configure Zstandard compression level (`1..=22`).
    #[must_use]
    pub fn with_zstd_level(mut self, level: i32) -> Self {
        self.zstd_level = level.clamp(1, 22);
        self
    }

    /// Configure payload authenticated encryption (`XChaCha20-Poly1305`).
    #[must_use]
    pub fn with_encryption(mut self, source: EncryptionKeySource) -> Self {
        self.encryption = Some(source);
        self
    }

    /// Set structured container metadata.
    #[must_use]
    pub fn with_metadata(mut self, metadata: ZnfMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    /// Configure resource limits.
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Configure streaming chunk buffer size (clamped to `1 KiB ..= 16 MiB`).
    #[must_use]
    pub fn with_buffer_size(mut self, buffer_size: usize) -> Self {
        self.buffer_size = buffer_size.clamp(MIN_STREAM_BUFFER_SIZE, MAX_CHUNK_SIZE);
        self
    }

    fn resolve_write_encryption(
        &self,
        meta: &mut ZnfMetadata,
    ) -> Result<Option<(SecretKey, [u8; NONCE_LEN])>, ZnfError> {
        match &self.encryption {
            None => Ok(None),
            Some(EncryptionKeySource::Password(pw)) => {
                let params = KdfParams::new_default()?;
                let key = params.derive_key(pw)?;
                let nonce = generate_nonce()?;
                meta.kdf_params = Some(params);
                meta.payload_nonce = Some(nonce);
                Ok(Some((key, nonce)))
            }
            Some(EncryptionKeySource::PasswordWithParams(pw, params)) => {
                let key = params.derive_key(pw)?;
                let nonce = generate_nonce()?;
                meta.kdf_params = Some(params.clone());
                meta.payload_nonce = Some(nonce);
                Ok(Some((key, nonce)))
            }
            Some(EncryptionKeySource::RawKey(key)) => {
                let nonce = generate_nonce()?;
                meta.payload_nonce = Some(nonce);
                Ok(Some((key.clone(), nonce)))
            }
        }
    }

    /// Encode a complete ZNF Core container (contiguous payload) into `writer`.
    ///
    /// # Errors
    ///
    /// Returns [`ZnfError`] if metadata/payload limits are exceeded or I/O fails.
    pub fn write_container<W: Write>(&self, payload: &[u8], mut writer: W) -> Result<(), ZnfError> {
        self.limits.check(
            "expanded",
            payload.len() as u64,
            self.limits.max_expanded_len,
        )?;

        let mut meta = self.metadata.clone();
        let crypto_ctx = self.resolve_write_encryption(&mut meta)?;
        let meta_bytes = meta.encode(&self.limits)?;

        // 1. Compute BLAKE3 of original uncompressed payload.
        let payload_blake3 = hash(payload);
        let uncompressed_len = payload.len() as u64;

        // 2. Compress payload if requested.
        let comp_cfg = CompConfig {
            algorithm: self.compression.to_algorithm(),
            zstd_level: self.zstd_level,
            max_expanded_len: self.limits.max_expanded_len,
        };
        let compressed = compress_bytes(payload, &comp_cfg)?;

        let stored_len = if crypto_ctx.is_some() {
            (compressed.len() + TAG_LEN) as u64
        } else {
            compressed.len() as u64
        };
        self.limits
            .check("payload", stored_len, self.limits.max_payload_len)?;

        // 3. Build and encode 64-byte header.
        let payload_offset = (HEADER_LEN + meta_bytes.len()) as u64;
        let mut header = ZnfHeader::with_layout(
            self.format_id,
            self.version.major,
            self.version.minor,
            HEADER_LEN as u64,
            payload_offset,
            stored_len,
        );
        header.set_compression(self.compression);
        if crypto_ctx.is_some() {
            header.set_encryption(ZnfEncryption::XChaCha20Poly1305);
        }
        if !meta_bytes.is_empty() {
            header.flags_mut().set(ZnfFeatureFlags::HAS_METADATA, true);
        }
        header.flags_mut().set(ZnfFeatureFlags::HAS_FOOTER, true);

        let header_bytes = header.to_bytes()?;

        // 4. Encrypt compressed payload if configured, binding header || metadata as AAD.
        let stored_payload = if let Some((ref key, ref nonce)) = crypto_ctx {
            let mut aad = Vec::with_capacity(HEADER_LEN + meta_bytes.len());
            aad.extend_from_slice(&header_bytes);
            aad.extend_from_slice(&meta_bytes);
            encrypt(key, nonce, &compressed, &aad)?
        } else {
            compressed
        };

        // 5. Compute whole-container pre-footer BLAKE3 over header || metadata || payload.
        let mut container_hasher = Hasher::new();
        container_hasher.update(&header_bytes);
        container_hasher.update(&meta_bytes);
        container_hasher.update(&stored_payload);
        let container_blake3 = container_hasher.finalize();

        // 6. Encode Footer TLV section.
        let mut footer = TlvWriter::new();
        footer.push(TLV_PAYLOAD_BLAKE3, payload_blake3.as_bytes(), &self.limits)?;
        footer.push(
            TLV_UNCOMPRESSED_LEN,
            &uncompressed_len.to_le_bytes(),
            &self.limits,
        )?;
        footer.push(
            TLV_STORED_PAYLOAD_LEN,
            &stored_len.to_le_bytes(),
            &self.limits,
        )?;
        footer.push(
            TLV_CONTAINER_BLAKE3,
            container_blake3.as_bytes(),
            &self.limits,
        )?;
        if let Some((ref key, ref base_nonce)) = crypto_ctx {
            let seal = compute_footer_seal(
                key,
                base_nonce,
                &header_bytes,
                &meta_bytes,
                1,
                uncompressed_len,
                &payload_blake3,
                &container_blake3,
            )?;
            footer.push(TLV_FOOTER_AUTH_TAG, &seal, &self.limits)?;
        }
        footer.push_end();

        // 7. Write all sections.
        writer.write_all(&header_bytes)?;
        writer.write_all(&meta_bytes)?;
        writer.write_all(&stored_payload)?;
        writer.write_all(footer.as_bytes())?;
        Ok(())
    }

    /// Encode a complete ZNF Core container into a `Vec<u8>`.
    pub fn write_to_vec(&self, payload: &[u8]) -> Result<Vec<u8>, ZnfError> {
        let mut out = Vec::new();
        self.write_container(payload, &mut out)?;
        Ok(out)
    }

    /// Stream an arbitrarily large payload from `reader` into `writer` using
    /// bounded memory (`self.buffer_size` per chunk, `Flags::STREAMING` enabled).
    ///
    /// Never loads the entire input or output into RAM. Supports optional
    /// cooperative cancellation via `cancel_flag`.
    ///
    /// # Errors
    ///
    /// Returns [`ZnfError`] on I/O error, cancellation, or limit violation.
    pub fn write_streaming<R: Read, W: Write>(
        &self,
        mut reader: R,
        mut writer: W,
        cancel_flag: Option<&AtomicBool>,
    ) -> Result<u64, ZnfError> {
        let mut meta = self.metadata.clone();
        let crypto_ctx = self.resolve_write_encryption(&mut meta)?;
        let meta_bytes = meta.encode(&self.limits)?;

        let payload_offset = (HEADER_LEN + meta_bytes.len()) as u64;
        let mut header = ZnfHeader::with_layout(
            self.format_id,
            self.version.major,
            self.version.minor,
            HEADER_LEN as u64,
            payload_offset,
            0, // streaming mode: length delimited by chunks and verified in footer
        );
        header.set_compression(self.compression);
        if crypto_ctx.is_some() {
            header.set_encryption(ZnfEncryption::XChaCha20Poly1305);
        }
        if !meta_bytes.is_empty() {
            header.flags_mut().set(ZnfFeatureFlags::HAS_METADATA, true);
        }
        header.flags_mut().set(ZnfFeatureFlags::HAS_FOOTER, true);
        header.flags_mut().set(ZnfFeatureFlags::STREAMING, true);

        let header_bytes = header.to_bytes()?;

        let mut container_hasher = Hasher::new();
        container_hasher.update(&header_bytes);
        container_hasher.update(&meta_bytes);

        writer.write_all(&header_bytes)?;
        writer.write_all(&meta_bytes)?;

        let comp_cfg = CompConfig {
            algorithm: self.compression.to_algorithm(),
            zstd_level: self.zstd_level,
            max_expanded_len: self.limits.max_expanded_len,
        };

        let mut payload_hasher = Hasher::new();
        let mut uncompressed_len: u64 = 0;
        let mut stored_payload_len: u64 = 0;
        let mut chunk_index: u64 = 0;
        let mut read_buf = vec![0u8; self.buffer_size];
        let mut wire_chunk_buf = Vec::new();

        loop {
            if let Some(flag) = cancel_flag {
                if flag.load(Ordering::Relaxed) {
                    return Err(ZnfError::Cancelled);
                }
            }
            let n = read_up_to(&mut reader, &mut read_buf)?;
            if n == 0 {
                break;
            }
            let plain_chunk = &read_buf[..n];
            uncompressed_len = uncompressed_len
                .checked_add(n as u64)
                .ok_or(ZnfError::IntegerOverflow("uncompressed length"))?;
            self.limits
                .check("expanded", uncompressed_len, self.limits.max_expanded_len)?;
            payload_hasher.update(plain_chunk);

            let compressed_chunk = compress_bytes(plain_chunk, &comp_cfg)?;
            let final_chunk = if let Some((ref key, ref base_nonce)) = crypto_ctx {
                let c_nonce = chunk_nonce(base_nonce, chunk_index);
                let aad = build_chunk_aad(&header_bytes, &meta_bytes, chunk_index);
                encrypt(key, &c_nonce, &compressed_chunk, &aad)?
            } else {
                compressed_chunk
            };

            wire_chunk_buf.clear();
            write_chunk(&mut wire_chunk_buf, &final_chunk, MAX_CHUNK_SIZE)?;
            stored_payload_len = stored_payload_len
                .checked_add(wire_chunk_buf.len() as u64)
                .ok_or(ZnfError::IntegerOverflow("stored payload length"))?;
            self.limits
                .check("payload", stored_payload_len, self.limits.max_payload_len)?;

            container_hasher.update(&wire_chunk_buf);
            writer.write_all(&wire_chunk_buf)?;
            chunk_index += 1;
        }

        // Write terminal 0u32 chunk marker.
        wire_chunk_buf.clear();
        write_end_chunk(&mut wire_chunk_buf)?;
        stored_payload_len = stored_payload_len
            .checked_add(wire_chunk_buf.len() as u64)
            .ok_or(ZnfError::IntegerOverflow("stored payload length"))?;
        container_hasher.update(&wire_chunk_buf);
        writer.write_all(&wire_chunk_buf)?;

        let payload_blake3 = payload_hasher.finalize();
        let container_blake3 = container_hasher.finalize();

        let mut footer = TlvWriter::new();
        footer.push(TLV_PAYLOAD_BLAKE3, payload_blake3.as_bytes(), &self.limits)?;
        footer.push(
            TLV_UNCOMPRESSED_LEN,
            &uncompressed_len.to_le_bytes(),
            &self.limits,
        )?;
        footer.push(
            TLV_STORED_PAYLOAD_LEN,
            &stored_payload_len.to_le_bytes(),
            &self.limits,
        )?;
        footer.push(
            TLV_CONTAINER_BLAKE3,
            container_blake3.as_bytes(),
            &self.limits,
        )?;
        if let Some((ref key, ref base_nonce)) = crypto_ctx {
            let seal = compute_footer_seal(
                key,
                base_nonce,
                &header_bytes,
                &meta_bytes,
                chunk_index,
                uncompressed_len,
                &payload_blake3,
                &container_blake3,
            )?;
            footer.push(TLV_FOOTER_AUTH_TAG, &seal, &self.limits)?;
        }
        footer.push_end();
        writer.write_all(footer.as_bytes())?;

        Ok(uncompressed_len)
    }
}

/// Reader, parser, and integrity/authenticity verifier for ZNF Core containers.
#[derive(Debug, Clone)]
pub struct ZnfReader {
    limits: Limits,
    key_source: Option<EncryptionKeySource>,
}

/// Decoded ZNF Core container (header, metadata, verified hashes, and decompressed payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedContainer {
    /// Parsed 64-byte header.
    pub header: ZnfHeader,
    /// Parsed and verified metadata.
    pub metadata: ZnfMetadata,
    /// Decompressed, verified payload bytes.
    pub payload: Vec<u8>,
    /// Verified payload BLAKE3 hash.
    pub payload_blake3: Hash,
    /// Verified pre-footer container BLAKE3 hash.
    pub container_blake3: Hash,
}

impl Default for ZnfReader {
    fn default() -> Self {
        Self::new()
    }
}

impl ZnfReader {
    /// Create a reader with default resource [`Limits`].
    #[must_use]
    pub fn new() -> Self {
        ZnfReader {
            limits: Limits::default(),
            key_source: None,
        }
    }

    /// Configure resource limits.
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Provide password or raw key for decrypting encrypted containers.
    #[must_use]
    pub fn with_encryption_key(mut self, source: EncryptionKeySource) -> Self {
        self.key_source = Some(source);
        self
    }

    fn resolve_read_key(
        &self,
        header: &ZnfHeader,
        meta: &ZnfMetadata,
    ) -> Result<Option<(SecretKey, [u8; NONCE_LEN])>, ZnfError> {
        if !header.flags().is_encrypted() {
            if self.key_source.is_some() {
                return Err(ZnfError::FlagHeaderInconsistency(
                    "decryption key provided for unencrypted container",
                ));
            }
            return Ok(None);
        }
        let nonce = meta
            .payload_nonce
            .ok_or(ZnfError::MissingRequiredField("TLV_PAYLOAD_NONCE"))?;
        match &self.key_source {
            None => Err(ZnfError::MissingRequiredField(
                "encryption key or password required for encrypted container",
            )),
            Some(EncryptionKeySource::Password(pw))
            | Some(EncryptionKeySource::PasswordWithParams(pw, _)) => {
                let kdf = meta
                    .kdf_params
                    .as_ref()
                    .ok_or(ZnfError::MissingRequiredField("TLV_KDF_PARAMS"))?;
                let key = kdf.derive_key(pw)?;
                Ok(Some((key, nonce)))
            }
            Some(EncryptionKeySource::RawKey(k)) => Ok(Some((k.clone(), nonce))),
        }
    }

    /// Read, validate, authenticate, decompress, and verify a container from a byte slice.
    ///
    /// Supports both contiguous and streaming (`Flags::STREAMING`) containers.
    ///
    /// # Errors
    ///
    /// Returns [`ZnfError`] on any structural, integrity, authentication, or limit error.
    pub fn read_container(&self, raw: &[u8]) -> Result<DecodedContainer, ZnfError> {
        let mut cursor = std::io::Cursor::new(raw);
        let mut payload = Vec::new();
        let (header, metadata, payload_blake3, container_blake3) =
            self.read_streaming(&mut cursor, &mut payload, None)?;
        if (cursor.position() as usize) != raw.len() {
            return Err(ZnfError::InvalidMetadata(
                "trailing bytes after container footer".into(),
            ));
        }
        Ok(DecodedContainer {
            header,
            metadata,
            payload,
            payload_blake3,
            container_blake3,
        })
    }

    /// Stream-read, validate, authenticate, decompress, and verify a ZNF Core container
    /// from any `R: Read`, writing verified plaintext incrementally into `W: Write`
    /// with bounded memory.
    ///
    /// # Errors
    ///
    /// Returns [`ZnfError`] on corruption, authentication failure, unsupported
    /// version/feature/extension, limit violation, or cancellation.
    pub fn read_streaming<R: Read, W: Write>(
        &self,
        mut reader: R,
        mut output: W,
        cancel_flag: Option<&AtomicBool>,
    ) -> Result<(ZnfHeader, ZnfMetadata, Hash, Hash), ZnfError> {
        // 1. Read and decode 64-byte header.
        let mut header_bytes = [0u8; HEADER_LEN];
        read_exact_checked(&mut reader, &mut header_bytes, 0)?;
        let header = ZnfHeader::decode(&header_bytes, &self.limits, None)?;

        let mut container_hasher = Hasher::new();
        container_hasher.update(&header_bytes);

        // 2. Read any header extensions (between 64 and header_len) + metadata section.
        let ext_len = (header.header_len() - HEADER_LEN as u64) as usize;
        if ext_len > 0 {
            let mut ext_buf = vec![0u8; ext_len];
            read_exact_checked(&mut reader, &mut ext_buf, HEADER_LEN as u64)?;
            container_hasher.update(&ext_buf);
        }

        let meta_len = header.metadata_len() as usize;
        let mut meta_bytes = vec![0u8; meta_len];
        if meta_len > 0 {
            read_exact_checked(&mut reader, &mut meta_bytes, header.header_len())?;
            container_hasher.update(&meta_bytes);
        }
        let metadata = ZnfMetadata::decode(&meta_bytes, &self.limits)?;
        let crypto_ctx = self.resolve_read_key(&header, &metadata)?;

        // 3. Process payload (either streaming chunks or contiguous).
        let mut payload_hasher = Hasher::new();
        let mut total_uncompressed: u64 = 0;
        let mut total_stored_payload: u64 = 0;
        let mut chunk_count: u64 = 0;

        if header.flags().is_streaming() {
            let mut chunk_buf = Vec::new();
            loop {
                if let Some(flag) = cancel_flag {
                    if flag.load(Ordering::Relaxed) {
                        return Err(ZnfError::Cancelled);
                    }
                }
                let maybe_len = read_chunk(&mut reader, &mut chunk_buf, MAX_CHUNK_SIZE)?;
                match maybe_len {
                    None => {
                        // Terminal 0u32 chunk marker.
                        container_hasher.update(&0u32.to_le_bytes());
                        total_stored_payload = total_stored_payload
                            .checked_add(4)
                            .ok_or(ZnfError::IntegerOverflow("stored payload length"))?;
                        break;
                    }
                    Some(c_len) => {
                        let len_le = (c_len as u32).to_le_bytes();
                        container_hasher.update(&len_le);
                        container_hasher.update(&chunk_buf);
                        total_stored_payload =
                            total_stored_payload
                                .checked_add(4 + c_len as u64)
                                .ok_or(ZnfError::IntegerOverflow("stored payload length"))?;
                        self.limits.check(
                            "payload",
                            total_stored_payload,
                            self.limits.max_payload_len,
                        )?;

                        let compressed_cow = if let Some((ref key, ref base_nonce)) = crypto_ctx {
                            let c_nonce = chunk_nonce(base_nonce, chunk_count);
                            let aad = build_chunk_aad(&header_bytes, &meta_bytes, chunk_count);
                            decrypt(key, &c_nonce, &chunk_buf, &aad)?
                        } else {
                            chunk_buf.clone()
                        };

                        let remaining_budget = self
                            .limits
                            .max_expanded_len
                            .saturating_sub(total_uncompressed);
                        let comp_cfg = CompConfig {
                            algorithm: header.compression().to_algorithm(),
                            zstd_level: 3,
                            max_expanded_len: remaining_budget,
                        };
                        let plain = decompress_bytes(
                            &compressed_cow,
                            header.compression().to_algorithm(),
                            &comp_cfg,
                        )?;
                        total_uncompressed = total_uncompressed
                            .checked_add(plain.len() as u64)
                            .ok_or(ZnfError::IntegerOverflow("uncompressed length"))?;
                        self.limits.check(
                            "expanded",
                            total_uncompressed,
                            self.limits.max_expanded_len,
                        )?;

                        payload_hasher.update(&plain);
                        output.write_all(&plain)?;
                        chunk_count += 1;
                    }
                }
            }
            if header.payload_len() != 0 && header.payload_len() != total_stored_payload {
                return Err(ZnfError::InvalidPayloadLength(total_stored_payload));
            }
        } else {
            if let Some(flag) = cancel_flag {
                if flag.load(Ordering::Relaxed) {
                    return Err(ZnfError::Cancelled);
                }
            }
            let p_len = header.payload_len();
            self.limits
                .check("payload", p_len, self.limits.max_payload_len)?;
            let mut stored_buf = vec![0u8; p_len as usize];
            read_exact_checked(&mut reader, &mut stored_buf, header.payload_offset())?;
            container_hasher.update(&stored_buf);
            total_stored_payload = p_len;

            let compressed_cow = if let Some((ref key, ref nonce)) = crypto_ctx {
                let mut aad = Vec::with_capacity(HEADER_LEN + meta_bytes.len());
                aad.extend_from_slice(&header_bytes);
                aad.extend_from_slice(&meta_bytes);
                decrypt(key, nonce, &stored_buf, &aad)?
            } else {
                stored_buf
            };

            let comp_cfg = CompConfig {
                algorithm: header.compression().to_algorithm(),
                zstd_level: 3,
                max_expanded_len: self.limits.max_expanded_len,
            };
            let plain = decompress_bytes(
                &compressed_cow,
                header.compression().to_algorithm(),
                &comp_cfg,
            )?;
            total_uncompressed = plain.len() as u64;
            payload_hasher.update(&plain);
            output.write_all(&plain)?;
            chunk_count = 1;
        }

        let computed_payload_blake3 = payload_hasher.finalize();
        let computed_container_blake3 = container_hasher.finalize();

        // 4. Read and validate Footer TLV section.
        if !header.flags().has_footer() {
            return Err(ZnfError::MissingRequiredField("Flags::HAS_FOOTER"));
        }
        let mut footer_bytes = Vec::new();
        let mut bounded_footer = BoundedReader::new(&mut reader, self.limits.max_metadata_len);
        bounded_footer.read_to_end(&mut footer_bytes)?;

        let mut f_reader = TlvReader::new(&footer_bytes, self.limits);
        let mut saw_end = false;
        let mut expected_payload_blake3: Option<Hash> = None;
        let mut expected_container_blake3: Option<Hash> = None;
        let mut expected_uncompressed_len: Option<u64> = None;
        let mut expected_stored_len: Option<u64> = None;
        let mut footer_auth_tag: Option<Vec<u8>> = None;

        while let Some(tlv) = f_reader.next_tlv()? {
            if tlv.is_end() {
                saw_end = true;
                break;
            }
            match tlv.ty {
                TLV_PAYLOAD_BLAKE3 => {
                    if tlv.value.len() != HASH_LEN {
                        return Err(ZnfError::InvalidMetadata(
                            "invalid TLV_PAYLOAD_BLAKE3 length".into(),
                        ));
                    }
                    let mut b = [0u8; HASH_LEN];
                    b.copy_from_slice(tlv.value);
                    expected_payload_blake3 = Some(Hash::from_bytes(b));
                }
                TLV_CONTAINER_BLAKE3 => {
                    if tlv.value.len() != HASH_LEN {
                        return Err(ZnfError::InvalidMetadata(
                            "invalid TLV_CONTAINER_BLAKE3 length".into(),
                        ));
                    }
                    let mut b = [0u8; HASH_LEN];
                    b.copy_from_slice(tlv.value);
                    expected_container_blake3 = Some(Hash::from_bytes(b));
                }
                TLV_UNCOMPRESSED_LEN => {
                    if tlv.value.len() != 8 {
                        return Err(ZnfError::InvalidMetadata(
                            "invalid TLV_UNCOMPRESSED_LEN length".into(),
                        ));
                    }
                    expected_uncompressed_len =
                        Some(u64::from_le_bytes(tlv.value.try_into().unwrap()));
                }
                TLV_STORED_PAYLOAD_LEN => {
                    if tlv.value.len() != 8 {
                        return Err(ZnfError::InvalidMetadata(
                            "invalid TLV_STORED_PAYLOAD_LEN length".into(),
                        ));
                    }
                    expected_stored_len = Some(u64::from_le_bytes(tlv.value.try_into().unwrap()));
                }
                TLV_FOOTER_AUTH_TAG => {
                    footer_auth_tag = Some(tlv.value.to_vec());
                }
                other if is_critical_extension_type(other) => {
                    return Err(ZnfError::UnsupportedCriticalExtension(other));
                }
                _ => {
                    // Forward compatibility: skip non-critical footer extensions.
                }
            }
        }

        if !saw_end {
            return Err(ZnfError::InvalidMetadata(
                "footer section missing TLV_END marker".into(),
            ));
        }

        if let Some(exp_stored) = expected_stored_len {
            if exp_stored != total_stored_payload {
                return Err(ZnfError::InvalidPayloadLength(total_stored_payload));
            }
        }

        let exp_uncomp = expected_uncompressed_len
            .ok_or(ZnfError::MissingRequiredField("TLV_UNCOMPRESSED_LEN"))?;
        if exp_uncomp != total_uncompressed {
            return Err(ZnfError::UncompressedLengthMismatch {
                expected: exp_uncomp,
                got: total_uncompressed,
            });
        }

        let exp_p_hash =
            expected_payload_blake3.ok_or(ZnfError::MissingRequiredField("TLV_PAYLOAD_BLAKE3"))?;
        if exp_p_hash != computed_payload_blake3 {
            return Err(ZnfError::PayloadHashMismatch {
                expected: exp_p_hash.to_hex(),
                computed: computed_payload_blake3.to_hex(),
            });
        }

        let exp_c_hash = expected_container_blake3
            .ok_or(ZnfError::MissingRequiredField("TLV_CONTAINER_BLAKE3"))?;
        if exp_c_hash != computed_container_blake3 {
            return Err(ZnfError::ContainerHashMismatch {
                expected: exp_c_hash.to_hex(),
                computed: computed_container_blake3.to_hex(),
            });
        }

        if let Some((ref key, ref base_nonce)) = crypto_ctx {
            let seal =
                footer_auth_tag.ok_or(ZnfError::MissingRequiredField("TLV_FOOTER_AUTH_TAG"))?;
            verify_footer_seal(
                key,
                base_nonce,
                &header_bytes,
                &meta_bytes,
                chunk_count,
                total_uncompressed,
                &computed_payload_blake3,
                &computed_container_blake3,
                &seal,
            )?;
        }

        Ok((
            header,
            metadata,
            computed_payload_blake3,
            computed_container_blake3,
        ))
    }
}

/// Structural and cryptographic validator for ZNF containers.
///
/// Can inspect and validate headers, metadata, section boundaries, and
/// pre-footer BLAKE3 hashes on any ZNF container (`.znf`, `.zarc`, etc.)
/// even without a decryption key.
#[derive(Debug, Clone)]
pub struct ZnfValidator {
    limits: Limits,
}

impl Default for ZnfValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl ZnfValidator {
    /// Create a validator with default [`Limits`].
    #[must_use]
    pub fn new() -> Self {
        ZnfValidator {
            limits: Limits::default(),
        }
    }

    /// Create a validator with custom [`Limits`].
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Validate container structure, header CRC-32, metadata TLVs/BLAKE3,
    /// section boundaries, and footer TLVs/container BLAKE3 without
    /// requiring decryption keys or exposing sensitive metadata values.
    ///
    /// # Errors
    ///
    /// Returns [`ZnfError`] if any structural, version, flag, critical extension,
    /// or unencrypted integrity check fails.
    pub fn validate_structure(&self, raw: &[u8]) -> Result<ContainerInfo, ZnfError> {
        let header = ZnfHeader::decode(raw, &self.limits, Some(raw.len() as u64))?;

        let meta_start = header.header_len() as usize;
        let payload_start = header.payload_offset() as usize;
        let metadata = if header.flags().has_metadata() {
            ZnfMetadata::decode(&raw[meta_start..payload_start], &self.limits)?
        } else {
            ZnfMetadata::new()
        };

        // Determine payload end: for non-streaming containers, payload_offset + payload_len.
        // For streaming containers with payload_len == 0, scan chunks to find the 0u32 marker.
        let payload_end = if header.flags().is_streaming() && header.payload_len() == 0 {
            let mut cursor = &raw[payload_start..];
            let mut tmp = Vec::new();
            let mut consumed = 0usize;
            loop {
                let before = cursor.len();
                let maybe = read_chunk(&mut cursor, &mut tmp, MAX_CHUNK_SIZE)?;
                consumed += before - cursor.len();
                if maybe.is_none() {
                    break;
                }
            }
            payload_start + consumed
        } else {
            (header.payload_offset() + header.payload_len()) as usize
        };

        if payload_end > raw.len() {
            return Err(ZnfError::InvalidPayloadLength(header.payload_len()));
        }

        let mut uncompressed_len = None;
        let mut payload_blake3 = None;
        let mut container_blake3 = None;

        if header.flags().has_footer() {
            let footer_slice = &raw[payload_end..];
            let mut f_reader = TlvReader::new(footer_slice, self.limits);
            let mut saw_end = false;
            while let Some(tlv) = f_reader.next_tlv()? {
                if tlv.is_end() {
                    saw_end = true;
                    break;
                }
                match tlv.ty {
                    TLV_UNCOMPRESSED_LEN if tlv.value.len() == 8 => {
                        uncompressed_len = Some(u64::from_le_bytes(tlv.value.try_into().unwrap()));
                    }
                    TLV_PAYLOAD_BLAKE3 if tlv.value.len() == HASH_LEN => {
                        let mut b = [0u8; HASH_LEN];
                        b.copy_from_slice(tlv.value);
                        payload_blake3 = Some(Hash::from_bytes(b));
                    }
                    TLV_CONTAINER_BLAKE3 if tlv.value.len() == HASH_LEN => {
                        let mut b = [0u8; HASH_LEN];
                        b.copy_from_slice(tlv.value);
                        let expected = Hash::from_bytes(b);
                        let computed = hash(&raw[..payload_end]);
                        if computed != expected {
                            return Err(ZnfError::ContainerHashMismatch {
                                expected: expected.to_hex(),
                                computed: computed.to_hex(),
                            });
                        }
                        container_blake3 = Some(expected);
                    }
                    other if is_critical_extension_type(other) => {
                        return Err(ZnfError::UnsupportedCriticalExtension(other));
                    }
                    _ => {}
                }
            }
            if !saw_end {
                return Err(ZnfError::InvalidMetadata(
                    "footer section missing TLV_END marker".into(),
                ));
            }
        }

        Ok(ContainerInfo {
            format_id: header.format_id(),
            version: header.version(),
            flags: header.flags(),
            compression: header.compression(),
            encryption: header.encryption(),
            header_len: header.header_len(),
            payload_offset: header.payload_offset(),
            payload_len: (payload_end - payload_start) as u64,
            uncompressed_len,
            metadata_attribute_count: metadata.attributes.len(),
            metadata_extension_count: metadata.unknown_extensions.len(),
            metadata_blake3: metadata.metadata_blake3,
            payload_blake3,
            container_blake3,
        })
    }
}

fn read_up_to<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize, ZnfError> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ZnfError::Io(e.to_string())),
        }
    }
    Ok(total)
}

fn read_exact_checked<R: Read>(
    reader: &mut R,
    mut buf: &mut [u8],
    base_offset: u64,
) -> Result<(), ZnfError> {
    let mut read_so_far = 0u64;
    while !buf.is_empty() {
        match reader.read(buf) {
            Ok(0) => {
                return Err(ZnfError::UnexpectedEof {
                    offset: base_offset + read_so_far,
                })
            }
            Ok(n) => {
                read_so_far += n as u64;
                buf = &mut buf[n..];
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ZnfError::Io(e.to_string())),
        }
    }
    Ok(())
}

fn build_chunk_aad(
    header_bytes: &[u8; HEADER_LEN],
    meta_bytes: &[u8],
    chunk_index: u64,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HEADER_LEN + meta_bytes.len() + 8);
    aad.extend_from_slice(header_bytes);
    aad.extend_from_slice(meta_bytes);
    aad.extend_from_slice(&chunk_index.to_le_bytes());
    aad
}

#[allow(clippy::too_many_arguments)]
fn compute_footer_seal(
    key: &SecretKey,
    base_nonce: &[u8; NONCE_LEN],
    header_bytes: &[u8; HEADER_LEN],
    meta_bytes: &[u8],
    chunk_count: u64,
    uncompressed_len: u64,
    payload_blake3: &Hash,
    container_blake3: &Hash,
) -> Result<Vec<u8>, ZnfError> {
    let f_nonce = chunk_nonce(base_nonce, u64::MAX);
    let aad = build_chunk_aad(header_bytes, meta_bytes, u64::MAX);
    let mut msg = [0u8; 8 + 8 + HASH_LEN + HASH_LEN];
    msg[0..8].copy_from_slice(&chunk_count.to_le_bytes());
    msg[8..16].copy_from_slice(&uncompressed_len.to_le_bytes());
    msg[16..48].copy_from_slice(payload_blake3.as_bytes());
    msg[48..80].copy_from_slice(container_blake3.as_bytes());
    Ok(encrypt(key, &f_nonce, &msg, &aad)?)
}

#[allow(clippy::too_many_arguments)]
fn verify_footer_seal(
    key: &SecretKey,
    base_nonce: &[u8; NONCE_LEN],
    header_bytes: &[u8; HEADER_LEN],
    meta_bytes: &[u8],
    chunk_count: u64,
    uncompressed_len: u64,
    payload_blake3: &Hash,
    container_blake3: &Hash,
    seal: &[u8],
) -> Result<(), ZnfError> {
    let f_nonce = chunk_nonce(base_nonce, u64::MAX);
    let aad = build_chunk_aad(header_bytes, meta_bytes, u64::MAX);
    let plain = decrypt(key, &f_nonce, seal, &aad)?;
    if plain.len() != 80 {
        return Err(ZnfError::AuthenticationFailed);
    }
    let exp_chunks = u64::from_le_bytes(plain[0..8].try_into().unwrap());
    let exp_uncomp = u64::from_le_bytes(plain[8..16].try_into().unwrap());
    if exp_chunks != chunk_count
        || exp_uncomp != uncompressed_len
        || &plain[16..48] != payload_blake3.as_bytes()
        || &plain[48..80] != container_blake3.as_bytes()
    {
        return Err(ZnfError::AuthenticationFailed);
    }
    Ok(())
}
