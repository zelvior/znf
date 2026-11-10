//! ZARC archive writer, reader, verifier, and extractor.
//!
//! File layout of a `.zarc` v1.0 archive:
//!
//! ```text
//! +-------------------------------------------------------------------+
//! | ZNF Core Fixed Header (64 bytes, FormatId = 1, Version = 1.0)     |
//! +-------------------------------------------------------------------+
//! | Metadata TLV Section (optional; present when HAS_METADATA set)    |
//! |   - TLV_KDF_PARAMS (0x0010): 28-byte Argon2id KdfParams           |
//! |   - TLV_COMMENT    (0x0020): UTF-8 archive comment (optional)     |
//! |   - TLV_END        (0xFFFF)                                       |
//! +-------------------------------------------------------------------+
//! | Payload Section (offset = payload_offset, len = payload_len)      |
//! |   For each file entry i:                                          |
//! |     compressed_bytes (or ciphertext + 16B tag if ENCRYPTED)       |
//! +-------------------------------------------------------------------+
//! | Footer TLV Section (always present; HAS_FOOTER set)               |
//! |   If unencrypted:                                                 |
//! |     - TLV_ZARC_INDEX (0x0100): encoded EntryRecord table          |
//! |   If encrypted:                                                   |
//! |     - TLV_ZARC_ENCRYPTED_INDEX (0x0101):                          |
//! |         24-byte nonce || XChaCha20-Poly1305(index_bytes, aad=hdr) |
//! |   - TLV_ARCHIVE_BLAKE3 (0x0102): 32-byte BLAKE3 over bytes        |
//! |         0 .. (payload_offset + payload_len)                       |
//! |   - TLV_PARITY_STRIPE (0x0103): optional ParityStripe             |
//! |   - TLV_END (0xFFFF)                                              |
//! +-------------------------------------------------------------------+
//! ```
//!
//! When encryption is enabled, **both** file payloads and the entry index
//! (filenames, sizes, timestamps, hashes) are AEAD-encrypted with
//! `XChaCha20-Poly1305`, binding the 64-byte ZNF Core header as AAD.
//! This prevents metadata leakage (filenames are hidden) and detects any
//! header tampering prior to releasing data.

use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::UNIX_EPOCH;

use znf_compression::{compress_bytes, decompress_bytes, Algorithm, Config as CompConfig};
use znf_core::{
    Flags, FormatId, Header, Limits, TlvReader, TlvWriter, ZnfCompression, ZnfEncryption,
    HEADER_LEN,
};
use znf_crypto::{decrypt, encrypt, generate_nonce, KdfParams, SecretKey, NONCE_LEN, TAG_LEN};
use znf_integrity::{hash, Hash, HASH_LEN};
use znf_recovery::ParityStripe;

use crate::entry::{decode_index, encode_index, EntryKind, EntryRecord, DEFAULT_MAX_ENTRIES};
use crate::error::ZarcError;
use crate::path::{normalize_fs_path, safe_join, validate_archive_path};

/// TLV type: Argon2id KDF parameters (`28` bytes).
pub const TLV_KDF_PARAMS: u16 = 0x0010;
/// TLV type: Optional UTF-8 archive comment.
pub const TLV_COMMENT: u16 = 0x0020;
/// TLV type: Unencrypted ZARC entry index table.
pub const TLV_ZARC_INDEX: u16 = 0x0100;
/// TLV type: Encrypted ZARC entry index (`24B nonce || ciphertext+tag`).
pub const TLV_ZARC_ENCRYPTED_INDEX: u16 = 0x0101;
/// TLV type: Whole-archive BLAKE3 digest over `0..(payload_offset + payload_len)`.
pub const TLV_ARCHIVE_BLAKE3: u16 = 0x0102;
/// TLV type: Optional XOR recovery parity stripe over payload.
pub const TLV_PARITY_STRIPE: u16 = 0x0103;

/// Options for creating a `.zarc` archive.
#[derive(Debug, Clone, Default)]
pub struct WriteOptions {
    /// Compression configuration.
    pub compression: CompConfig,
    /// Optional password for Argon2id + XChaCha20-Poly1305 encryption.
    pub password: Option<Vec<u8>>,
    /// Optional explicit KDF parameters (defaults to `KdfParams::new_default()`).
    pub kdf_params: Option<KdfParams>,
    /// Optional archive comment.
    pub comment: Option<String>,
    /// Whether to include a recovery parity stripe in the footer.
    pub include_parity: bool,
    /// Resource limits used while encoding TLVs.
    pub limits: Limits,
}

/// Options for reading, verifying, and extracting a `.zarc` archive.
#[derive(Debug, Clone)]
pub struct ReadOptions {
    /// Optional password if the archive is encrypted.
    pub password: Option<Vec<u8>>,
    /// Resource and decompression-bomb limits.
    pub limits: Limits,
    /// Maximum number of entries allowed in the index.
    pub max_entries: usize,
    /// Maximum compression ratio (`uncompressed / stored`) before flagging a bomb.
    /// Default: `1000` (applied to entries larger than 1 MiB uncompressed).
    pub max_compression_ratio: u64,
}

impl Default for ReadOptions {
    fn default() -> Self {
        ReadOptions {
            password: None,
            limits: Limits::default(),
            max_entries: DEFAULT_MAX_ENTRIES,
            max_compression_ratio: 1000,
        }
    }
}

/// Builder for creating `.zarc` archives in memory or on disk.
#[derive(Debug)]
pub struct ZarcWriter {
    options: WriteOptions,
    seen_paths: HashSet<String>,
    pending: Vec<PendingEntry>,
}

#[derive(Debug)]
struct PendingEntry {
    path: String,
    kind: EntryKind,
    unix_mode: u32,
    mtime_unix_secs: i64,
    data: Vec<u8>,
}

impl ZarcWriter {
    /// Create a new archive builder with the given options.
    #[must_use]
    pub fn new(options: WriteOptions) -> Self {
        ZarcWriter {
            options,
            seen_paths: HashSet::new(),
            pending: Vec::new(),
        }
    }

    /// Add an empty directory entry.
    ///
    /// # Errors
    ///
    /// Returns [`ZarcError`] if `archive_path` is unsafe or a duplicate.
    pub fn add_directory(
        &mut self,
        archive_path: &str,
        unix_mode: u32,
        mtime_unix_secs: i64,
    ) -> Result<(), ZarcError> {
        let canonical = validate_archive_path(archive_path)?;
        if !self.seen_paths.insert(canonical.clone()) {
            return Err(ZarcError::DuplicateEntry(canonical));
        }
        self.pending.push(PendingEntry {
            path: canonical,
            kind: EntryKind::Directory,
            unix_mode,
            mtime_unix_secs,
            data: Vec::new(),
        });
        Ok(())
    }

    /// Add a file entry from an in-memory byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`ZarcError`] if `archive_path` is unsafe or a duplicate.
    pub fn add_bytes(
        &mut self,
        archive_path: &str,
        data: &[u8],
        unix_mode: u32,
        mtime_unix_secs: i64,
    ) -> Result<(), ZarcError> {
        let canonical = validate_archive_path(archive_path)?;
        if !self.seen_paths.insert(canonical.clone()) {
            return Err(ZarcError::DuplicateEntry(canonical));
        }
        self.pending.push(PendingEntry {
            path: canonical,
            kind: EntryKind::File,
            unix_mode,
            mtime_unix_secs,
            data: data.to_vec(),
        });
        Ok(())
    }

    /// Recursively add a file or directory from the local filesystem.
    ///
    /// `base_dir` is stripped from `fs_path` to form the relative archive path.
    /// Symlinks are rejected by default to prevent symlink-escape attacks.
    ///
    /// # Errors
    ///
    /// Returns [`ZarcError`] on unsafe path, symlink, or I/O error.
    pub fn add_path(&mut self, base_dir: &Path, fs_path: &Path) -> Result<(), ZarcError> {
        let symlink_meta = fs::symlink_metadata(fs_path)?;
        if symlink_meta.file_type().is_symlink() {
            return Err(ZarcError::UnsupportedFsEntry(format!(
                "symlink refused: {}",
                fs_path.display()
            )));
        }
        let rel = fs_path.strip_prefix(base_dir).unwrap_or(fs_path);
        let mtime = symlink_meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs() as i64);
        let mode = unix_mode_from_metadata(&symlink_meta);

        if symlink_meta.is_dir() {
            if !rel.as_os_str().is_empty() && rel != Path::new(".") {
                let archive_path = normalize_fs_path(rel)?;
                self.add_directory(&archive_path, mode, mtime)?;
            }
            let mut children: Vec<_> = fs::read_dir(fs_path)?.collect::<Result<Vec<_>, _>>()?;
            // Sort deterministically by filename so archive output is reproducible.
            children.sort_by_key(|e| e.file_name());
            for child in children {
                self.add_path(base_dir, &child.path())?;
            }
        } else if symlink_meta.is_file() {
            let archive_path = normalize_fs_path(rel)?;
            let data = fs::read(fs_path)?;
            self.add_bytes(&archive_path, &data, mode, mtime)?;
        } else {
            return Err(ZarcError::UnsupportedFsEntry(fs_path.display().to_string()));
        }
        Ok(())
    }

    /// Finalize and encode the complete `.zarc` archive into `writer`.
    ///
    /// # Errors
    ///
    /// Returns [`ZarcError`] on compression, encryption, or I/O failure.
    pub fn finish<W: Write>(self, mut writer: W) -> Result<(), ZarcError> {
        let limits = &self.options.limits;

        // 1. Optional encryption setup (Argon2id KDF).
        let (derived_key, kdf_params) = if let Some(ref pw) = self.options.password {
            let params = match self.options.kdf_params.clone() {
                Some(p) => p,
                None => KdfParams::new_default()?,
            };
            let key = params.derive_key(pw)?;
            (Some(key), Some(params))
        } else {
            (None, None)
        };

        // 2. Build metadata TLV section if needed.
        let mut meta_tlv = TlvWriter::new();
        if let Some(ref params) = kdf_params {
            meta_tlv.push(TLV_KDF_PARAMS, &params.encode(), limits)?;
        }
        if let Some(ref comment) = self.options.comment {
            meta_tlv.push(TLV_COMMENT, comment.as_bytes(), limits)?;
        }
        let has_metadata = !meta_tlv.is_empty();
        if has_metadata {
            meta_tlv.push_end();
        }
        let meta_bytes = meta_tlv.into_bytes();

        // 3. Compress (and optionally encrypt) each entry into the payload buffer.
        //    Wait to encrypt until we know the header bytes?
        //    Notice: header contains `payload_len`. For AEAD, ciphertext length is
        //    `compressed_len + TAG_LEN` (deterministic before encryption!).
        //    So we can first compress all entries, compute exact `payload_len`,
        //    encode the 64-byte ZNF Core header, and then use that exact 64-byte
        //    header as AAD for all entry and index encryptions.
        struct CompressedItem {
            path: String,
            kind: EntryKind,
            compression: Algorithm,
            unix_mode: u32,
            mtime_unix_secs: i64,
            uncompressed_size: u64,
            blake3_hash: Hash,
            compressed: Vec<u8>,
        }

        let mut items = Vec::with_capacity(self.pending.len());
        let mut total_payload_len: u64 = 0;

        for p in self.pending {
            let (compression, compressed, digest) = match p.kind {
                EntryKind::Directory => (
                    Algorithm::None,
                    Vec::new(),
                    Hash::from_bytes([0u8; HASH_LEN]),
                ),
                EntryKind::File => {
                    let d = hash(&p.data);
                    let c = compress_bytes(&p.data, &self.options.compression)?;
                    (self.options.compression.algorithm, c, d)
                }
            };
            let stored_len = if p.kind == EntryKind::File && derived_key.is_some() {
                (compressed.len() + TAG_LEN) as u64
            } else {
                compressed.len() as u64
            };
            total_payload_len = total_payload_len.checked_add(stored_len).ok_or_else(|| {
                ZarcError::ResourceLimitExceeded("payload length overflow".into())
            })?;
            items.push(CompressedItem {
                path: p.path,
                kind: p.kind,
                compression,
                unix_mode: p.unix_mode,
                mtime_unix_secs: p.mtime_unix_secs,
                uncompressed_size: p.data.len() as u64,
                blake3_hash: digest,
                compressed,
            });
        }

        // 4. Construct and encode ZNF Core Header (64 bytes).
        let payload_offset = (HEADER_LEN + meta_bytes.len()) as u64;
        let mut header = Header::with_layout(
            FormatId::ZARC,
            1,
            0,
            HEADER_LEN as u64,
            payload_offset,
            total_payload_len,
        );
        if self.options.compression.algorithm != Algorithm::None {
            header.set_compression(ZnfCompression::from_algorithm(
                self.options.compression.algorithm,
            ));
        }
        if derived_key.is_some() {
            header.set_encryption(ZnfEncryption::XChaCha20Poly1305);
        }
        if has_metadata {
            header.flags_mut().set(Flags::HAS_METADATA, true);
        }
        header.flags_mut().set(Flags::HAS_FOOTER, true);

        let mut header_bytes = [0u8; HEADER_LEN];
        header.encode(&mut header_bytes)?;

        // 5. Assemble payload and entry records (encrypting if key is present).
        let mut payload_bytes = Vec::with_capacity(total_payload_len as usize);
        let mut records = Vec::with_capacity(items.len());

        for item in items {
            let rel_offset = payload_bytes.len() as u64;
            let (stored_bytes, nonce) = match (&derived_key, item.kind) {
                (Some(key), EntryKind::File) => {
                    let n = generate_nonce()?;
                    let ct = encrypt(key, &n, &item.compressed, &header_bytes)?;
                    (ct, n)
                }
                _ => (item.compressed, [0u8; NONCE_LEN]),
            };
            let stored_size = stored_bytes.len() as u64;
            payload_bytes.extend_from_slice(&stored_bytes);
            records.push(EntryRecord {
                path: item.path,
                kind: item.kind,
                compression: item.compression,
                flags: 0,
                unix_mode: item.unix_mode,
                mtime_unix_secs: item.mtime_unix_secs,
                uncompressed_size: item.uncompressed_size,
                stored_size,
                payload_rel_offset: rel_offset,
                blake3_hash: item.blake3_hash,
                entry_nonce: nonce,
            });
        }

        // 6. Compute whole-archive BLAKE3 over header + metadata + payload.
        let mut archive_hasher = znf_integrity::Hasher::new();
        archive_hasher.update(&header_bytes);
        archive_hasher.update(&meta_bytes);
        archive_hasher.update(&payload_bytes);
        let archive_digest = archive_hasher.finalize();

        // 7. Build Footer TLV section.
        let raw_index = encode_index(&records)?;
        let mut footer_tlv = TlvWriter::new();
        if let Some(ref key) = derived_key {
            let idx_nonce = generate_nonce()?;
            let ct = encrypt(key, &idx_nonce, &raw_index, &header_bytes)?;
            let mut enc_idx = Vec::with_capacity(NONCE_LEN + ct.len());
            enc_idx.extend_from_slice(&idx_nonce);
            enc_idx.extend_from_slice(&ct);
            footer_tlv.push(TLV_ZARC_ENCRYPTED_INDEX, &enc_idx, limits)?;
        } else {
            footer_tlv.push(TLV_ZARC_INDEX, &raw_index, limits)?;
        }
        footer_tlv.push(TLV_ARCHIVE_BLAKE3, archive_digest.as_bytes(), limits)?;
        if self.options.include_parity && !payload_bytes.is_empty() {
            let stripe = ParityStripe::compute(&payload_bytes, znf_recovery::DEFAULT_BLOCK_SIZE)?;
            footer_tlv.push(TLV_PARITY_STRIPE, &stripe.encode(), limits)?;
        }
        footer_tlv.push_end();
        let footer_bytes = footer_tlv.into_bytes();

        // 8. Write all sections out.
        writer.write_all(&header_bytes)?;
        writer.write_all(&meta_bytes)?;
        writer.write_all(&payload_bytes)?;
        writer.write_all(&footer_bytes)?;
        Ok(())
    }
}

/// Parsed `.zarc` archive reader and verifier over an in-memory or mapped byte slice.
#[derive(Debug)]
pub struct ZarcArchive<'a> {
    raw: &'a [u8],
    header: Header,
    header_bytes: [u8; HEADER_LEN],
    comment: Option<String>,
    kdf_params: Option<KdfParams>,
    derived_key: Option<SecretKey>,
    entries: Vec<EntryRecord>,
    archive_blake3: Option<Hash>,
    parity_stripe: Option<ParityStripe>,
    options: ReadOptions,
}

impl<'a> ZarcArchive<'a> {
    /// Open and parse a `.zarc` archive, validating the ZNF Core header,
    /// metadata TLVs, footer TLVs, whole-archive BLAKE3 digest, and entry index.
    ///
    /// # Errors
    ///
    /// Returns [`ZarcError`] on any structural, integrity, or authentication error.
    /// Never panics on arbitrary bytes.
    pub fn open(raw: &'a [u8], options: ReadOptions) -> Result<Self, ZarcError> {
        let header = Header::decode(raw, &options.limits, Some(raw.len() as u64))?;
        if header.format_id() != FormatId::ZARC {
            return Err(ZarcError::NotZarcFormat(header.format_id().raw()));
        }
        let mut header_bytes = [0u8; HEADER_LEN];
        header_bytes.copy_from_slice(&raw[..HEADER_LEN]);

        // Parse metadata section if present.
        let meta_start = header.header_len() as usize;
        let payload_start = header.payload_offset() as usize;
        if payload_start > raw.len() || meta_start > payload_start {
            return Err(ZarcError::MalformedArchive(
                "invalid metadata/payload offsets".into(),
            ));
        }
        let meta_len = (payload_start - meta_start) as u64;
        options
            .limits
            .check("metadata", meta_len, options.limits.max_metadata_len)?;

        let mut kdf_params: Option<KdfParams> = None;
        let mut comment: Option<String> = None;
        if header.flags().has_metadata() {
            let mut r = TlvReader::new(&raw[meta_start..payload_start], options.limits);
            let mut saw_meta_end = false;
            while let Some(tlv) = r.next_tlv()? {
                if tlv.is_end() {
                    saw_meta_end = true;
                    break;
                }
                match tlv.ty {
                    TLV_KDF_PARAMS => {
                        kdf_params = Some(KdfParams::decode(tlv.value)?);
                    }
                    TLV_COMMENT => {
                        let s = std::str::from_utf8(tlv.value).map_err(|_| {
                            ZarcError::MalformedArchive("invalid UTF-8 in comment TLV".into())
                        })?;
                        comment = Some(s.to_string());
                    }
                    _ => {
                        // Forward compatibility: skip unknown metadata TLVs.
                    }
                }
            }
            if !saw_meta_end {
                return Err(ZarcError::MalformedArchive(
                    "metadata TLV section missing TLV_END marker".into(),
                ));
            }
        }

        // Derive decryption key if archive is encrypted.
        let derived_key = if header.flags().is_encrypted() {
            let pw = options
                .password
                .as_deref()
                .ok_or(ZarcError::EncryptionMismatch(
                    "archive is encrypted; password required",
                ))?;
            let params = kdf_params.as_ref().ok_or_else(|| {
                ZarcError::MalformedArchive("encrypted archive missing KDF params TLV".into())
            })?;
            Some(params.derive_key(pw)?)
        } else {
            if options.password.is_some() {
                return Err(ZarcError::EncryptionMismatch(
                    "password supplied for unencrypted archive",
                ));
            }
            None
        };

        // Locate payload and footer.
        let payload_end_u64 = header
            .payload_offset()
            .checked_add(header.payload_len())
            .ok_or(znf_core::Error::IntegerOverflow("payload end"))?;
        if payload_end_u64 > raw.len() as u64 {
            return Err(ZarcError::MalformedArchive(
                "payload extends past end of file".into(),
            ));
        }
        let payload_end = payload_end_u64 as usize;

        if !header.flags().has_footer() {
            return Err(ZarcError::MalformedArchive(
                "ZARC archive missing required footer flag".into(),
            ));
        }

        let footer_slice = &raw[payload_end..];
        let mut f_reader = TlvReader::new(footer_slice, options.limits);
        let mut raw_index_bytes: Option<Vec<u8>> = None;
        let mut archive_blake3: Option<Hash> = None;
        let mut parity_stripe: Option<ParityStripe> = None;
        let mut saw_footer_end = false;

        while let Some(tlv) = f_reader.next_tlv()? {
            if tlv.is_end() {
                saw_footer_end = true;
                break;
            }
            match tlv.ty {
                TLV_ZARC_INDEX => {
                    if header.flags().is_encrypted() {
                        return Err(ZarcError::MalformedArchive(
                            "unencrypted index in encrypted archive".into(),
                        ));
                    }
                    raw_index_bytes = Some(tlv.value.to_vec());
                }
                TLV_ZARC_ENCRYPTED_INDEX => {
                    let key = derived_key.as_ref().ok_or_else(|| {
                        ZarcError::MalformedArchive("encrypted index in unencrypted archive".into())
                    })?;
                    if tlv.value.len() < NONCE_LEN + TAG_LEN {
                        return Err(ZarcError::MalformedArchive(
                            "encrypted index TLV too short".into(),
                        ));
                    }
                    let mut nonce = [0u8; NONCE_LEN];
                    nonce.copy_from_slice(&tlv.value[..NONCE_LEN]);
                    let ct = &tlv.value[NONCE_LEN..];
                    let pt = decrypt(key, &nonce, ct, &header_bytes)?;
                    raw_index_bytes = Some(pt);
                }
                TLV_ARCHIVE_BLAKE3 => {
                    if tlv.value.len() != HASH_LEN {
                        return Err(ZarcError::MalformedArchive(
                            "invalid BLAKE3 digest length in footer".into(),
                        ));
                    }
                    let mut b = [0u8; HASH_LEN];
                    b.copy_from_slice(tlv.value);
                    archive_blake3 = Some(Hash::from_bytes(b));
                }
                TLV_PARITY_STRIPE => {
                    parity_stripe = Some(ParityStripe::decode(tlv.value)?);
                }
                _ => {
                    // Forward compatibility: ignore unknown footer TLVs.
                }
            }
        }

        if !saw_footer_end {
            return Err(ZarcError::MalformedArchive(
                "footer TLV section missing TLV_END marker".into(),
            ));
        }

        let index_bytes = raw_index_bytes.ok_or_else(|| {
            ZarcError::MalformedArchive("missing ZARC index TLV in footer".into())
        })?;
        let entries = decode_index(&index_bytes, options.max_entries)?;

        // Validate every entry's offset, size, and bomb limits against payload_len
        // and total expanded limit.
        let mut total_uncompressed: u64 = 0;
        for entry in &entries {
            let end = entry
                .payload_rel_offset
                .checked_add(entry.stored_size)
                .ok_or_else(|| {
                    ZarcError::MalformedArchive("entry payload offset overflow".into())
                })?;
            if end > header.payload_len() {
                return Err(ZarcError::MalformedArchive(format!(
                    "entry '{}' stored range {}..{} exceeds payload length {}",
                    entry.path,
                    entry.payload_rel_offset,
                    end,
                    header.payload_len()
                )));
            }
            options.limits.check(
                "entry uncompressed",
                entry.uncompressed_size,
                options.limits.max_expanded_len,
            )?;
            total_uncompressed = total_uncompressed
                .checked_add(entry.uncompressed_size)
                .ok_or_else(|| {
                    ZarcError::ResourceLimitExceeded("total uncompressed size overflow".into())
                })?;
            options.limits.check(
                "total archive uncompressed",
                total_uncompressed,
                options.limits.max_expanded_len,
            )?;
            // Compression ratio check for non-trivial entries (> 1 MiB expanded).
            if entry.uncompressed_size > 1024 * 1024 && entry.stored_size > 0 {
                let ratio = entry.uncompressed_size / entry.stored_size;
                if ratio > options.max_compression_ratio {
                    return Err(ZarcError::ResourceLimitExceeded(format!(
                        "suspicious compression ratio ({ratio}:1) on entry '{}'",
                        entry.path
                    )));
                }
            }
        }

        Ok(ZarcArchive {
            raw,
            header,
            header_bytes,
            comment,
            kdf_params,
            derived_key,
            entries,
            archive_blake3,
            parity_stripe,
            options,
        })
    }

    /// Parsed ZNF Core header.
    #[must_use]
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Optional archive comment.
    #[must_use]
    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    /// Optional KDF parameters (present when encrypted).
    #[must_use]
    pub fn kdf_params(&self) -> Option<&KdfParams> {
        self.kdf_params.as_ref()
    }

    /// Entries in the archive index.
    #[must_use]
    pub fn entries(&self) -> &[EntryRecord] {
        &self.entries
    }

    /// Whole-archive BLAKE3 hash recorded in the footer.
    #[must_use]
    pub fn archive_blake3(&self) -> Option<Hash> {
        self.archive_blake3
    }

    /// Optional parity stripe recorded in the footer.
    #[must_use]
    pub fn parity_stripe(&self) -> Option<&ParityStripe> {
        self.parity_stripe.as_ref()
    }

    /// Decode, authenticate, decompress, and BLAKE3-verify a single entry's
    /// payload bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ZarcError`] on tampering, corruption, or bomb limit violation.
    pub fn read_entry_bytes(&self, entry: &EntryRecord) -> Result<Vec<u8>, ZarcError> {
        if entry.kind == EntryKind::Directory {
            return Ok(Vec::new());
        }
        let payload_start = self.header.payload_offset() as usize;
        let start = payload_start + entry.payload_rel_offset as usize;
        let end = start + entry.stored_size as usize;
        let stored_slice = &self.raw[start..end];

        let compressed_cow: std::borrow::Cow<'_, [u8]> = if let Some(ref key) = self.derived_key {
            let pt = decrypt(key, &entry.entry_nonce, stored_slice, &self.header_bytes)?;
            std::borrow::Cow::Owned(pt)
        } else {
            std::borrow::Cow::Borrowed(stored_slice)
        };

        // Bound decompression to the smaller of the global limit and the entry's
        // declared uncompressed size (+0 so excess trailing data is also caught).
        let max_expanded = self
            .options
            .limits
            .max_expanded_len
            .min(entry.uncompressed_size);
        let comp_cfg = CompConfig {
            algorithm: entry.compression,
            zstd_level: 3,
            max_expanded_len: max_expanded,
        };
        let decompressed = decompress_bytes(&compressed_cow, entry.compression, &comp_cfg)?;
        if decompressed.len() as u64 != entry.uncompressed_size {
            return Err(ZarcError::MalformedArchive(format!(
                "entry '{}' decompressed to {} bytes, expected {}",
                entry.path,
                decompressed.len(),
                entry.uncompressed_size
            )));
        }

        // Verify per-file BLAKE3 hash.
        entry.blake3_hash.verify(&decompressed)?;
        Ok(decompressed)
    }

    /// Verify the integrity of the entire archive:
    /// 1. Whole-archive BLAKE3 over `header + metadata + payload`.
    /// 2. Optional parity stripe verification.
    /// 3. Every entry's AEAD tag (if encrypted), decompression, exact length,
    ///    and per-entry BLAKE3 digest.
    ///
    /// # Errors
    ///
    /// Returns [`ZarcError`] if any check fails.
    pub fn verify_all(&self) -> Result<(), ZarcError> {
        let payload_end = (self.header.payload_offset() + self.header.payload_len()) as usize;
        if let Some(expected) = self.archive_blake3 {
            expected.verify(&self.raw[..payload_end])?;
        }
        if let Some(ref stripe) = self.parity_stripe {
            let payload_start = self.header.payload_offset() as usize;
            let mut copy = self.raw[payload_start..payload_end].to_vec();
            stripe.verify_and_repair(&mut copy)?;
        }
        for entry in &self.entries {
            let _ = self.read_entry_bytes(entry)?;
        }
        Ok(())
    }

    /// Extract all entries safely into `dest_dir`.
    ///
    /// - Validates every path with [`safe_join`] (preventing `..`, absolute paths,
    ///   backslashes, drive letters, and reserved device names).
    /// - Refuses to traverse existing symlinks inside `dest_dir`.
    /// - Verifies BLAKE3 and AEAD tags before writing final file contents.
    ///
    /// # Errors
    ///
    /// Returns [`ZarcError`] if any entry fails verification or path safety checks.
    pub fn extract_to(&self, dest_dir: &Path) -> Result<usize, ZarcError> {
        fs::create_dir_all(dest_dir)?;
        let mut extracted_count = 0;

        for entry in &self.entries {
            let out_path = safe_join(dest_dir, &entry.path)?;
            ensure_no_symlink_ancestors(dest_dir, &out_path)?;

            match entry.kind {
                EntryKind::Directory => {
                    fs::create_dir_all(&out_path)?;
                    apply_permissions(&out_path, entry.unix_mode, true)?;
                }
                EntryKind::File => {
                    let bytes = self.read_entry_bytes(entry)?;
                    if let Some(parent) = out_path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    if out_path.exists() {
                        let meta = fs::symlink_metadata(&out_path)?;
                        if meta.file_type().is_symlink() {
                            return Err(ZarcError::UnsupportedFsEntry(format!(
                                "refusing to overwrite symlink at {}",
                                out_path.display()
                            )));
                        }
                    }
                    fs::write(&out_path, &bytes)?;
                    apply_permissions(&out_path, entry.unix_mode, false)?;
                }
            }
            extracted_count += 1;
        }
        Ok(extracted_count)
    }
}

fn ensure_no_symlink_ancestors(root: &Path, target: &Path) -> Result<(), ZarcError> {
    let rel = target.strip_prefix(root).unwrap_or(target);
    let mut cur = root.to_path_buf();
    for comp in rel.components() {
        cur.push(comp);
        if let Ok(meta) = fs::symlink_metadata(&cur) {
            if meta.file_type().is_symlink() {
                return Err(ZarcError::UnsupportedFsEntry(format!(
                    "symlink component detected during extraction: {}",
                    cur.display()
                )));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn unix_mode_from_metadata(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn unix_mode_from_metadata(_meta: &fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn apply_permissions(path: &Path, mode: u32, is_dir: bool) -> Result<(), ZarcError> {
    use std::os::unix::fs::PermissionsExt;
    if mode != 0 {
        // Mask off setuid/setgid/sticky bits (`0o777`) when extracting untrusted archives.
        let safe_mode = (mode & 0o777) | if is_dir { 0o700 } else { 0o600 };
        fs::set_permissions(path, fs::Permissions::from_mode(safe_mode))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn apply_permissions(_path: &Path, _mode: u32, _is_dir: bool) -> Result<(), ZarcError> {
    Ok(())
}

/// Attempt to repair a single-block payload corruption in a `.zarc` archive
/// using its embedded `TLV_PARITY_STRIPE` (if present).
///
/// Returns `Ok(Some(repaired_bytes))` if a parity stripe was present and
/// repaired 1 corrupted block, or `Ok(None)` if no repair was needed.
///
/// # Errors
///
/// Returns [`ZarcError`] if no parity stripe is present or damage exceeds
/// single-stripe recovery capability.
pub fn attempt_parity_repair(raw: &[u8], limits: &Limits) -> Result<Option<Vec<u8>>, ZarcError> {
    let header = Header::decode(raw, limits, Some(raw.len() as u64))?;
    let payload_start = header.payload_offset() as usize;
    let payload_end = (header.payload_offset() + header.payload_len()) as usize;
    let footer_slice = &raw[payload_end..];

    let mut r = TlvReader::new(footer_slice, *limits);
    let mut stripe: Option<ParityStripe> = None;
    while let Some(tlv) = r.next_tlv()? {
        if tlv.is_end() {
            break;
        }
        if tlv.ty == TLV_PARITY_STRIPE {
            stripe = Some(ParityStripe::decode(tlv.value)?);
        }
    }
    let stripe = stripe.ok_or_else(|| {
        ZarcError::MalformedArchive("archive does not contain a parity stripe".into())
    })?;

    let mut fixed = raw.to_vec();
    let count = stripe.verify_and_repair(&mut fixed[payload_start..payload_end])?;
    if count == 0 {
        Ok(None)
    } else {
        Ok(Some(fixed))
    }
}
