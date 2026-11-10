//! ZARC archive writer, reader, inspector, verifier, recovery engine, and extractor.
//!
//! File layout of a `.zarc` v1.0 archive:
//!
//! ```text
//! +-------------------------------------------------------------------+
//! | ZNF Core Fixed Header (64 bytes, FormatId = 1, Version = 1.0)     |
//! +-------------------------------------------------------------------+
//! | Metadata TLV Section (optional; present when HAS_METADATA set)    |
//! |   - TLV_KDF_PARAMS (0x0010): 28-byte Argon2id KdfParams           |
//! |   - TLV_COMMENT    (0x0020): UTF-8 archive comment (unencrypted)  |
//! |   - Non-critical extensions (0x7000..=0xFFFE, preserved)          |
//! |   - Critical extensions (0x4000..=0x6FFF, rejected if unknown)    |
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
//! |     - TLV_ZARC_ENCRYPTED_METADATA (0x0104, optional):             |
//! |         24-byte nonce || XChaCha20-Poly1305(comment_utf8, aad=hdr)|
//! |   - TLV_ARCHIVE_BLAKE3 (0x0102): 32-byte BLAKE3 over bytes        |
//! |         0 .. (payload_offset + payload_len)                       |
//! |   - TLV_PARITY_STRIPE (0x0103): optional ParityStripe             |
//! |   - TLV_END (0xFFFF)                                              |
//! +-------------------------------------------------------------------+
//! ```

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::UNIX_EPOCH;

use znf_compression::{compress, decompress, Algorithm, Config as CompConfig};
use znf_core::{
    is_critical_extension_type, Flags, FormatId, Header, Limits, TlvReader, TlvWriter,
    ZnfCompression, ZnfEncryption, HEADER_LEN,
};
use znf_crypto::{decrypt, encrypt, generate_nonce, KdfParams, SecretKey, NONCE_LEN, TAG_LEN};
use znf_integrity::{hash, Hash, Hasher, HASH_LEN};
use znf_recovery::ParityStripe;

use crate::entry::{
    decode_index, encode_index, EntryKind, EntryRecord, DEFAULT_MAX_ENTRIES, ENTRY_FLAG_ENCRYPTED,
    ENTRY_FLAG_HAS_USER_METADATA,
};
use crate::error::ZarcError;
use crate::path::{
    case_fold_path, normalize_fs_path, safe_join_with_depth, validate_archive_path,
    DEFAULT_MAX_DEPTH,
};

/// TLV type: Argon2id KDF parameters (`28` bytes).
pub const TLV_KDF_PARAMS: u16 = 0x0010;
/// TLV type: Optional UTF-8 archive comment (used when unencrypted).
pub const TLV_COMMENT: u16 = 0x0020;
/// TLV type: Unencrypted ZARC entry index table.
pub const TLV_ZARC_INDEX: u16 = 0x0100;
/// TLV type: Encrypted ZARC entry index (`24B nonce || ciphertext+tag`).
pub const TLV_ZARC_ENCRYPTED_INDEX: u16 = 0x0101;
/// TLV type: Whole-archive BLAKE3 digest over `0..(payload_offset + payload_len)`.
pub const TLV_ARCHIVE_BLAKE3: u16 = 0x0102;
/// TLV type: Optional XOR recovery parity stripe over payload.
pub const TLV_PARITY_STRIPE: u16 = 0x0103;
/// TLV type: Encrypted archive comment (`24B nonce || ciphertext+tag`).
pub const TLV_ZARC_ENCRYPTED_METADATA: u16 = 0x0104;

/// Progress notification emitted during archive creation or extraction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveProgress {
    /// Entry index (`0..total_entries`).
    pub entry_index: usize,
    /// Total entries being processed.
    pub total_entries: usize,
    /// Canonical archive path of the current entry.
    pub current_path: String,
    /// Total uncompressed bytes processed so far.
    pub bytes_processed: u64,
}

/// Aggregated compression statistics for a `.zarc` archive.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CompressionStats {
    /// Total entries (`file_count + dir_count`).
    pub total_entries: usize,
    /// Number of regular file entries.
    pub file_count: usize,
    /// Number of directory entries.
    pub dir_count: usize,
    /// Files stored uncompressed (`Algorithm::None`).
    pub stored_files: usize,
    /// Files compressed with Zstandard (`Algorithm::Zstd`).
    pub zstd_files: usize,
    /// Files compressed with LZ4 (`Algorithm::Lz4`).
    pub lz4_files: usize,
    /// Sum of original uncompressed bytes across all entries.
    pub total_uncompressed_bytes: u64,
    /// Sum of stored payload bytes across all entries.
    pub total_stored_bytes: u64,
}

impl CompressionStats {
    /// Compression ratio (`total_uncompressed_bytes / total_stored_bytes`), or `1.0` if empty.
    #[must_use]
    pub fn ratio(&self) -> f64 {
        if self.total_stored_bytes == 0 {
            1.0
        } else {
            self.total_uncompressed_bytes as f64 / self.total_stored_bytes as f64
        }
    }

    /// Space savings percentage (`(1 - stored / uncompressed) * 100`), or `0.0` if empty.
    #[must_use]
    pub fn space_savings_percent(&self) -> f64 {
        if self.total_uncompressed_bytes == 0 {
            0.0
        } else {
            (1.0 - (self.total_stored_bytes as f64 / self.total_uncompressed_bytes as f64)) * 100.0
        }
    }
}

/// Diagnostic inspection report of a `.zarc` archive (works with or without decryption password).
#[derive(Debug, Clone)]
pub struct ZarcInspection {
    /// Total archive size in bytes.
    pub file_size: u64,
    /// ZARC format version (`major, minor`).
    pub version: (u16, u16),
    /// Header feature flags.
    pub flags: Flags,
    /// Global compression identifier in header.
    pub header_compression: ZnfCompression,
    /// Global encryption identifier in header.
    pub header_encryption: ZnfEncryption,
    /// Payload start offset.
    pub payload_offset: u64,
    /// Payload byte length.
    pub payload_len: u64,
    /// Whether the entry index is encrypted and locked (no password provided).
    pub index_locked: bool,
    /// Whole-archive BLAKE3 digest in footer (verified even when locked).
    pub archive_blake3: Option<Hash>,
    /// Whether whole-archive BLAKE3 was verified against `0..payload_end`.
    pub archive_blake3_verified: bool,
    /// Whether a recovery parity stripe is present in the footer.
    pub has_parity_stripe: bool,
    /// Optional KDF parameters (when encrypted).
    pub kdf_params: Option<KdfParams>,
    /// Optional comment (available when unencrypted or authenticated).
    pub comment: Option<String>,
    /// Compression statistics (available when unencrypted or authenticated).
    pub stats: Option<CompressionStats>,
    /// Entry records (available when unencrypted or authenticated).
    pub entries: Vec<EntryRecord>,
    /// Advisory forward-compatibility warnings (e.g. non-zero advisory flags or unknown non-critical TLVs).
    pub warnings: Vec<String>,
}

/// Per-entry integrity and recovery status produced by [`ZarcArchive::diagnose_entries`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryDiagnosis {
    /// Canonical archive path.
    pub path: String,
    /// Entry kind.
    pub kind: EntryKind,
    /// Uncompressed size.
    pub uncompressed_size: u64,
    /// Whether this entry's payload and BLAKE3/AEAD integrity verified cleanly.
    pub intact: bool,
    /// Error description if damaged/unrecoverable.
    pub error: Option<String>,
}

/// Summary of partial recovery extraction (`extract_verified_entries`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryExtractionReport {
    /// Paths of entries that passed full verification and were extracted.
    pub extracted_paths: Vec<String>,
    /// Paths and error messages of damaged entries that were refused/skipped.
    pub failed_entries: Vec<(String, String)>,
}

/// Options for creating a `.zarc` archive.
#[derive(Debug, Clone)]
pub struct WriteOptions {
    /// Global default compression configuration.
    pub compression: CompConfig,
    /// Optional password for Argon2id + XChaCha20-Poly1305 encryption.
    pub password: Option<Vec<u8>>,
    /// Optional explicit KDF parameters (defaults to `KdfParams::new_default()`).
    pub kdf_params: Option<KdfParams>,
    /// Optional archive comment (encrypted in `TLV_ZARC_ENCRYPTED_METADATA` when `password` is set).
    pub comment: Option<String>,
    /// Whether to include a recovery parity stripe in the footer.
    pub include_parity: bool,
    /// Whether `finish_to_path` is allowed to overwrite an existing file.
    pub overwrite: bool,
    /// Reject case-insensitive path collisions (`File.txt` vs `file.txt`) during creation.
    pub reject_case_collisions: bool,
    /// Streaming read buffer size in bytes (default `64 KiB`).
    pub buffer_size: usize,
    /// Resource limits used while encoding TLVs.
    pub limits: Limits,
}

impl Default for WriteOptions {
    fn default() -> Self {
        WriteOptions {
            compression: CompConfig::default(),
            password: None,
            kdf_params: None,
            comment: None,
            include_parity: false,
            overwrite: false,
            reject_case_collisions: false,
            buffer_size: 64 * 1024,
            limits: Limits::default(),
        }
    }
}

/// Options for reading and verifying a `.zarc` archive.
#[derive(Debug, Clone)]
pub struct ReadOptions {
    /// Optional password if the archive is encrypted.
    pub password: Option<Vec<u8>>,
    /// Resource and decompression-bomb limits.
    pub limits: Limits,
    /// Maximum number of entries allowed in the index.
    pub max_entries: usize,
    /// Maximum compression ratio (`uncompressed / stored`) before flagging a bomb.
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

/// Options controlling safe archive extraction (`extract_with_options`).
#[derive(Debug, Clone)]
pub struct ExtractOptions {
    /// Allow overwriting existing files in the destination directory (default `false`).
    pub overwrite: bool,
    /// Optional subset of archive paths (files or directory prefixes) to extract.
    pub selected_paths: Option<Vec<String>>,
    /// Reject archives containing case-insensitive path collisions (`File.txt` vs `file.txt`).
    pub detect_case_collisions: bool,
    /// Maximum allowed directory nesting depth (default `64`).
    pub max_directory_depth: usize,
    /// Maximum total files to extract.
    pub max_files: usize,
    /// Maximum total bytes to write to disk.
    pub max_disk_bytes: u64,
}

impl Default for ExtractOptions {
    fn default() -> Self {
        ExtractOptions {
            overwrite: false,
            selected_paths: None,
            detect_case_collisions: true,
            max_directory_depth: DEFAULT_MAX_DEPTH,
            max_files: DEFAULT_MAX_ENTRIES,
            max_disk_bytes: 10 * 1024 * 1024 * 1024, // 10 GiB
        }
    }
}

/// Builder for creating `.zarc` archives with streaming file reading and bounded buffers.
#[derive(Debug)]
pub struct ZarcWriter {
    options: WriteOptions,
    seen_paths: HashSet<String>,
    seen_case_folded: HashMap<String, String>,
    pending: Vec<PendingEntry>,
    preserved_meta_extensions: Vec<(u16, Vec<u8>)>,
}

#[derive(Debug)]
enum EntrySource {
    EmptyDir,
    Memory(Vec<u8>),
    FsFile {
        fs_path: PathBuf,
        expected_size: u64,
        expected_mtime_secs: i64,
    },
}

#[derive(Debug)]
struct PendingEntry {
    path: String,
    kind: EntryKind,
    compression_override: Option<CompConfig>,
    unix_mode: u32,
    mtime_unix_secs: i64,
    user_metadata: BTreeMap<String, String>,
    source: EntrySource,
}

impl ZarcWriter {
    /// Create a new archive builder with the given options.
    #[must_use]
    pub fn new(options: WriteOptions) -> Self {
        ZarcWriter {
            options,
            seen_paths: HashSet::new(),
            seen_case_folded: HashMap::new(),
            pending: Vec::new(),
            preserved_meta_extensions: Vec::new(),
        }
    }

    /// Add a non-critical metadata TLV extension (`0x7000..=0xFFFE`) to preserve in the archive.
    pub fn add_metadata_extension(&mut self, ty: u16, value: Vec<u8>) {
        self.preserved_meta_extensions.push((ty, value));
    }

    fn register_path(&mut self, canonical: &str) -> Result<(), ZarcError> {
        if !self.seen_paths.insert(canonical.to_string()) {
            return Err(ZarcError::DuplicateEntry(canonical.to_string()));
        }
        if self.options.reject_case_collisions {
            let folded = case_fold_path(canonical);
            if let Some(prev) = self.seen_case_folded.insert(folded, canonical.to_string()) {
                return Err(ZarcError::CaseInsensitiveCollision {
                    first: prev,
                    second: canonical.to_string(),
                });
            }
        }
        Ok(())
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
        self.register_path(&canonical)?;
        self.pending.push(PendingEntry {
            path: canonical,
            kind: EntryKind::Directory,
            compression_override: None,
            unix_mode,
            mtime_unix_secs,
            user_metadata: BTreeMap::new(),
            source: EntrySource::EmptyDir,
        });
        Ok(())
    }

    /// Add a file entry from an in-memory byte slice using the global compression config.
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
        self.add_bytes_with_options(
            archive_path,
            data,
            unix_mode,
            mtime_unix_secs,
            None,
            BTreeMap::new(),
        )
    }

    /// Add a file entry with optional per-entry compression override and user metadata.
    ///
    /// # Errors
    ///
    /// Returns [`ZarcError`] if `archive_path` is unsafe or a duplicate.
    pub fn add_bytes_with_options(
        &mut self,
        archive_path: &str,
        data: &[u8],
        unix_mode: u32,
        mtime_unix_secs: i64,
        compression_override: Option<CompConfig>,
        user_metadata: BTreeMap<String, String>,
    ) -> Result<(), ZarcError> {
        let canonical = validate_archive_path(archive_path)?;
        self.register_path(&canonical)?;
        self.pending.push(PendingEntry {
            path: canonical,
            kind: EntryKind::File,
            compression_override,
            unix_mode,
            mtime_unix_secs,
            user_metadata,
            source: EntrySource::Memory(data.to_vec()),
        });
        Ok(())
    }

    /// Recursively add a file or directory from the local filesystem.
    ///
    /// Files are recorded by path and streamed in bounded buffers during `finish`
    /// rather than loading all files into RAM up front. Symlinks are refused.
    ///
    /// # Errors
    ///
    /// Returns [`ZarcError`] on unsafe path, symlink, or I/O error.
    pub fn add_path(&mut self, base_dir: &Path, fs_path: &Path) -> Result<(), ZarcError> {
        let symlink_meta = fs::symlink_metadata(fs_path)?;
        if symlink_meta.file_type().is_symlink() {
            return Err(ZarcError::SymlinkNotAllowed(format!(
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
            children.sort_by_key(|e| e.file_name());
            for child in children {
                self.add_path(base_dir, &child.path())?;
            }
        } else if symlink_meta.is_file() {
            let archive_path = normalize_fs_path(rel)?;
            self.register_path(&archive_path)?;
            self.pending.push(PendingEntry {
                path: archive_path,
                kind: EntryKind::File,
                compression_override: None,
                unix_mode: mode,
                mtime_unix_secs: mtime,
                user_metadata: BTreeMap::new(),
                source: EntrySource::FsFile {
                    fs_path: fs_path.to_path_buf(),
                    expected_size: symlink_meta.len(),
                    expected_mtime_secs: mtime,
                },
            });
        } else {
            return Err(ZarcError::UnsupportedFsEntry(fs_path.display().to_string()));
        }
        Ok(())
    }

    /// Finalize and atomically write the `.zarc` archive to `output_path`.
    ///
    /// - Refuses to overwrite an existing file unless `self.options.overwrite` is `true`.
    /// - Writes to a temporary sibling file first and cleans it up if any error occurs.
    ///
    /// # Errors
    ///
    /// Returns [`ZarcError`] on existing output file, changed source file, or I/O failure.
    pub fn finish_to_path(
        self,
        output_path: &Path,
        progress: Option<&mut dyn FnMut(ArchiveProgress)>,
        cancel_flag: Option<&AtomicBool>,
    ) -> Result<(), ZarcError> {
        if output_path.exists() && !self.options.overwrite {
            return Err(ZarcError::TargetAlreadyExists(
                output_path.display().to_string(),
            ));
        }
        if let Some(parent) = output_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let tmp_name = format!(
            ".{}.zarc_part_{}",
            output_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("archive"),
            std::process::id()
        );
        let tmp_path = output_path.with_file_name(tmp_name);
        let result = (|| -> Result<(), ZarcError> {
            let mut file = fs::File::create(&tmp_path)?;
            self.finish_with_progress(&mut file, progress, cancel_flag)?;
            file.flush()?;
            drop(file);
            fs::rename(&tmp_path, output_path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp_path);
        }
        result
    }

    /// Finalize and encode the complete `.zarc` archive into `writer`.
    ///
    /// # Errors
    ///
    /// Returns [`ZarcError`] on compression, encryption, or I/O failure.
    pub fn finish<W: Write>(self, writer: W) -> Result<(), ZarcError> {
        self.finish_with_progress(writer, None, None)
    }

    /// Finalize and encode the `.zarc` archive into `writer` with optional progress
    /// reporting and cooperative cancellation.
    ///
    /// # Errors
    ///
    /// Returns [`ZarcError`] on failure or cancellation.
    pub fn finish_with_progress<W: Write>(
        self,
        mut writer: W,
        mut progress: Option<&mut dyn FnMut(ArchiveProgress)>,
        cancel_flag: Option<&AtomicBool>,
    ) -> Result<(), ZarcError> {
        let limits = &self.options.limits;
        let buf_size = self.options.buffer_size.max(4096);

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

        // 2. Build metadata TLV section.
        //    Privacy rule: when encrypted, `comment` is NOT written to the unencrypted
        //    metadata section; it is encrypted in the footer (`TLV_ZARC_ENCRYPTED_METADATA`).
        let mut meta_tlv = TlvWriter::new();
        if let Some(ref params) = kdf_params {
            meta_tlv.push(TLV_KDF_PARAMS, &params.encode(), limits)?;
        }
        if derived_key.is_none() {
            if let Some(ref comment) = self.options.comment {
                meta_tlv.push(TLV_COMMENT, comment.as_bytes(), limits)?;
            }
        }
        for (ty, val) in &self.preserved_meta_extensions {
            meta_tlv.push(*ty, val, limits)?;
        }
        let has_metadata = !meta_tlv.is_empty();
        if has_metadata {
            meta_tlv.push_end();
        }
        let meta_bytes = meta_tlv.into_bytes();

        // 3. Stream-read, hash, and compress each entry using bounded buffers.
        struct CompressedItem {
            path: String,
            kind: EntryKind,
            compression: Algorithm,
            unix_mode: u32,
            mtime_unix_secs: i64,
            uncompressed_size: u64,
            blake3_hash: Hash,
            user_metadata: BTreeMap<String, String>,
            compressed: Vec<u8>,
        }

        let total_entries = self.pending.len();
        let mut items = Vec::with_capacity(total_entries);
        let mut total_payload_len: u64 = 0;
        let mut bytes_processed_so_far: u64 = 0;
        let mut any_entry_compressed = self.options.compression.algorithm != Algorithm::None;

        for (idx, p) in self.pending.into_iter().enumerate() {
            if let Some(flag) = cancel_flag {
                if flag.load(Ordering::Relaxed) {
                    return Err(ZarcError::Cancelled);
                }
            }
            let comp_cfg = p.compression_override.unwrap_or(self.options.compression);
            if comp_cfg.algorithm != Algorithm::None {
                any_entry_compressed = true;
            }

            let (compression, compressed, digest, uncomp_len) = match p.source {
                EntrySource::EmptyDir => (
                    Algorithm::None,
                    Vec::new(),
                    Hash::from_bytes([0u8; HASH_LEN]),
                    0u64,
                ),
                EntrySource::Memory(data) => {
                    let u_len = data.len() as u64;
                    let d = hash(&data);
                    let mut c = Vec::new();
                    compress(&data[..], &mut c, &comp_cfg)?;
                    (comp_cfg.algorithm, c, d, u_len)
                }
                EntrySource::FsFile {
                    ref fs_path,
                    expected_size,
                    expected_mtime_secs,
                } => {
                    // Stream file through Hasher + Compressor in bounded chunks.
                    let file = fs::File::open(fs_path)?;
                    let mut hashing_reader = HashingReader::new(file, buf_size);
                    let mut c = Vec::new();
                    let read_bytes = compress(&mut hashing_reader, &mut c, &comp_cfg)?;
                    let (d, _) = hashing_reader.finish();

                    // Check if file size or modification timestamp changed during archiving.
                    let post_meta = fs::symlink_metadata(fs_path)?;
                    let post_mtime = post_meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map_or(0, |dur| dur.as_secs() as i64);
                    if read_bytes != expected_size
                        || post_meta.len() != expected_size
                        || post_mtime != expected_mtime_secs
                    {
                        return Err(ZarcError::SourceFileChanged(fs_path.display().to_string()));
                    }
                    (comp_cfg.algorithm, c, d, read_bytes)
                }
            };

            bytes_processed_so_far = bytes_processed_so_far.saturating_add(uncomp_len);
            if let Some(cb) = progress.as_deref_mut() {
                cb(ArchiveProgress {
                    entry_index: idx,
                    total_entries,
                    current_path: p.path.clone(),
                    bytes_processed: bytes_processed_so_far,
                });
            }

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
                uncompressed_size: uncomp_len,
                blake3_hash: digest,
                user_metadata: p.user_metadata,
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
        if any_entry_compressed {
            let hdr_algo = if self.options.compression.algorithm != Algorithm::None {
                self.options.compression.algorithm
            } else {
                Algorithm::Zstd
            };
            header.set_compression(ZnfCompression::from_algorithm(hdr_algo));
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
            let (stored_bytes, nonce, mut e_flags) = match (&derived_key, item.kind) {
                (Some(key), EntryKind::File) => {
                    let n = generate_nonce()?;
                    let ct = encrypt(key, &n, &item.compressed, &header_bytes)?;
                    (ct, n, ENTRY_FLAG_ENCRYPTED)
                }
                _ => (item.compressed, [0u8; NONCE_LEN], 0u16),
            };
            if !item.user_metadata.is_empty() {
                e_flags |= ENTRY_FLAG_HAS_USER_METADATA;
            }
            let stored_size = stored_bytes.len() as u64;
            payload_bytes.extend_from_slice(&stored_bytes);
            records.push(EntryRecord {
                path: item.path,
                kind: item.kind,
                compression: item.compression,
                flags: e_flags,
                unix_mode: item.unix_mode,
                mtime_unix_secs: item.mtime_unix_secs,
                uncompressed_size: item.uncompressed_size,
                stored_size,
                payload_rel_offset: rel_offset,
                blake3_hash: item.blake3_hash,
                entry_nonce: nonce,
                user_metadata: item.user_metadata,
            });
        }

        // 6. Compute whole-archive BLAKE3 over header + metadata + payload.
        let mut archive_hasher = Hasher::new();
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

            if let Some(ref comment) = self.options.comment {
                let cm_nonce = generate_nonce()?;
                let cm_ct = encrypt(key, &cm_nonce, comment.as_bytes(), &header_bytes)?;
                let mut enc_cm = Vec::with_capacity(NONCE_LEN + cm_ct.len());
                enc_cm.extend_from_slice(&cm_nonce);
                enc_cm.extend_from_slice(&cm_ct);
                footer_tlv.push(TLV_ZARC_ENCRYPTED_METADATA, &enc_cm, limits)?;
            }
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

struct HashingReader<R> {
    inner: R,
    hasher: Hasher,
    total_read: u64,
    chunk_cap: usize,
}

impl<R: Read> HashingReader<R> {
    fn new(inner: R, chunk_cap: usize) -> Self {
        HashingReader {
            inner,
            hasher: Hasher::new(),
            total_read: 0,
            chunk_cap,
        }
    }

    fn finish(self) -> (Hash, u64) {
        (self.hasher.finalize(), self.total_read)
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let cap = buf.len().min(self.chunk_cap);
        let n = self.inner.read(&mut buf[..cap])?;
        if n > 0 {
            self.hasher.update(&buf[..n]);
            self.total_read += n as u64;
        }
        Ok(n)
    }
}

/// Parsed `.zarc` archive reader, inspector, verifier, and extractor.
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
    preserved_meta_extensions: Vec<(u16, Vec<u8>)>,
    options: ReadOptions,
}

impl<'a> ZarcArchive<'a> {
    /// Open and parse a `.zarc` archive, validating the ZNF Core header,
    /// metadata TLVs, footer TLVs, and entry index.
    ///
    /// Rejects unsupported critical extensions (`0x4000..=0x6FFF`), preserves
    /// unknown non-critical extensions (`0x7000..=0xFFFE`), and never panics.
    ///
    /// # Errors
    ///
    /// Returns [`ZarcError`] on any structural, integrity, or authentication error.
    pub fn open(raw: &'a [u8], options: ReadOptions) -> Result<Self, ZarcError> {
        let header = Header::decode(raw, &options.limits, Some(raw.len() as u64))?;
        if header.format_id() != FormatId::ZARC {
            return Err(ZarcError::NotZarcFormat(header.format_id().raw()));
        }
        let mut header_bytes = [0u8; HEADER_LEN];
        header_bytes.copy_from_slice(&raw[..HEADER_LEN]);

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
        let mut preserved_meta_extensions = Vec::new();
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
                    other if is_critical_extension_type(other) => {
                        return Err(ZarcError::Core(
                            znf_core::Error::UnsupportedCriticalExtension(other),
                        ));
                    }
                    other => {
                        preserved_meta_extensions.push((other, tlv.value.to_vec()));
                    }
                }
            }
            if !saw_meta_end {
                return Err(ZarcError::MalformedArchive(
                    "metadata TLV section missing TLV_END marker".into(),
                ));
            }
        }

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
                TLV_ZARC_ENCRYPTED_METADATA => {
                    let key = derived_key.as_ref().ok_or_else(|| {
                        ZarcError::MalformedArchive(
                            "encrypted metadata in unencrypted archive".into(),
                        )
                    })?;
                    if tlv.value.len() < NONCE_LEN + TAG_LEN {
                        return Err(ZarcError::MalformedArchive(
                            "encrypted metadata TLV too short".into(),
                        ));
                    }
                    let mut nonce = [0u8; NONCE_LEN];
                    nonce.copy_from_slice(&tlv.value[..NONCE_LEN]);
                    let ct = &tlv.value[NONCE_LEN..];
                    let pt = decrypt(key, &nonce, ct, &header_bytes)?;
                    let s = std::str::from_utf8(&pt).map_err(|_| {
                        ZarcError::MalformedArchive("invalid UTF-8 in decrypted comment".into())
                    })?;
                    comment = Some(s.to_string());
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
                other if is_critical_extension_type(other) => {
                    return Err(ZarcError::Core(
                        znf_core::Error::UnsupportedCriticalExtension(other),
                    ));
                }
                _ => {}
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
            if entry.uncompressed_size > 64 * 1024 && entry.stored_size > 0 {
                let ratio = entry.uncompressed_size / entry.stored_size;
                if ratio > options.max_compression_ratio {
                    return Err(ZarcError::ResourceLimitExceeded(format!(
                        "suspicious compression ratio ({ratio}:1) on entry '{}'",
                        entry.path
                    )));
                }
            }
        }

        // Reject overlapping entry stored ranges
        for i in 0..entries.len() {
            for j in (i + 1)..entries.len() {
                let a = &entries[i];
                let b = &entries[j];
                let a_start = a.payload_rel_offset;
                let a_end = a_start.saturating_add(a.stored_size);
                let b_start = b.payload_rel_offset;
                let b_end = b_start.saturating_add(b.stored_size);
                if a_start < b_end && b_start < a_end {
                    return Err(ZarcError::MalformedArchive(format!(
                        "overlapping entry stored ranges: '{}' ({}..{}) and '{}' ({}..{})",
                        a.path, a_start, a_end, b.path, b_start, b_end
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
            preserved_meta_extensions,
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

    /// Look up an entry by its canonical archive path.
    #[must_use]
    pub fn find_entry(&self, path: &str) -> Option<&EntryRecord> {
        self.entries.iter().find(|e| e.path == path)
    }

    /// Preserved non-critical metadata TLV extensions (`0x7000..=0xFFFE`).
    #[must_use]
    pub fn preserved_metadata_extensions(&self) -> &[(u16, Vec<u8>)] {
        &self.preserved_meta_extensions
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

    /// Compute aggregated compression statistics across all entries.
    #[must_use]
    pub fn compression_stats(&self) -> CompressionStats {
        let mut stats = CompressionStats {
            total_entries: self.entries.len(),
            ..CompressionStats::default()
        };
        for e in &self.entries {
            match e.kind {
                EntryKind::Directory => stats.dir_count += 1,
                EntryKind::File => {
                    stats.file_count += 1;
                    match e.compression {
                        Algorithm::None => stats.stored_files += 1,
                        Algorithm::Zstd => stats.zstd_files += 1,
                        Algorithm::Lz4 => stats.lz4_files += 1,
                    }
                    stats.total_uncompressed_bytes += e.uncompressed_size;
                    stats.total_stored_bytes += e.stored_size;
                }
            }
        }
        stats
    }

    /// Stream-decode, authenticate, decompress, and BLAKE3-verify a single entry
    /// into `output` with bounded memory.
    ///
    /// # Errors
    ///
    /// Returns [`ZarcError`] on tampering, corruption, or bomb limit violation.
    pub fn stream_entry_to<W: Write>(
        &self,
        entry: &EntryRecord,
        mut output: W,
    ) -> Result<u64, ZarcError> {
        if entry.kind == EntryKind::Directory {
            return Ok(0);
        }
        let payload_start = self.header.payload_offset() as usize;
        let start = payload_start + entry.payload_rel_offset as usize;
        let end = start + entry.stored_size as usize;
        if end > self.raw.len() {
            return Err(ZarcError::MalformedArchive(format!(
                "entry '{}' truncated in archive payload",
                entry.path
            )));
        }
        let stored_slice = &self.raw[start..end];

        let compressed_cow: std::borrow::Cow<'_, [u8]> = if let Some(ref key) = self.derived_key {
            let pt = decrypt(key, &entry.entry_nonce, stored_slice, &self.header_bytes)?;
            std::borrow::Cow::Owned(pt)
        } else {
            std::borrow::Cow::Borrowed(stored_slice)
        };

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

        let mut hashing_writer = HashingWriter {
            inner: &mut output,
            hasher: Hasher::new(),
            written: 0,
        };
        decompress(
            &compressed_cow[..],
            &mut hashing_writer,
            entry.compression,
            &comp_cfg,
        )?;
        let written = hashing_writer.written;
        let computed_hash = hashing_writer.hasher.finalize();

        if written != entry.uncompressed_size {
            return Err(ZarcError::MalformedArchive(format!(
                "entry '{}' decompressed to {} bytes, expected {}",
                entry.path, written, entry.uncompressed_size
            )));
        }
        if computed_hash != entry.blake3_hash {
            return Err(ZarcError::Integrity(
                znf_integrity::IntegrityError::HashMismatch {
                    expected: entry.blake3_hash.to_hex(),
                    computed: computed_hash.to_hex(),
                },
            ));
        }
        Ok(written)
    }

    /// Decode, authenticate, decompress, and BLAKE3-verify a single entry's
    /// payload bytes in memory.
    ///
    /// # Errors
    ///
    /// Returns [`ZarcError`] on tampering, corruption, or bomb limit violation.
    pub fn read_entry_bytes(&self, entry: &EntryRecord) -> Result<Vec<u8>, ZarcError> {
        let mut out = Vec::with_capacity(entry.uncompressed_size.min(1024 * 1024) as usize);
        self.stream_entry_to(entry, &mut out)?;
        Ok(out)
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
            self.stream_entry_to(entry, std::io::sink())?;
        }
        Ok(())
    }

    /// Diagnose each entry independently without aborting on the first damaged entry.
    ///
    /// Useful for inspecting partially corrupted archives and identifying which
    /// entries remain independently verifiable and recoverable.
    #[must_use]
    pub fn diagnose_entries(&self) -> Vec<EntryDiagnosis> {
        let mut reports = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            match self.stream_entry_to(entry, std::io::sink()) {
                Ok(_) => reports.push(EntryDiagnosis {
                    path: entry.path.clone(),
                    kind: entry.kind,
                    uncompressed_size: entry.uncompressed_size,
                    intact: true,
                    error: None,
                }),
                Err(e) => reports.push(EntryDiagnosis {
                    path: entry.path.clone(),
                    kind: entry.kind,
                    uncompressed_size: entry.uncompressed_size,
                    intact: false,
                    error: Some(e.to_string()),
                }),
            }
        }
        reports
    }

    /// Extract all entries into `dest_dir` with default extraction options
    /// (refuses to overwrite existing files, checks case collisions, verifies BLAKE3).
    ///
    /// # Errors
    ///
    /// Returns [`ZarcError`] if any entry fails verification or safety checks.
    pub fn extract_to(&self, dest_dir: &Path) -> Result<usize, ZarcError> {
        self.extract_with_options(dest_dir, &ExtractOptions::default(), None, None)
    }

    /// Extract entries into `dest_dir` according to `extract_opts` with optional
    /// progress reporting and cooperative cancellation.
    ///
    /// - Validates every path and directory depth via [`safe_join_with_depth`].
    /// - Detects case-insensitive collisions when `extract_opts.detect_case_collisions` is `true`.
    /// - Refuses to traverse or overwrite symlinks inside `dest_dir`.
    /// - Refuses to overwrite existing files unless `extract_opts.overwrite` is `true`.
    /// - Streams decompressed data to a temporary sibling file and verifies BLAKE3
    ///   **before** atomically renaming into place.
    ///
    /// # Errors
    ///
    /// Returns [`ZarcError`] on any safety, limit, or integrity violation.
    pub fn extract_with_options(
        &self,
        dest_dir: &Path,
        extract_opts: &ExtractOptions,
        mut progress: Option<&mut dyn FnMut(ArchiveProgress)>,
        cancel_flag: Option<&AtomicBool>,
    ) -> Result<usize, ZarcError> {
        // Normalize optional selection filters.
        let normalized_filters: Option<Vec<String>> = match &extract_opts.selected_paths {
            None => None,
            Some(list) => {
                let mut clean = Vec::with_capacity(list.len());
                for p in list {
                    clean.push(validate_archive_path(p)?);
                }
                Some(clean)
            }
        };

        let matching_entries: Vec<&EntryRecord> = self
            .entries
            .iter()
            .filter(|e| entry_matches_selection(&e.path, normalized_filters.as_deref()))
            .collect();

        if let Some(ref filters) = normalized_filters {
            if !filters.is_empty() && matching_entries.is_empty() {
                return Err(ZarcError::EntryNotFound(filters.join(", ")));
            }
        }

        if matching_entries.len() > extract_opts.max_files {
            return Err(ZarcError::ResourceLimitExceeded(format!(
                "extraction entry count {} exceeds limit {}",
                matching_entries.len(),
                extract_opts.max_files
            )));
        }

        // Pre-flight check: case-insensitive collisions and total disk budget.
        let mut folded_seen: HashMap<String, String> = HashMap::new();
        let mut planned_disk_bytes: u64 = 0;
        for entry in &matching_entries {
            if extract_opts.detect_case_collisions {
                let folded = case_fold_path(&entry.path);
                if let Some(prev) = folded_seen.insert(folded, entry.path.clone()) {
                    return Err(ZarcError::CaseInsensitiveCollision {
                        first: prev,
                        second: entry.path.clone(),
                    });
                }
            }
            planned_disk_bytes = planned_disk_bytes.saturating_add(entry.uncompressed_size);
            if planned_disk_bytes > extract_opts.max_disk_bytes {
                return Err(ZarcError::ResourceLimitExceeded(format!(
                    "planned extraction size {planned_disk_bytes} exceeds max_disk_bytes {}",
                    extract_opts.max_disk_bytes
                )));
            }
        }

        fs::create_dir_all(dest_dir)?;
        let mut extracted_count = 0usize;
        let mut bytes_processed = 0u64;
        let total_entries = matching_entries.len();

        for (idx, entry) in matching_entries.into_iter().enumerate() {
            if let Some(flag) = cancel_flag {
                if flag.load(Ordering::Relaxed) {
                    return Err(ZarcError::Cancelled);
                }
            }
            let out_path =
                safe_join_with_depth(dest_dir, &entry.path, extract_opts.max_directory_depth)?;
            ensure_no_symlink_ancestors(dest_dir, &out_path)?;

            match entry.kind {
                EntryKind::Directory => {
                    fs::create_dir_all(&out_path)?;
                    apply_permissions(&out_path, entry.unix_mode, true)?;
                }
                EntryKind::File => {
                    if let Some(parent) = out_path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    if let Ok(meta) = fs::symlink_metadata(&out_path) {
                        if meta.file_type().is_symlink() {
                            return Err(ZarcError::SymlinkNotAllowed(format!(
                                "refusing to overwrite symlink at {}",
                                out_path.display()
                            )));
                        }
                        if !extract_opts.overwrite {
                            return Err(ZarcError::TargetAlreadyExists(
                                out_path.display().to_string(),
                            ));
                        }
                    }

                    // Stream to a temporary sibling file and verify BLAKE3 before renaming.
                    let tmp_name = format!(
                        ".{}.zarc_extract_{}_{}",
                        entry.file_name(),
                        std::process::id(),
                        idx
                    );
                    let tmp_path = out_path.with_file_name(tmp_name);
                    let write_res = (|| -> Result<u64, ZarcError> {
                        let mut tmp_file = fs::File::create(&tmp_path)?;
                        let n = self.stream_entry_to(entry, &mut tmp_file)?;
                        tmp_file.flush()?;
                        Ok(n)
                    })();

                    match write_res {
                        Ok(n) => {
                            fs::rename(&tmp_path, &out_path)?;
                            apply_permissions(&out_path, entry.unix_mode, false)?;
                            bytes_processed = bytes_processed.saturating_add(n);
                        }
                        Err(e) => {
                            let _ = fs::remove_file(&tmp_path);
                            return Err(e);
                        }
                    }
                }
            }

            extracted_count += 1;
            if let Some(cb) = progress.as_deref_mut() {
                cb(ArchiveProgress {
                    entry_index: idx,
                    total_entries,
                    current_path: entry.path.clone(),
                    bytes_processed,
                });
            }
        }
        Ok(extracted_count)
    }

    /// Partially extract only independently verified intact entries into `dest_dir`,
    /// refusing to write any damaged entry and returning a detailed [`RecoveryExtractionReport`].
    ///
    /// # Errors
    ///
    /// Returns [`ZarcError`] on path safety or filesystem errors.
    pub fn extract_verified_entries(
        &self,
        dest_dir: &Path,
        extract_opts: &ExtractOptions,
    ) -> Result<RecoveryExtractionReport, ZarcError> {
        fs::create_dir_all(dest_dir)?;
        let mut extracted_paths = Vec::new();
        let mut failed_entries = Vec::new();

        for (idx, entry) in self.entries.iter().enumerate() {
            let out_path =
                safe_join_with_depth(dest_dir, &entry.path, extract_opts.max_directory_depth)?;
            ensure_no_symlink_ancestors(dest_dir, &out_path)?;

            match entry.kind {
                EntryKind::Directory => {
                    fs::create_dir_all(&out_path)?;
                    apply_permissions(&out_path, entry.unix_mode, true)?;
                    extracted_paths.push(entry.path.clone());
                }
                EntryKind::File => {
                    if let Some(parent) = out_path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    if out_path.exists() && !extract_opts.overwrite {
                        return Err(ZarcError::TargetAlreadyExists(
                            out_path.display().to_string(),
                        ));
                    }
                    let tmp_name = format!(
                        ".{}.zarc_recover_{}_{}",
                        entry.file_name(),
                        std::process::id(),
                        idx
                    );
                    let tmp_path = out_path.with_file_name(tmp_name);
                    let res = (|| -> Result<(), ZarcError> {
                        let mut tmp_file = fs::File::create(&tmp_path)?;
                        self.stream_entry_to(entry, &mut tmp_file)?;
                        tmp_file.flush()?;
                        Ok(())
                    })();
                    match res {
                        Ok(()) => {
                            fs::rename(&tmp_path, &out_path)?;
                            apply_permissions(&out_path, entry.unix_mode, false)?;
                            extracted_paths.push(entry.path.clone());
                        }
                        Err(e) => {
                            let _ = fs::remove_file(&tmp_path);
                            failed_entries.push((entry.path.clone(), e.to_string()));
                        }
                    }
                }
            }
        }

        Ok(RecoveryExtractionReport {
            extracted_paths,
            failed_entries,
        })
    }
}

struct HashingWriter<W> {
    inner: W,
    hasher: Hasher,
    written: u64,
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        if n > 0 {
            self.hasher.update(&buf[..n]);
            self.written += n as u64;
        }
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn entry_matches_selection(entry_path: &str, filters: Option<&[String]>) -> bool {
    match filters {
        None => true,
        Some([]) => true,
        Some(list) => list.iter().any(|sel| {
            entry_path == sel
                || entry_path
                    .strip_prefix(sel)
                    .is_some_and(|rest| rest.starts_with('/'))
        }),
    }
}

/// Inspect a `.zarc` archive without extracting files.
///
/// If the archive is encrypted and `password` is `None`, returns header, flags,
/// KDF parameters, and verified whole-archive `BLAKE3` digest with
/// `index_locked = true` and `entries = []` (protecting encrypted filenames and
/// metadata). If `password` is provided (or the archive is unencrypted), also
/// returns full entry listing and [`CompressionStats`].
///
/// # Errors
///
/// Returns [`ZarcError`] if the container structure or whole-archive BLAKE3 is invalid,
/// or if a provided password fails authentication.
pub fn inspect_archive(
    raw: &[u8],
    password: Option<Vec<u8>>,
    limits: &Limits,
) -> Result<ZarcInspection, ZarcError> {
    let header = Header::decode(raw, limits, Some(raw.len() as u64))?;
    if header.format_id() != FormatId::ZARC {
        return Err(ZarcError::NotZarcFormat(header.format_id().raw()));
    }

    let mut warnings = Vec::new();
    if header.version().minor > 0 {
        warnings.push(format!(
            "archive uses newer minor version {}.{} (forward-compatible read)",
            header.version().major,
            header.version().minor
        ));
    }
    if header.flags().non_critical_advisory_bits() != 0 {
        warnings.push(format!(
            "archive has unknown advisory flags: {:#018x}",
            header.flags().non_critical_advisory_bits()
        ));
    }

    let meta_start = header.header_len() as usize;
    let payload_start = header.payload_offset() as usize;
    let payload_end = (header.payload_offset() + header.payload_len()) as usize;

    let mut kdf_params = None;
    if header.flags().has_metadata() {
        let mut r = TlvReader::new(&raw[meta_start..payload_start], *limits);
        let mut saw_end = false;
        while let Some(tlv) = r.next_tlv()? {
            if tlv.is_end() {
                saw_end = true;
                break;
            }
            match tlv.ty {
                TLV_KDF_PARAMS => kdf_params = Some(KdfParams::decode(tlv.value)?),
                TLV_COMMENT => {
                    let _ = std::str::from_utf8(tlv.value).map_err(|_| {
                        ZarcError::MalformedArchive("invalid UTF-8 in comment TLV".into())
                    })?;
                }
                other if is_critical_extension_type(other) => {
                    return Err(ZarcError::Core(
                        znf_core::Error::UnsupportedCriticalExtension(other),
                    ));
                }
                other => {
                    warnings.push(format!(
                        "ignored unknown non-critical metadata TLV {other:#06x}"
                    ));
                }
            }
        }
        if !saw_end {
            return Err(ZarcError::MalformedArchive(
                "metadata TLV section missing TLV_END marker".into(),
            ));
        }
    }

    let footer_slice = &raw[payload_end..];
    let mut f_reader = TlvReader::new(footer_slice, *limits);
    let mut archive_blake3 = None;
    let mut archive_blake3_verified = false;
    let mut has_parity_stripe = false;
    let mut saw_footer_end = false;

    while let Some(tlv) = f_reader.next_tlv()? {
        if tlv.is_end() {
            saw_footer_end = true;
            break;
        }
        match tlv.ty {
            TLV_ARCHIVE_BLAKE3 => {
                if tlv.value.len() != HASH_LEN {
                    return Err(ZarcError::MalformedArchive(
                        "invalid BLAKE3 digest length in footer".into(),
                    ));
                }
                let mut b = [0u8; HASH_LEN];
                b.copy_from_slice(tlv.value);
                let h = Hash::from_bytes(b);
                h.verify(&raw[..payload_end])?;
                archive_blake3 = Some(h);
                archive_blake3_verified = true;
            }
            TLV_PARITY_STRIPE => {
                let _ = ParityStripe::decode(tlv.value)?;
                has_parity_stripe = true;
            }
            TLV_ZARC_INDEX | TLV_ZARC_ENCRYPTED_INDEX | TLV_ZARC_ENCRYPTED_METADATA => {}
            other if is_critical_extension_type(other) => {
                return Err(ZarcError::Core(
                    znf_core::Error::UnsupportedCriticalExtension(other),
                ));
            }
            other => {
                warnings.push(format!(
                    "ignored unknown non-critical footer TLV {other:#06x}"
                ));
            }
        }
    }
    if !saw_footer_end {
        return Err(ZarcError::MalformedArchive(
            "footer TLV section missing TLV_END marker".into(),
        ));
    }

    // If encrypted and no password provided, return locked summary without exposing index.
    if header.flags().is_encrypted() && password.is_none() {
        return Ok(ZarcInspection {
            file_size: raw.len() as u64,
            version: (header.version().major, header.version().minor),
            flags: header.flags(),
            header_compression: header.compression(),
            header_encryption: header.encryption(),
            payload_offset: header.payload_offset(),
            payload_len: header.payload_len(),
            index_locked: true,
            archive_blake3,
            archive_blake3_verified,
            has_parity_stripe,
            kdf_params,
            comment: None,
            stats: None,
            entries: Vec::new(),
            warnings,
        });
    }

    let arch = ZarcArchive::open(
        raw,
        ReadOptions {
            password,
            limits: *limits,
            ..ReadOptions::default()
        },
    )?;

    Ok(ZarcInspection {
        file_size: raw.len() as u64,
        version: (header.version().major, header.version().minor),
        flags: header.flags(),
        header_compression: header.compression(),
        header_encryption: header.encryption(),
        payload_offset: header.payload_offset(),
        payload_len: header.payload_len(),
        index_locked: false,
        archive_blake3,
        archive_blake3_verified,
        has_parity_stripe,
        kdf_params,
        comment: arch.comment().map(str::to_string),
        stats: Some(arch.compression_stats()),
        entries: arch.entries().to_vec(),
        warnings,
    })
}

/// Add one or more filesystem paths to an existing `.zarc` archive atomically.
///
/// Opens and verifies the existing archive, preserves all existing entries,
/// compression settings, comment, parity setting, KDF parameters, and unknown
/// metadata extensions, appends the new paths, and atomically replaces `archive_path`.
///
/// # Errors
///
/// Returns [`ZarcError`] if the existing archive is invalid, a duplicate path is
/// added, or I/O fails.
pub fn add_paths_to_archive_file(
    archive_path: &Path,
    new_inputs: &[&Path],
    password: Option<Vec<u8>>,
) -> Result<usize, ZarcError> {
    let raw = fs::read(archive_path)?;
    let arch = ZarcArchive::open(
        &raw,
        ReadOptions {
            password: password.clone(),
            ..ReadOptions::default()
        },
    )?;

    let opts = WriteOptions {
        compression: CompConfig {
            algorithm: arch.header().compression().to_algorithm(),
            zstd_level: 3,
            max_expanded_len: arch.options.limits.max_expanded_len,
        },
        password,
        kdf_params: arch.kdf_params().cloned(),
        comment: arch.comment().map(str::to_string),
        include_parity: arch.parity_stripe().is_some(),
        overwrite: true,
        ..WriteOptions::default()
    };

    let mut writer = ZarcWriter::new(opts);
    for (ty, val) in arch.preserved_metadata_extensions() {
        writer.add_metadata_extension(*ty, val.clone());
    }

    // Re-add existing entries with their exact compression, permissions, mtime, and user metadata.
    for existing in arch.entries() {
        match existing.kind {
            EntryKind::Directory => {
                writer.add_directory(
                    &existing.path,
                    existing.unix_mode,
                    existing.mtime_unix_secs,
                )?;
            }
            EntryKind::File => {
                let data = arch.read_entry_bytes(existing)?;
                writer.add_bytes_with_options(
                    &existing.path,
                    &data,
                    existing.unix_mode,
                    existing.mtime_unix_secs,
                    Some(CompConfig {
                        algorithm: existing.compression,
                        zstd_level: 3,
                        max_expanded_len: arch.options.limits.max_expanded_len,
                    }),
                    existing.user_metadata.clone(),
                )?;
            }
        }
    }

    for &input in new_inputs {
        let base = input.parent().unwrap_or_else(|| Path::new(""));
        writer.add_path(base, input)?;
    }

    let final_count = writer.pending.len();
    writer.finish_to_path(archive_path, None, None)?;
    Ok(final_count)
}

/// Remove one or more canonical entry paths (or directory subtrees) from an
/// existing `.zarc` archive atomically.
///
/// # Errors
///
/// Returns [`ZarcError::EntryNotFound`] if none of the specified paths exist in the archive.
pub fn remove_entries_from_archive_file(
    archive_path: &Path,
    paths_to_remove: &[String],
    password: Option<Vec<u8>>,
) -> Result<usize, ZarcError> {
    let raw = fs::read(archive_path)?;
    let arch = ZarcArchive::open(
        &raw,
        ReadOptions {
            password: password.clone(),
            ..ReadOptions::default()
        },
    )?;

    let mut canonical_remove = Vec::with_capacity(paths_to_remove.len());
    for p in paths_to_remove {
        canonical_remove.push(validate_archive_path(p)?);
    }

    let opts = WriteOptions {
        compression: CompConfig {
            algorithm: arch.header().compression().to_algorithm(),
            zstd_level: 3,
            max_expanded_len: arch.options.limits.max_expanded_len,
        },
        password,
        kdf_params: arch.kdf_params().cloned(),
        comment: arch.comment().map(str::to_string),
        include_parity: arch.parity_stripe().is_some(),
        overwrite: true,
        ..WriteOptions::default()
    };

    let mut writer = ZarcWriter::new(opts);
    for (ty, val) in arch.preserved_metadata_extensions() {
        writer.add_metadata_extension(*ty, val.clone());
    }

    let mut removed_count = 0usize;
    for existing in arch.entries() {
        if entry_matches_selection(&existing.path, Some(&canonical_remove)) {
            removed_count += 1;
            continue;
        }
        match existing.kind {
            EntryKind::Directory => {
                writer.add_directory(
                    &existing.path,
                    existing.unix_mode,
                    existing.mtime_unix_secs,
                )?;
            }
            EntryKind::File => {
                let data = arch.read_entry_bytes(existing)?;
                writer.add_bytes_with_options(
                    &existing.path,
                    &data,
                    existing.unix_mode,
                    existing.mtime_unix_secs,
                    Some(CompConfig {
                        algorithm: existing.compression,
                        zstd_level: 3,
                        max_expanded_len: arch.options.limits.max_expanded_len,
                    }),
                    existing.user_metadata.clone(),
                )?;
            }
        }
    }

    if removed_count == 0 {
        return Err(ZarcError::EntryNotFound(canonical_remove.join(", ")));
    }

    writer.finish_to_path(archive_path, None, None)?;
    Ok(removed_count)
}

fn ensure_no_symlink_ancestors(root: &Path, target: &Path) -> Result<(), ZarcError> {
    let rel = target.strip_prefix(root).unwrap_or(target);
    let mut cur = root.to_path_buf();
    for comp in rel.components() {
        cur.push(comp);
        if let Ok(meta) = fs::symlink_metadata(&cur) {
            if meta.file_type().is_symlink() {
                return Err(ZarcError::SymlinkNotAllowed(format!(
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
