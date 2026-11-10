# ZARC (.zarc) Architecture

This document describes the internal architecture of the ZARC archive engine
(`crates/znf-zarc`), the crate responsible for creating, reading, verifying,
and extracting `.zarc` containers built on the ZNF Core v1.0 binary format.

## 1. Module Layout

| Module | Responsibility |
|---|---|
| `archive.rs` | `ZarcArchive` reader/verifier/extractor, `ZarcWriter` builder, `add_paths_to_archive_file`, `remove_entries_from_archive_file`, `inspect_archive`, `diagnose_entries`, `extract_verified_entries`, `attempt_parity_repair` |
| `entry.rs` | `EntryRecord` serialization/deserialization (98-byte fixed prefix + path), `encode_index` / `decode_index`, entry-level flags (`ENTRY_FLAG_ENCRYPTED`, `ENTRY_FLAG_HAS_USER_METADATA`), `file_name()`, `depth()`, `is_encrypted()` |
| `error.rs` | `ZarcError` enum with classification helpers (`is_unsupported`, `is_bomb`, etc.) |
| `path.rs` | `validate_archive_path`, `validate_archive_path_with_depth`, `normalize_fs_path`, `safe_join_with_depth`, path traversal / symlink / UNC / device-name rejection |
| `lib.rs` | Public re-exports, rustdoc doctest example |

## 2. Core Data Types

### `ZarcWriter`

Builds a `.zarc` archive incrementally. Supports:

- `add_bytes(path, data, mode, mtime, compression, user_metadata)` — in-memory entries
- `add_path(base_dir, fs_path)` — filesystem entries (symlinks rejected)
- `add_directory(path, mode, mtime)` — directory entries
- `finish(buf)` / `finish_to_path(path, progress, cancel)` — atomic finalization

### `ZarcArchive`

Parsed, validated in-memory representation of an opened `.zarc` file. Fields:

- `header` — parsed 64-byte ZNF Core header (`FormatId::ZARC`, version 1.0)
- `entries` — `Vec<EntryRecord>` decoded from the footer index TLV
- `archive_blake3` — whole-archive BLAKE3 digest from footer TLV `0x0102`
- `comment`, `kdf_params`, `derived_key` — decrypted metadata (encrypted archives only)
- `preserved_meta_extensions` — non-critical unknown metadata TLVs retained verbatim

### `EntryRecord`

98-byte fixed prefix followed by a variable-length UTF-8 path:

| Field | Size | Description |
|---|---|---|
| `entry_kind` | 1 byte | `0` = File, `1` = Directory |
| `compression` | 1 byte | `0` = Store, `1` = Zstd, `2` = LZ4 |
| `flags` | 2 bytes | Entry-level flags |
| `unix_mode` | 4 bytes | POSIX permissions (`& 0o777`) |
| `mtime_unix_secs` | 8 bytes | Unix timestamp |
| `uncompressed_size` | 8 bytes | Original byte size |
| `stored_size` | 8 bytes | Stored (compressed/encrypted) byte size |
| `payload_rel_offset` | 8 bytes | Offset relative to `header.payload_offset()` |
| `blake3_hash` | 32 bytes | BLAKE3 of uncompressed content |
| `entry_nonce` | 24 bytes | Per-entry XChaCha20-Poly1305 nonce (`0` if unencrypted) |
| `path_len` | 2 bytes | UTF-8 path byte length |
| `path` | `path_len` bytes | Canonical relative path |

## 3. Write Path

1. `ZarcWriter::new(opts)` initializes with compression, password, KDF params, comment, overwrite flag, and parity inclusion.
2. Entries are added via `add_bytes` / `add_path` / `add_directory`. Each entry's path is validated by `validate_archive_path`. Symlinks are refused with `ZarcError::SymlinkNotAllowed`.
3. On `finish(buf)` / `finish_to_path`:
   - The metadata TLV section is built (`TLV_KDF_PARAMS`, optional `TLV_COMMENT` or `TLV_ZARC_ENCRYPTED_METADATA`).
   - Each entry's payload is compressed (Store / Zstd / LZ4), optionally encrypted with `XChaCha20-Poly1305` using a fresh 24-byte nonce.
   - The entry index is encoded, optionally encrypted as `TLV_ZARC_ENCRYPTED_INDEX`.
   - The archive-level BLAKE3 digest is computed over `header || metadata || payload`.
   - Optional parity stripe (`TLV_PARITY_STRIPE`) is appended.
   - For `finish_to_path`, content is written to a temp file then atomically renamed.

## 4. Read Path

1. `ZarcArchive::open(raw, opts)`:
   - Decodes and validates the 64-byte ZNF Core header (magic, `FormatId::ZARC`, CRC-32, reserved bits, flag/compression/encryption consistency).
   - Parses the metadata TLV section (if `HAS_METADATA` flag set), rejecting unknown critical extension types.
   - Derives the decryption key from password + KDF params if `ENCRYPTED` flag set.
   - Reads the footer TLV section, decrypting `TLV_ZARC_ENCRYPTED_INDEX` if needed.
   - Decodes and validates each `EntryRecord` (bounds check, compression ratio check ≤ 64 KiB threshold).
   - **New:** rejects overlapping entry stored ranges with `ZarcError::MalformedArchive`.
2. `verify_all()` recomputes per-entry BLAKE3 hashes and the whole-archive BLAKE3 digest.

## 5. Extraction Path

1. `extract_to(dest)` / `extract_with_options(dest, opts, progress, cancel)`:
   - Validates each entry path via `safe_join_with_depth` (canonical, depth-limited).
   - `ensure_no_symlink_ancestors` checks every path component under `dest` via `symlink_metadata`, refusing symlinked directories.
   - Existing symlinks at the target path are refused with `ZarcError::SymlinkNotAllowed`.
   - Without `overwrite: true`, existing target files trigger `ZarcError::TargetAlreadyExists`.
   - Decrypts + decompresses each entry, streaming output with BLAKE3 verification.
   - POSIX modes are masked to `0o777` (setuid/setgid/stripped bits removed).

## 6. Modification Operations

- `add_paths_to_archive_file(path, inputs, password)` — appends entries to an existing `.zarc` by rewriting the archive with new entries included.
- `remove_entries_from_archive_file(path, paths, password)` — removes matching entries and rewrites the archive.
- Both operations require the archive password if encrypted, and rewrite the footer (index, BLAKE3, parity) atomically.

## 7. Concurrency & Cancellation

- `ReadOptions` / `WriteOptions` accept an optional `&AtomicBool` cancellation flag.
- `finish_to_path` checks the flag before writing the output file; if cancelled, no temp file is left behind.
- Extraction checks the flag per entry and aborts with `ZarcError::Cancelled`.
- No shared mutable state across threads; archives are not thread-safe by default but `&ZarcArchive` is `Sync` for read-only inspection.

## 8. Safety Guarantees

- `#![forbid(unsafe_code)]` across the entire `znf-zarc` crate.
- No `serde`; all binary encoding uses explicit little-endian `to_le_bytes` / `from_le_bytes`.
- All external byte input is bounds-checked before indexing; no `.unwrap()` on untrusted data.
- Integer overflow is checked via `checked_add` / `checked_mul` everywhere.
- `Limits` struct caps path length (4 KiB), component length (255 bytes), depth (64), metadata size, TLV size, entry count, and expanded size.