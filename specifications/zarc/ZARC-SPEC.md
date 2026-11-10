# ZARC (`.zarc`) Container Format Specification (Version 1.0)

- **Status:** Implemented (`crates/znf-zarc`, `apps/znf-cli`)
- **Format ID:** `0x0000_0001` (`FormatId::ZARC`)
- **Core Specification:** ZNF Core v1.0 (`specifications/core/ZNF-CORE-SPEC.md`)
- **File Extension:** `.zarc`

---

## 1. Overview

ZARC is a lossless, cross-platform archive container built on the ZNF Core binary foundation. It packages files and directory hierarchies with:

- **Lossless Compression:** Stored (`0`), Zstandard (`1`), or LZ4 block framing (`2`).
- **Optional Authenticated Encryption:** `XChaCha20-Poly1305` (256-bit key, 192-bit nonce, 128-bit tag) with `Argon2id` v19 password key derivation, encrypting **both** file contents and the entry index (hiding filenames, sizes, and directory structure).
- **Cryptographic Integrity:** Per-entry `BLAKE3` hashes over uncompressed content plus a whole-archive `BLAKE3` digest over `header || metadata || payload`.
- **Optional Error Recovery:** Block-level XOR parity (`ParityStripe`) in the footer capable of repairing single-block payload corruption.

---

## 2. Container Section Layout

```text
Offset 0
+===================================================================+
| 1. ZNF Core Fixed Header (64 bytes, FormatId = 1, Version = 1.0)  |
+===================================================================+
| 2. Metadata TLV Section (optional; present if HAS_METADATA set)   |
|    - TLV_KDF_PARAMS (0x0010): 28 bytes (required if ENCRYPTED)    |
|    - TLV_COMMENT    (0x0020): UTF-8 string (optional)             |
|    - TLV_END        (0xFFFF): 0 bytes                             |
+===================================================================+
| 3. Payload Section (offset = payload_offset, len = payload_len)   |
|    Concatenated entry data streams (compressed, and if ENCRYPTED, |
|    authenticated with XChaCha20-Poly1305 + 16-byte Poly1305 tag). |
+===================================================================+
| 4. Footer TLV Section (required; HAS_FOOTER is always set)        |
|    - TLV_ZARC_INDEX (0x0100) OR TLV_ZARC_ENCRYPTED_INDEX (0x0101) |
|    - TLV_ARCHIVE_BLAKE3 (0x0102): 32-byte BLAKE3 digest           |
|    - TLV_PARITY_STRIPE  (0x0103): optional recovery stripe        |
|    - TLV_END            (0xFFFF): 0 bytes                         |
+===================================================================+
```

---

## 3. Metadata Section TLVs

| Type | Name | Length | Value Encoding |
|---|---|---|---|
| `0x0010` | `TLV_KDF_PARAMS` | `28` | `m_cost_kib: u32 LE` (`8192..=1048576`), `t_cost: u32 LE` (`1..=32`), `p_cost: u32 LE` (`1..=64`), `salt: [u8; 16]` |
| `0x0020` | `TLV_COMMENT` | `N` | Valid UTF-8 string (no NUL requirement) |

---

## 4. Entry Index Table & `EntryRecord` Layout

The index table begins with `entry_count: u32 (LE)` followed by `entry_count` consecutive `EntryRecord` items.

Each `EntryRecord` has a 98-byte fixed prefix followed by `path_len` UTF-8 bytes:

| Offset | Size | Type | Field | Description |
|---:|---:|---|---|---|
| `0` | `1` | `u8` | `entry_kind` | `0` = Regular File, `1` = Directory |
| `1` | `1` | `u8` | `compression` | `0` = Store, `1` = Zstd, `2` = LZ4 |
| `2` | `2` | `u16` (LE) | `flags` | Reserved (`0` in v1.0) |
| `4` | `4` | `u32` (LE) | `unix_mode` | POSIX permissions masked to `0o777` (or `0`) |
| `8` | `8` | `i64` (LE) | `mtime_unix_secs` | UTC modification timestamp (seconds since 1970-01-01) |
| `16` | `8` | `u64` (LE) | `uncompressed_size` | Original byte size (`0` for directories) |
| `24` | `8` | `u64` (LE) | `stored_size` | Byte size in Payload Section (`0` for directories) |
| `32` | `8` | `u64` (LE) | `payload_rel_offset` | Offset relative to `header.payload_offset()` |
| `40` | `32` | `[u8; 32]` | `blake3_hash` | BLAKE3 digest of original uncompressed file bytes |
| `72` | `24` | `[u8; 24]` | `entry_nonce` | Per-entry `XChaCha20-Poly1305` nonce (`0` if unencrypted) |
| `96` | `2` | `u16` (LE) | `path_len` | Byte length of canonical UTF-8 path |
| `98` | `path_len` | `[u8; path_len]` | `path` | Canonical relative path (`a/b/c.txt`) |

### Canonical Path Rules

Every `path` in an `EntryRecord` **must** obey:
- Valid UTF-8, `1 <= path_len <= 4096`.
- Forward-slash (`/`) separator only; backslashes (`\`), NUL bytes, and ASCII control characters (`< 0x20`, `0x7F`) are forbidden.
- Relative only: no leading `/`, no Windows drive prefixes (`C:`), and no `.` or `..` segments.
- No Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`..`COM9`, `LPT1`..`LPT9`).
- Duplicate paths within the same archive are rejected with `ZarcError::DuplicateEntry`.

---

## 5. Compression Framing

1. **Store (`0`):** Raw uncompressed file bytes.
2. **Zstandard (`1`):** Standard RFC 8878 Zstandard frame (`zstd` crate, levels `1..=22`, default `3`).
3. **LZ4 (`2`):** Bounded 64 KiB block framing (`lz4_flex` safe block codec):
   - Sequence of blocks: `uncompressed_block_len: u32 LE` (`1..=65536`) || `compressed_block_len: u32 LE` || `compressed_bytes`.
   - Terminated by `0u32 LE`.

---

## 6. Authenticated Encryption (`ENCRYPTED` Flag)

When `Flags::ENCRYPTED` is set:

1. **Key Derivation:** A 256-bit key is derived from the user password and `TLV_KDF_PARAMS` using `Argon2id` v19 (`m_cost_kib`, `t_cost`, `p_cost`, 16-byte random OS salt).
2. **Associated Data (AAD):** All `XChaCha20-Poly1305` operations bind the exact 64-byte ZNF Core header (`bytes 0..64`) as AAD. Any modification to the header causes AEAD decryption to fail with `CryptoError::AuthenticationFailed`.
3. **Per-Entry Encryption:** Each file's compressed payload is encrypted with a fresh 24-byte random OS nonce stored in `entry_nonce`.
4. **Encrypted Index (`TLV_ZARC_ENCRYPTED_INDEX = 0x0101`):** The index table is encrypted with its own fresh 24-byte random OS nonce: `nonce (24B) || ciphertext || tag (16B)`. Unencrypted `TLV_ZARC_INDEX` is rejected in encrypted archives.

---

## 7. Footer Section TLVs

| Type | Name | Description |
|---|---|---|
| `0x0100` | `TLV_ZARC_INDEX` | Unencrypted index table (forbidden when `ENCRYPTED` is set) |
| `0x0101` | `TLV_ZARC_ENCRYPTED_INDEX` | `24B nonce || XChaCha20-Poly1305(index, aad=header[0..64])` |
| `0x0102` | `TLV_ARCHIVE_BLAKE3` | 32-byte BLAKE3 digest over `file[0 .. payload_offset + payload_len]` |
| `0x0103` | `TLV_PARITY_STRIPE` | Optional `znf-recovery` XOR parity stripe over the Payload Section |

---

## 8. Encrypted Metadata TLVs

| Type | Name | Description |
|---|---|---|
| `0x0200` | `TLV_ZARC_ENCRYPTED_METADATA` | Encrypted comment / user metadata (`24B nonce || XChaCha20-Poly1305(plaintext, aad=header[0..64])`) |

When `Flags::ENCRYPTED` is set, `TLV_COMMENT` must not appear in the metadata section; instead, comment and other sensitive metadata are placed in `TLV_ZARC_ENCRYPTED_METADATA`.

---

## 9. Entry-Level Flags

| Bit | Name | Value | Description |
|---:|---|---:|---|
| `0` | `ENTRY_FLAG_ENCRYPTED` | `1 << 0` | Entry payload is encrypted |
| `1` | `ENTRY_FLAG_HAS_USER_METADATA` | `1 << 1` | Entry has user-defined key-value metadata |

---

## 10. Error Handling

All public API functions return `Result<T, ZarcError>`. Key error variants:

| Variant | Meaning |
|---|---|
| `ZarcError::NotZarcFormat(id)` | File has a valid ZNF header but wrong `FormatId` |
| `ZarcError::MalformedArchive(msg)` | Archive structure violates the specification |
| `ZarcError::DuplicateEntry(path)` | Two entries share the same canonical path |
| `ZarcError::CaseInsensitiveCollision { first, second }` | Paths collide case-insensitively |
| `ZarcError::EntryNotFound(path)` | Requested entry does not exist |
| `ZarcError::TargetAlreadyExists(path)` | Output file already exists, `overwrite` not set |
| `ZarcError::SourceFileChanged(path)` | Source file mutated during archiving |
| `ZarcError::UnsupportedFsEntry(msg)` | Symlink/device file where disallowed |
| `ZarcError::SymlinkNotAllowed(msg)` | Symlink explicitly encountered and refused |
| `ZarcError::ResourceLimitExceeded(msg)` | Bomb-protection limit exceeded |
| `ZarcError::Cancelled` | Operation aborted by caller via cancellation token |

---

## 11. Public API Reference

| Function/Method | Description |
|---|---|
| `ZarcWriter::new(opts)` | Create a new archive writer |
| `writer.add_bytes(path, data, mode, mtime)` | Add an in-memory file entry |
| `writer.add_path(base_dir, fs_path)` | Add a file from the filesystem |
| `writer.finish(buf)` | Finalize archive into a `Vec<u8>` |
| `writer.finish_to_path(path, progress, cancel)` | Atomically write archive to filesystem |
| `ZarcArchive::open(raw, opts)` | Open and validate a `.zarc` archive |
| `arch.verify_all()` | Verify all entry hashes and archive BLAKE3 |
| `arch.extract_to(dest)` | Extract all entries to a directory |
| `arch.extract_with_options(dest, opts, progress, cancel)` | Extract with fine-grained control |
| `arch.find_entry(path)` | Look up an entry by canonical path |
| `arch.diagnose_entries()` | Per-entry integrity diagnosis |
| `arch.extract_verified_entries(dest, opts)` | Extract only verified-intact entries |
| `inspect_archive(raw, password, limits)` | Read metadata without full validation |
| `add_paths_to_archive_file(path, inputs, password)` | Add files to an existing `.zarc` |
| `remove_entries_from_archive_file(path, paths, password)` | Remove entries from an existing `.zarc` |

---

## 12. Compliance & Conformance

Implementations of this specification must:

- Reject headers with unknown critical feature flags (`ZnfError::InvalidFlags`)
- Reject archives with unsupported `FormatId` values
- Validate all entry paths against canonical path rules before extraction
- Refuse to archive or extract symlinks by default
- Enforce `max_expanded_len` and `max_compression_ratio` resource limits
- Verify per-entry BLAKE3 hashes on `verify_all()`
- Verify whole-archive BLAKE3 digest on `verify_all()`
- Use atomic temp-file + rename for `finish_to_path` to prevent partial writes
