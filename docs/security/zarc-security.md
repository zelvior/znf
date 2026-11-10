# ZARC (.zarc) Security Architecture

This document details the security properties, threat model, and hardening
mechanisms of the ZARC archive engine (`crates/znf-zarc`).

## 1. Threat Model

All `.zarc` inputs are treated as **untrusted and potentially adversarial**.
An attacker may craft a `.zarc` file to attempt:

1. **Path Traversal / Arbitrary File Write ("Zip Slip")** — Writing outside the
   extraction directory via `../`, leading `/`, Windows drive letters (`C:`),
   backslashes (`\`), reserved device names (`CON`, `NUL`, `COM1`), or symlink
   chains.
2. **Decompression Bombs / Memory Exhaustion** — Declaring huge
   `uncompressed_size`, `entry_count = u32::MAX`, oversized TLV lengths, or
   extreme compression ratios to exhaust RAM or disk.
3. **KDF Resource Exhaustion (DoS)** — Specifying extreme `Argon2id` parameters
   (e.g., `m_cost_kib = 4 GiB`, `t_cost = 10000`) in an unauthenticated header
   TLV.
4. **Ciphertext / Header Tampering** — Modifying header version/flags, swapping
   encrypted entries, truncating the footer index, or flipping payload bits.
5. **Parser Panics / Integer Overflows** — Out-of-bounds slice indexing or
   `u64`/`usize` arithmetic wraparound from malicious field values.
6. **Case-Insensitive Collisions** — Two paths that differ only by case
   (`File.txt` vs `file.txt`) causing silent overwrites on case-insensitive
   filesystems.

## 2. Cryptographic Guarantees

| Property | Mechanism |
|---|---|
| Confidentiality | `XChaCha20-Poly1305` (256-bit key, 192-bit nonce, 128-bit tag) |
| Authenticity | AEAD tag verification before any plaintext release |
| Key derivation | `Argon2id` v19 with bounded parameters |
| Per-entry integrity | BLAKE3 over uncompressed content, stored in `EntryRecord` |
| Whole-archive integrity | BLAKE3 over `header || metadata || payload`, stored in footer |
| Header binding | 64-byte ZNF Core header bound as AAD to every AEAD operation |
| Index confidentiality | `TLV_ZARC_ENCRYPTED_INDEX` hides filenames, sizes, hashes |
| Metadata confidentiality | `TLV_ZARC_ENCRYPTED_METADATA` hides comments/user metadata |
| Key zeroization | `SecretKey` zeroizes on drop via `zeroize::Zeroize` |

**No custom cryptography:** All primitives come from audited RustCrypto crates
(`chacha20poly1305`, `argon2`, `blake3`) and OS CSPRNG (`getrandom`).

## 3. KDF Parameter Bounds

`KdfParams::validate()` enforces before running `Argon2id`:

| Parameter | Min | Max |
|---|---|---|
| `m_cost_kib` | 8 MiB | 1 GiB |
| `t_cost` | 1 | 32 |
| `p_cost` | 1 | 64 |

## 4. Extraction & Parser Hardening

### Canonical Path Validation (`znf_zarc::path`)

Rejects:

- Empty paths
- Paths > 4096 bytes
- NUL / ASCII control bytes (`< 0x20`, `0x7F`)
- Leading `/` or `\` (absolute paths)
- Any `\` separator
- Windows drive letters (`C:`, `D:`, etc.)
- `..` segments (parent traversal)
- Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`,
  `LPT1`–`LPT9`)
- Components ending in a space or dot

`.` components and empty segments are stripped (normalized), so `a/./b` and
`a//b` both canonicalize to `a/b`.

### Symlink Refusal

- `ZarcWriter::add_path` refuses to archive symlinks with
  `ZarcError::SymlinkNotAllowed`.
- `ZarcArchive::extract_to` checks every ancestor component under the
  destination directory via `symlink_metadata` (`ensure_no_symlink_ancestors`)
  and refuses to traverse or overwrite symlinks.
- Existing symlinks at the target extraction path are refused with
  `ZarcError::SymlinkNotAllowed`.
- Extracted POSIX permissions are masked to `0o777` (setuid/setgid/sticky bits
  removed).

### Bomb & Allocation Defenses

- `decode_index` verifies `entry_count <= (buf.len() - 4) / 98` before
  allocating `Vec::with_capacity(count)`.
- Per-entry and cumulative archive uncompressed sizes are checked against
  `Limits::max_expanded_len`.
- Entries > 64 KiB exceeding `ReadOptions::max_compression_ratio` (default
  `1000:1`) are rejected prior to decompression.
- Streaming decompression stops immediately if output exceeds the entry's
  declared `uncompressed_size` or `max_expanded_len`.
- Suspicious compression ratio check threshold: **64 KiB** uncompressed size.

### Structural Validation on `open()`

- Header magic, `FormatId::ZARC`, CRC-32, reserved flag bits, and
  flag/compression/encryption consistency are validated.
- Unknown critical extension types in metadata are rejected.
- Each entry's stored range is bounds-checked against `payload_len`.
- **Overlapping entry stored ranges** are rejected with
  `ZarcError::MalformedArchive`.
- Duplicate entry paths are rejected with `ZarcError::DuplicateEntry`.

## 5. Error Classification

`ZarcError` provides classification helpers:

- `is_unsupported()` — true for unsupported formats, critical extensions, or
  features the implementation does not support.
- `is_bomb()` — true for resource-limit-exceeded errors (decompression bombs,
  excessive entry counts, oversized metadata).
- `is_corruption()` — true for integrity failures (BLAKE3 mismatch, CRC-32
  failure, AEAD authentication failure).

## 6. Atomic Writes

`finish_to_path` writes to a temp file in the same directory, then atomically
renames it to the target path. This prevents:

- Partial archives from being visible if the process crashes mid-write.
- Concurrent readers from observing a torn archive.
- The `overwrite` flag from being bypassed via a race condition.

## 7. Residual Risks

- **Encrypted archives without a password:** The index and metadata are
  encrypted, but the archive structure (header, payload offsets, footer TLV
  types) is visible. File count and approximate sizes may be inferred.
- **Case-insensitive filesystems:** Extracted files may collide on
  case-insensitive filesystems even when archive paths are distinct. Use
  `ExtractOptions` with case-collision detection or extract to a
  case-sensitive filesystem.
- **Side channels:** Compressed size leaks information about plaintext content
  (classic compression side channel). No padding is applied.