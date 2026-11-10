# ZNF & ZARC Threat Model and Security Architecture

## 1. Threat Model

ZNF and `.zarc` parsers are designed under the assumption that **all input archives are untrusted and potentially adversarial**. Specifically, an attacker may craft a `.zarc` file to attempt:

1. **Path Traversal / Arbitrary File Overwrite ("Zip Slip"):** Writing files outside the target extraction directory via `../`, leading `/`, Windows drive letters (`C:`), backslashes (`\`), reserved device names (`CON`, `NUL`, `COM1`), or symlink chains.
2. **Decompression Bombs / Memory Exhaustion:** Declaring huge `uncompressed_size`, `entry_count = u32::MAX`, oversized TLV lengths, or extreme compression ratios to exhaust RAM or disk space.
3. **KDF Resource Exhaustion (DoS):** Specifying extreme `Argon2id` parameters (e.g., `m_cost_kib = 4 GiB`, `t_cost = 10000`) in an unauthenticated header TLV.
4. **Ciphertext / Header Tampering:** Modifying header version/flags, swapping encrypted entries, or truncating the footer index.
5. **Parser Panics / Integer Overflows:** Triggering out-of-bounds slice indexing or `u64`/`usize` arithmetic wraparound.

---

## 2. Cryptographic Architecture & Assumptions

- **No Custom Cryptography:** ZNF never implements cipher, hash, or KDF primitives. It uses audited RustCrypto crates (`chacha20poly1305`, `argon2`), `blake3`, and OS CSPRNG (`getrandom`).
- **Checksums vs. Authentication:**
  - Header `CRC-32` (`znf-core`) and `BLAKE3` (`znf-integrity`) detect accidental corruption in unencrypted archives.
  - Only `XChaCha20-Poly1305` (`znf-crypto`) provides cryptographic authenticity and confidentiality against an active attacker.
- **Header AAD Binding:** Every `XChaCha20-Poly1305` encryption in `.zarc` binds the 64-byte ZNF Core header (`bytes 0..64`) as Associated Data (AAD). Even if an attacker modifies header fields and recomputes the header CRC-32, AEAD decryption fails before any plaintext is released.
- **Index Confidentiality:** In encrypted `.zarc` archives, the entry index (`TLV_ZARC_ENCRYPTED_INDEX`) is encrypted with its own 192-bit random nonce so filenames, directory layout, file sizes, and hashes are not leaked in cleartext.
- **KDF Parameter Bounds:** `KdfParams::validate()` enforces `8 MiB <= m_cost <= 1 GiB`, `1 <= t_cost <= 32`, and `1 <= p_cost <= 64` before running `Argon2id`.
- **Key Zeroization:** `SecretKey` zeroizes its 32-byte key buffer on drop via `zeroize::Zeroize`.

---

## 3. Extraction & Parser Hardening

- **Canonical Path Validation (`znf_zarc::path`):**
  - Rejects empty paths, paths `> 4096` bytes, NUL/control bytes, leading `/` or `\`, any `\` separator, Windows drive letters (`C:`), any `..` segment, and Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1..9`, `LPT1..9`).
  - Validated both when decoding the index and when joining paths onto the extraction root (`safe_join`).
- **Symlink Refusal:**
  - `ZarcWriter::add_path` refuses to archive symlinks by default.
  - `ZarcArchive::extract_to` checks every ancestor component under the destination directory via `symlink_metadata` and refuses to traverse or overwrite symlinks.
  - Extracted POSIX permissions mask off setuid/setgid/sticky bits (`mode & 0o777`).
- **Bomb & Allocation Defenses:**
  - `decode_index` verifies `entry_count <= (buf.len() - 4) / 98` before allocating `Vec::with_capacity(count)`.
  - Per-entry and cumulative archive uncompressed sizes are checked against `Limits::max_expanded_len`.
  - Entries `> 1 MiB` exceeding `ReadOptions::max_compression_ratio` (default `1000:1`) are rejected prior to decompression.
  - Streaming decompression stops immediately if output exceeds the entry's declared `uncompressed_size` or `max_expanded_len`.
