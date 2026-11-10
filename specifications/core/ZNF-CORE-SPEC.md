# ZNF Core Binary Format Specification (Version 1.0)

- **Status:** Implemented (`crates/znf-core`)
- **Specification Version:** `1.0`
- **Byte Order:** Explicit Little-Endian (`LE`) for all multi-byte integer fields

---

## 1. Design Principles

1. **Explicit Wire Layout:** Native in-memory struct layouts (`repr(C)` or `repr(Rust)`) are **never** written directly to disk or network streams. Every field is encoded and decoded at explicit byte offsets in little-endian order.
2. **Deterministic Output:** Given identical inputs and explicit parameters, encoding produces byte-for-byte identical headers, metadata maps (`BTreeMap` lexicographical UTF-8 key order), and Type-Length-Value (TLV) sequences across all CPU architectures and operating systems.
3. **Bounded Parsing:** Every offset and length field is validated against caller-configured [`Limits`](../../crates/znf-core/src/limits.rs) and checked for integer overflow before memory allocation or slice indexing.
4. **Clear Separation of Checksums vs. Authentication:** The header includes an IEEE 802.3 CRC-32 checksum to detect accidental bit rot or truncation, and sections include unkeyed `BLAKE3` digests. Checksums and unkeyed hashes are **not** cryptographic authentication; confidentiality and authenticity against active tampering are provided by `znf-crypto` (`XChaCha20-Poly1305` AEAD).

---

## 2. Fixed Header Layout (64 Bytes)

Every ZNF container begins at byte offset `0` with a 64-byte fixed header (`ZnfHeader`):

| Offset | Size (Bytes) | Type | Field Name | Description |
|---:|---:|---|---|---|
| `0` | `4` | `[u8; 4]` | `magic` | Exact ASCII bytes `0x5A 0x4E 0x46 0x00` (`"ZNF\0"`) |
| `4` | `4` | `u32` (LE) | `format_id` | Container format identifier (see Section 3) |
| `8` | `2` | `u16` (LE) | `version_major` | Breaking format version (`1` for v1.x) |
| `10` | `2` | `u16` (LE) | `version_minor` | Backward-compatible minor version (`0` for v1.0) |
| `12` | `8` | `u64` (LE) | `flags` | Bitmask of container capabilities (see Section 4) |
| `20` | `8` | `u64` (LE) | `header_len` | Total header size in bytes (`>= 64`) |
| `28` | `8` | `u64` (LE) | `payload_offset` | Byte offset from file start to payload (`>= header_len`) |
| `36` | `8` | `u64` (LE) | `payload_len` | Stored payload length in bytes (`0` if streaming pipe mode) |
| `44` | `4` | `u32` (LE) | `header_crc32` | IEEE CRC-32 computed over `header[0..44] \|\| header[48..64]` |
| `48` | `1` | `u8` | `compression_id` | `0` = None, `1` = Zstd, `2` = LZ4 (see Section 5) |
| `49` | `1` | `u8` | `encryption_id` | `0` = None, `1` = XChaCha20-Poly1305 (see Section 5) |
| `50` | `14` | `[u8; 14]` | `reserved` | Must be all-zero (`0x00` * 14) in v1.x |

### Header Validation Rules

1. **Minimum Size:** Input shorter than 64 bytes is rejected with `ZnfError::TooShort`.
2. **Magic Bytes:** Bytes `0..4` must equal `[0x5A, 0x4E, 0x46, 0x00]`; otherwise `ZnfError::InvalidMagic`.
3. **CRC-32 First:** Before trusting `header_len`, `payload_offset`, `payload_len`, or identifiers, parsers compute `crc32(header[0..44] || header[48..64])` (all 60 non-CRC header bytes) and verify it equals `header_crc32`.
4. **Version Compatibility:**
   - Readers supporting major version `1` **must** reject files where `version_major != 1` with `ZnfError::UnsupportedMajorVersion`.
   - Readers **must** accept any `version_minor` when `version_major == 1`.
5. **Flag & Identifier Consistency:**
   - Any unknown critical flag bit (`bits 5..=31`) or invalid upper flag bit (`bits 48..=63`) is rejected with `ZnfError::InvalidFlags`.
   - `compression_id != 0` requires `Flags::COMPRESSED` to be set; `encryption_id != 0` requires `Flags::ENCRYPTED` to be set.
   - `payload_offset > header_len` requires `Flags::HAS_METADATA` to be set.
6. **Reserved Bytes:** Bytes `50..64` must all be `0x00`; non-zero bytes are rejected with `ZnfError::NonZeroReserved`.
7. **Offset & Limit Checks:**
   - `64 <= header_len <= limits.max_header_len`
   - `payload_offset >= header_len` and `(payload_offset - header_len) <= limits.max_metadata_len`
   - `payload_len <= limits.max_payload_len`
   - `payload_offset.checked_add(payload_len)` must not overflow `u64` and (when total file length is known) must be `<= file_len`.

---

## 3. Format Identifier Registry

| `format_id` | Constant | Status | Description |
|---|---|---|---|
| `0x0000_0000` | `FormatId::RESERVED` | Reserved | Invalid; must always be rejected |
| `0x0000_0001` | `FormatId::ZARC` | **Implemented** | ZARC (`.zarc`) multi-entry archive container |
| `0x0000_0002` | `FormatId::CORE` | **Implemented** | Generic ZNF Core single-stream container (`.znf`) |
| `0x0000_0003..=0x7FFF_FFFF` | — | Planned / Unassigned | Reserved for future standard ZNF formats |
| `0x8000_0000..=0xFFFF_FFFE` | — | Private Use | Vendor / experimental formats |
| `0xFFFF_FFFF` | — | Reserved | Invalid; must always be rejected |

---

## 4. Header Feature Flags (`ZnfFeatureFlags`, `u64` LE)

| Bit / Range | Mask | Name | Rule |
|---:|---|---|---|
| `0` | `0x0001` | `COMPRESSED` | Payload is compressed using `compression_id` (or per-entry in ZARC) |
| `1` | `0x0002` | `ENCRYPTED` | Payload and sensitive metadata are AEAD-encrypted |
| `2` | `0x0004` | `HAS_METADATA` | Metadata TLV section exists in `header_len..payload_offset` |
| `3` | `0x0008` | `HAS_FOOTER` | Footer TLV section exists after the payload section |
| `4` | `0x0010` | `STREAMING` | Payload is framed as `znf-stream` length-prefixed chunks |
| `5..=31` | `0x0000_0000_FFFF_FFE0` | Critical Reserved | Writers set to `0`; readers **must reject** if any bit is `1` |
| `32..=47` | `0x0000_FFFF_0000_0000` | Non-Critical Advisory | Writers set to `0` by default; readers **ignore** unknown bits |
| `48..=63` | `0xFFFF_0000_0000_0000` | Invalid Must-Be-Zero | Writers set to `0`; readers **must reject** if any bit is `1` |

---

## 5. Compression and Encryption Identifiers

### `compression_id` (Header Byte `48`, `ZnfCompression`)
- `0` (`None`): Uncompressed raw bytes.
- `1` (`Zstd`): RFC 8878 Zstandard frame (`znf-compression`).
- `2` (`Lz4`): Bounded 64 KiB LZ4 block stream (`u32 uncomp_len || u32 comp_len || block_bytes`, terminated by `0u32`).
- `3..=255`: Unsupported (`ZnfError::UnsupportedCompression`).

### `encryption_id` (Header Byte `49`, `ZnfEncryption`)
- `0` (`None`): Unencrypted.
- `1` (`XChaCha20Poly1305`): 256-bit `XChaCha20-Poly1305` (192-bit nonce, 128-bit Poly1305 tag) with `Argon2id` v19 password KDF or raw 256-bit key.
- `2..=255`: Unsupported (`ZnfError::UnsupportedEncryption`).

---

## 6. Type-Length-Value (TLV) & Structured Metadata Encoding

### TLV Record Wire Format

```text
+-------------------+---------------------+-------------------------------+
| Type: u16 (LE)    | Length: u32 (LE)    | Value: [u8; Length]           |
| 2 bytes           | 4 bytes             | Length bytes                  |
+-------------------+---------------------+-------------------------------+
```

### TLV Type Ranges & Extension Rules

| Range | Classification | Reader Behavior |
|---|---|---|
| `0x0000` | `TLV_RESERVED` | Reject immediately (`ZnfError::ReservedTlvType(0)`) |
| `0x0001..=0x3FFF` | Standard Core & Format TLVs | Parse known types; skip unknown non-critical types |
| `0x4000..=0x6FFF` | **Critical Extensions** | **Reject if unrecognized** (`ZnfError::UnsupportedCriticalExtension`) |
| `0x7000..=0xFFFE` | **Non-Critical / Vendor Extensions** | Preserve in `ZnfMetadata::unknown_extensions` or skip safely |
| `0xFFFF` | `TLV_END` | End of TLV section (`Length` **must** be `0`) |

### Standard Core Metadata TLV Types (`header_len..payload_offset`)

| Type | Constant | Value Format |
|---|---|---|
| `0x0001` | `TLV_CORE_ATTRIBUTES` | `count: u32 LE` followed by sorted `(key_len: u16 LE, key_utf8, MetadataValue)` entries |
| `0x0010` | `TLV_KDF_PARAMS` | `m_cost_kib: u32 LE` (`8192..=1048576`), `t_cost: u32 LE` (`1..=32`), `p_cost: u32 LE` (`1..=64`), `salt: [u8; 16]` |
| `0x0011` | `TLV_PAYLOAD_NONCE` | `[u8; 24]` random OS nonce for `XChaCha20-Poly1305` |
| `0x0020` | `TLV_COMMENT` | Valid UTF-8 string |
| `0x0030` | `TLV_METADATA_BLAKE3` | `[u8; 32]` BLAKE3 digest over `metadata_section[0..offset_of_tlv_0x0030]` |

### `MetadataValue` Wire Tags (Maximum Nesting Depth = `16`)

| Tag (`u8`) | Variant | Wire Encoding Following Tag |
|---:|---|---|
| `1` | `Text(String)` | `len: u32 LE` \|\| `utf8_bytes` |
| `2` | `Bytes(Vec<u8>)` | `len: u32 LE` \|\| `raw_bytes` |
| `3` | `Uint(u64)` | `u64 LE` (8 bytes) |
| `4` | `Int(i64)` | `i64 LE` (8 bytes) |
| `5` | `Bool(bool)` | `u8` (`0` = `false`, `1` = `true`; `2..=255` rejected) |
| `6` | `List(Vec<MetadataValue>)` | `count: u32 LE` \|\| `count` encoded `MetadataValue` items |
| `7` | `Map(BTreeMap<String, MetadataValue>)` | `count: u32 LE` \|\| `count` sorted `(key_len: u16 LE, key_utf8, MetadataValue)` entries |

---

## 7. Standard Core Footer TLVs & Integrity Coverage

| Type | Constant | Size | Exact Coverage / Meaning |
|---|---|---:|---|
| `0x0102` | `TLV_CONTAINER_BLAKE3` | `32` | BLAKE3 digest over `file[0 .. payload_end]` (64B header + metadata + stored payload; non-circular) |
| `0x0110` | `TLV_PAYLOAD_BLAKE3` | `32` | BLAKE3 digest over exact original uncompressed, unencrypted payload bytes (`0..uncompressed_len`) |
| `0x0111` | `TLV_UNCOMPRESSED_LEN` | `8` | `u64 LE` original uncompressed payload byte length |
| `0x0112` | `TLV_STORED_PAYLOAD_LEN` | `8` | `u64 LE` stored payload byte length |
| `0x0113` | `TLV_FOOTER_AUTH_TAG` | `96` | Present when `Flags::ENCRYPTED`: `XChaCha20-Poly1305` encryption of `chunk_count (u64 LE) \|\| uncompressed_len (u64 LE) \|\| payload_blake3 (32B) \|\| container_blake3 (32B)` under `nonce = chunk_nonce(base_nonce, u64::MAX)` and `AAD = header[0..64] \|\| metadata_bytes \|\| u64::MAX.to_le_bytes()` |

---

## 8. Binary Test Vectors

### Vector 1: 64-Byte `ZnfHeader` (`FormatId::CORE = 2`, v1.0, `Zstd`, `Flags = COMPRESSED | HAS_FOOTER`)
- **Parameters:** `format_id = 2`, `major = 1`, `minor = 0`, `flags = 0x09`, `header_len = 64`, `payload_offset = 64`, `payload_len = 128`, `compression_id = 1 (Zstd)`, `encryption_id = 0 (None)`.
- **Computed `header_crc32`:** `0xcd6549cd` (stored little-endian at offset `44..48` as `cd 49 65 cd`).
- **Exact 64-Byte Hex Output:**
  ```text
  5a4e460002000000010000000900000000000000400000000000000040000000
  000000008000000000000000cd4965cd01000000000000000000000000000000
  ```
