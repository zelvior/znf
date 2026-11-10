# ZIMG (`.zimg`) Lossless Image Format Specification (Version 1.0)

- **Status:** Implemented (`crates/znf-img`, `apps/znf-cli`)
- **Format ID:** `0x0000_0003` (`FormatId::ZIMG`)
- **Core Specification:** ZNF Core v1.0 (`specifications/core/ZNF-CORE-SPEC.md`)
- **File Extension:** `.zimg`
- **Specification Version:** 1.0

---

## 1. Overview

ZIMG is a modern, privacy-focused, lossless-first image format built on the
ZNF Core v1.0 binary foundation. It stores raster images with exact pixel
sample preservation, optional authenticated encryption, BLAKE3 integrity
verification, and a structured metadata system.

Design goals:

- **Lossless preservation:** decoded pixel samples match the original exactly.
- **Compression efficiency:** Zstandard and LZ4 with optional scanline filtering.
- **Fast encode/decode:** streaming-friendly chunked architecture.
- **Low memory:** bounded chunk sizes, no unbounded allocations.
- **High resolution:** multi-megapixel support with overflow-safe math.
- **Color accuracy:** sRGB, linear RGB, and embedded ICC profiles.
- **Metadata privacy:** optional, user-controlled; no telemetry or auto-collection.
- **Optional encryption:** XChaCha20-Poly1305 + Argon2id.
- **Integrity:** per-chunk and whole-file BLAKE3.

ZIMG is **not** a wrapper around PNG, JPEG, or any other existing format. It
has its own binary specification and native implementation.

---

## 2. Container Structure

ZIMG files use the ZNF Core 64-byte fixed header with `FormatId::ZIMG` (3).
The overall layout follows the same container pattern as ZARC:

```text
Offset 0
+===================================================================+
| 1. ZNF Core Fixed Header (64 bytes, FormatId = 3, Version = 1.0)  |
+===================================================================+
| 2. Metadata TLV Section (optional; HAS_METADATA flag)             |
|    - TLV_ZIMG_DIMENSIONS   (0x0100): width \| height               |
|    - TLV_ZIMG_PIXEL_FORMAT (0x0101): color_model \| bit_depth     |
|    |                                     \| channel_count \| alpha |
|    - TLV_ZIMG_COLOR_SPACE  (0x0102): sRGB / linear / ICC id       |
|    - TLV_ZIMG_ICC_PROFILE  (0x0103): ICC profile bytes            |
|    - TLV_ZIMG_COMPRESSION  (0x0104): algorithm \| level           |
|    - TLV_ZIMG_METADATA     (0x0105): title, description, etc.     |
|    - TLV_ZIMG_ENCRYPTED_METADATA (0x0106): nonce(24B) \| ciphertext |
|    - Non-critical extensions (0x7000..=0xFFFE)                    |
|    - Critical extensions   (0x4000..=0x6FFF, reject if unknown)   |
|    - TLV_END (0xFFFF)                                             |
+===================================================================+
| 3. Payload Section                                                |
|    Chunked compressed pixel data (each chunk: optionally nonce+   |
|    ciphertext+tag if encrypted, else raw compressed bytes)        |
+===================================================================+
| 4. Footer TLV Section (required; HAS_FOOTER always set)           |
|    - TLV_ZIMG_CHUNK_INDEX   (0x0200): chunk offset/size table     |
|    - TLV_ZIMG_PIXEL_BLAKE3  (0x0201): per-chunk BLAKE3 hashes     |
|    - TLV_ARCHIVE_BLAKE3     (0x0202): whole-file BLAKE3 digest    |
|    - TLV_END (0xFFFF)                                             |
+===================================================================+
```

All multi-byte integers are little-endian. No native Rust struct
serialization is used; every field is encoded explicitly.

---

## 3. ZNF Core Header

| Offset | Size | Field | Encoding | Validation |
|--------|------|-------|----------|------------|
| 0 | 4 | Magic | `ZNF\0` ([0x5A,0x4E,0x46,0x00]) | Must match |
| 4 | 4 | Format ID | u32 LE | Must be 3 (ZIMG) |
| 8 | 2 | Major version | u16 LE | Must be 1 |
| 10 | 2 | Minor version | u16 LE | Must be 0 |
| 12 | 8 | Feature flags | u64 LE | See flags below |
| 20 | 8 | Header length | u64 LE | >= 64 |
| 28 | 8 | Payload offset | u64 LE | >= header_len |
| 36 | 8 | Payload length | u64 LE | Bounded by Limits |
| 44 | 4 | Header CRC-32 | u32 LE | IEEE CRC-32 over bytes 0..44 \| 48..64 |
| 48 | 1 | Compression ID | u8 | 0=None, 1=Zstd, 2=LZ4 |
| 49 | 1 | Encryption ID | u8 | 0=None, 1=XChaCha20-Poly1305 |
| 50 | 14 | Reserved | [u8;14] | Must be zero |

### Feature flags (from `ZnfFeatureFlags`)

| Bit | Name | Meaning |
|-----|------|---------|
| 0 | COMPRESSED | Payload is compressed (Zstd or LZ4) |
| 1 | ENCRYPTED | Payload is AEAD-encrypted |
| 2 | HAS_METADATA | Metadata TLV section present |
| 3 | HAS_FOOTER | Footer TLV section present (always set in ZIMG) |
| 4 | STREAMING | Payload uses chunked framing (always set in ZIMG) |

### Compression ID (byte 48)

| Value | Meaning |
|-------|---------|
| 0 | Stored (no compression) |
| 1 | Zstandard (RFC 8878) |
| 2 | LZ4 block framing |

### Encryption ID (byte 49)

| Value | Meaning |
|-------|---------|
| 0 | Unencrypted |
| 1 | XChaCha20-Poly1305 (256-bit key, 192-bit nonce, 128-bit tag) |

---

## 4. Pixel Format

### Color Models

| ID | Name | Channels | Description |
|----|------|----------|-------------|
| 0 | Gray | 1 | Single luminance channel |
| 1 | GrayAlpha | 2 | Luminance + alpha |
| 2 | RGB | 3 | Red, green, blue |
| 3 | RGBA | 4 | Red, green, blue, alpha |

### Bit Depths

| Value | Bytes per sample | Description |
|-------|-----------------|-------------|
| 8 | 1 | 8 bits per sample (0-255) |
| 16 | 2 | 16 bits per sample, little-endian (0-65535) |

### Alpha Info

| Value | Meaning |
|-------|---------|
| 0 | No alpha channel |
| 1 | Alpha channel present |

### Color Space

| Value | Meaning |
|-------|---------|
| 0 | sRGB |
| 1 | Linear RGB |
| 2 | ICC profile embedded (see TLV_ZIMG_ICC_PROFILE) |

### Pixel Format TLV (`TLV_ZIMG_PIXEL_FORMAT = 0x0101`)

4 bytes: `[color_model: u8] [bit_depth: u8] [channel_count: u8] [alpha_info: u8]`

The `channel_count` must match the color model's channel count (Gray=1, GrayAlpha=2, RGB=3, RGBA=4).

---

## 5. Dimensions TLV (`TLV_ZIMG_DIMENSIONS = 0x0100`)

8 bytes: `[width: u32 LE] [height: u32 LE]`

### Limits

| Parameter | Maximum |
|-----------|---------|
| Width | 1,000,000 pixels |
| Height | 1,000,000 pixels |
| Total pixels (width × height) | 256,000,000 |

Dimension calculations use overflow-checked arithmetic. Images exceeding
limits are rejected with `ZimgError::InvalidDimensions`.

---

## 6. Compression TLV (`TLV_ZIMG_COMPRESSION = 0x0104`)

2 bytes: `[algorithm: u8] [level: u8]`

| Algorithm ID | Name | Level range |
|--------------|------|-------------|
| 0 | Stored | N/A |
| 1 | Zstandard | 1-22 |
| 2 | LZ4 | N/A |

Default level: 3 (Zstandard).

---

## 7. Chunked Pixel Storage

Pixel data is divided into independently compressed chunks for bounded memory
and random-access decoding.

### Chunking strategies

- **Scanline:** each row is a separate chunk.
- **Fixed:** chunks of up to `max_uncompressed` bytes (default 1 MiB).

Each filtered scanline is prefixed with a 1-byte filter type:

| Filter ID | Name | Description |
|-----------|------|-------------|
| 0 | None | No filtering |
| 1 | Sub | Difference from left pixel |
| 2 | Up | Difference from pixel above |
| 3 | Average | Average of left and above |
| 4 | Paeth | Paeth predictor |

### Chunk Index Entry (`TLV_ZIMG_CHUNK_INDEX = 0x0200`)

The chunk index begins with `count: u32 LE` followed by `count` entries of 60 bytes each:

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | `chunk_index` (u32 LE) |
| 4 | 8 | `uncompressed_offset` (u64 LE) — offset within full pixel buffer |
| 12 | 8 | `stored_offset` (u64 LE) — offset within payload section |
| 20 | 4 | `uncompressed_len` (u32 LE) |
| 24 | 4 | `stored_len` (u32 LE) |
| 28 | 32 | `blake3_hash` — BLAKE3 of uncompressed chunk bytes |

Total: 4 + count × 60 bytes.

### Per-Chunk BLAKE3 (`TLV_ZIMG_PIXEL_BLAKE3 = 0x0201`)

`count: u32 LE` followed by `count × 32` bytes of BLAKE3 hashes (one per chunk,
over the uncompressed chunk bytes including filter byte).

---

## 8. Metadata

### Structured Metadata TLV (`TLV_ZIMG_METADATA = 0x0105`)

Format: `count: u16 LE` followed by `count` entries:
`key_len: u16 LE` \| `key_utf8` \| `val_len: u16 LE` \| `val_utf8`.

Standard keys: `title`, `description`, `creator`, `created`, `software`, `copyright`.
Custom keys are preserved sorted by key.

### ICC Profile TLV (`TLV_ZIMG_ICC_PROFILE = 0x0103`)

Raw ICC profile bytes. Preserved exactly; not parsed or converted.

### Encrypted Metadata TLV (`TLV_ZIMG_ENCRYPTED_METADATA = 0x0106`)

24-byte nonce \| XChaCha20-Poly1305(plaintext, aad=header[0..64]).
Used when metadata privacy is required alongside payload encryption.

### Privacy rules

- Metadata is optional; omit all TLV sections for no metadata.
- No device information, location, or user identity is automatically collected.
- Metadata removal/sanitization is supported via `znf image metadata --remove`.
- Unknown non-critical metadata extensions are preserved when safe.

---

## 9. Encryption

When `Flags::ENCRYPTED` is set:

1. **Key derivation:** Argon2id v19 from password + `TLV_KDF_PARAMS` (28 bytes).
2. **Per-chunk encryption:** Each compressed chunk is encrypted with XChaCha20-Poly1305
   using a fresh 24-byte random nonce. Format per chunk: `nonce(24B) \| ciphertext + tag(16B)`.
   AAD = chunk index as 8-byte LE.
3. **Encrypted metadata:** Optional `TLV_ZIMG_ENCRYPTED_METADATA` with nonce(24B) \|
   ciphertext+tag, AAD = header[0..64].
4. **Index:** Chunk index and pixel hashes are NOT encrypted (they reveal structure
   but not pixel content). The archive BLAKE3 covers header \| metadata \| payload.

Visible in cleartext (even when encrypted): dimensions, pixel format, compression
algorithm, chunk count, chunk offsets/sizes, archive structure. Pixel data and
metadata are confidential.

---

## 10. Integrity

| Integrity Value | Covers | Location |
|-----------------|--------|----------|
| Header CRC-32 | Header bytes 0..44 \| 48..64 | Header byte 44 |
| Per-chunk BLAKE3 | Uncompressed chunk bytes (filter + row data) | `TLV_ZIMG_PIXEL_BLAKE3` |
| Archive BLAKE3 | `header(0..payload_offset+payload_len)` | `TLV_ARCHIVE_BLAKE3` |
| AEAD tags | Per-chunk ciphertext + AAD | Embedded in encrypted chunks |

BLAKE3 detects corruption with overwhelming probability but is **not**
authentication. Use AEAD (encryption) for authenticity against active attackers.

---

## 11. Error Handling

All public functions return `Result<T, ZimgError>`.

| Variant | Meaning |
|---------|---------|
| `ZimgError::NotZimgFormat(id)` | File has valid ZNF header but wrong FormatId |
| `ZimgError::MalformedImage(msg)` | Image structure violates specification |
| `ZimgError::InvalidDimensions(msg)` | Dimensions exceed limits or overflow |
| `ZimgError::UnsupportedPixelFormat(msg)` | Unknown/invalid color model, bit depth, etc. |
| `ZimgError::ChunkNotFound(idx)` | Requested chunk does not exist |
| `ZimgError::TargetAlreadyExists(path)` | Output exists, overwrite not set |
| `ZimgError::ResourceLimitExceeded(msg)` | Bomb-protection limit exceeded |
| `ZimgError::EncryptionMismatch(msg)` | Password required or supplied for unencrypted |
| `ZimgError::AuthenticationFailed` | Wrong key or tampered AEAD data |
| `ZimgError::Core(...)` | Underlying ZNF Core error |
| `ZimgError::Compression(...)` | Compression/decompression error |
| `ZimgError::Integrity(...)` | BLAKE3 hash mismatch |
| `ZimgError::Io(...)` | Standard I/O error |

Classification helpers: `is_authentication_failure()`, `is_corruption()`,
`is_unsupported()`.

---

## 12. Public API Reference

| Function/Method | Description |
|-----------------|-------------|
| `Image::new(w, h, pf)` | Create image buffer with validated dimensions |
| `encode_image(img, opts)` | Encode Image to ZIMG file bytes |
| `decode_image(bytes, opts)` | Decode ZIMG file bytes to Image |
| `EncodeOptions { compression, filter, password, ... }` | Encoding configuration |
| `DecodeOptions { password, limits, verify_integrity }` | Decoding configuration |
| `ImageMetadata` | Structured title/description/creator/custom metadata |
| `PixelFormat { color_model, bit_depth, channel_count, alpha, color_space }` | Pixel format descriptor |
| `FilterType::None\|Sub\|Up\|Average\|Paeth` | Scanline filter selection |
| `ZimgError` | Typed error with classification helpers |

---

## 13. CLI

Commands (`znf image <subcommand>`):

| Command | Description |
|---------|-------------|
| `encode INPUT OUTPUT` | Encode raw image to `.zimg` |
| `decode INPUT.zimg OUTPUT` | Decode `.zimg` to raw pixels + sidecar |
| `inspect FILE.zimg` | Inspect header and properties |
| `verify FILE.zimg` | Verify all BLAKE3 hashes and AEAD tags |
| `metadata FILE.zimg [--remove -o OUT]` | Display or remove metadata |
| `info FILE.zimg` | Detailed image information |
| `optimize INPUT.zimg OUTPUT.zimg` | Re-encode with different settings |

Options: `--compression`, `--level`, `--filter`, `--encrypt`,
`--password-env`, `--overwrite`, `--progress`, `--json`.

---

## 14. Compliance

Independent implementations must:

- Use the ZNF Core 64-byte header with `FormatId::ZIMG` (3).
- Reject headers with unknown critical feature flags.
- Validate dimensions against limits before allocation.
- Use little-endian for all multi-byte integers.
- Never use native struct serialization for wire format.
- Reject unknown critical TLV extensions (`0x4000..=0x6FFF`).
- Preserve non-critical extensions (`0x7000..=0xFFFE`).
- Verify per-chunk and archive BLAKE3 on decode (when integrity enabled).
- Use XChaCha20-Poly1305 + Argon2id for encryption.
- Apply overflow-checked arithmetic for dimension calculations.
