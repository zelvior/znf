# ZIMG (.zimg) Architecture

This document describes the internal architecture of the ZIMG image engine
(`crates/znf-img`), the crate responsible for encoding, decoding, and
verifying `.zimg` images built on the ZNF Core v1.0 binary format.

## 1. Module Layout

| Module | Responsibility |
|---|---|
| `lib.rs` | Public API re-exports, `ImageInfo`, spec version constant |
| `error.rs` | `ZimgError` enum with `is_authentication_failure()`, `is_corruption()`, `is_unsupported()` |
| `format.rs` | Binary format constants: TLV types, color models, bit depths, limits |
| `header.rs` | *(uses znf-core `Header` directly; ZIMG reuses ZNF Core header with FormatId::ZIMG)* |
| `image.rs` | `Image` buffer, `PixelFormat`, `ColorModel`, `BitDepth`, `AlphaInfo`, `ColorSpace`, row access |
| `encode.rs` | Scanline filtering (None/Sub/Up/Average/Paeth), compression, chunking, assembly |
| `decode.rs` | Header parsing, metadata TLV parsing, chunk decryption/decompression, unfiltering, integrity verification |
| `chunk.rs` | `Chunk` record, chunking strategies (scanline/fixed), boundary computation |
| `metadata.rs` | `ImageMetadata` with encode/decode for structured key-value metadata |

## 2. Core Data Types

### `Image`

In-memory pixel buffer with explicit row stride:

| Field | Type | Description |
|---|---|---|
| `width` | `u32` | Image width in pixels |
| `height` | `u32` | Image height in pixels |
| `pixel_format` | `PixelFormat` | Color model, bit depth, channels, alpha, color space |
| `stride` | `usize` | Bytes per row (>= width × bytes_per_pixel) |
| `data` | `Vec<u8>` | Row-major pixel data, little-endian for 16-bit |
| `chunk_hashes` | `Vec<Hash>` | Per-chunk BLAKE3 hashes (set after decode) |

`Image::new()` validates dimensions against `MAX_WIDTH`, `MAX_HEIGHT`,
and `MAX_TOTAL_PIXELS` using overflow-checked arithmetic.

### `PixelFormat`

| Field | Type | Description |
|---|---|---|
| `color_model` | `ColorModel` | Gray, GrayAlpha, Rgb, Rgba |
| `bit_depth` | `BitDepth` | Bits8, Bits16 |
| `channel_count` | `u8` | Must match color model |
| `alpha` | `AlphaInfo` | None, Present |
| `color_space` | `ColorSpace` | Srgb, Linear, Icc |

Wire encoding: 4 bytes via `to_wire_bytes()` / `from_wire_bytes()`.

### `EncodeOptions`

| Field | Type | Default |
|---|---|---|
| `compression` | `CompConfig` | `CompConfig::zstd(3)` |
| `filter` | `FilterType` | `FilterType::None` |
| `chunk_strategy` | `ChunkStrategy` | Fixed 1 MiB chunks |
| `password` | `Option<Vec<u8>>` | `None` |
| `kdf_params` | `Option<KdfParams>` | `None` |
| `include_integrity` | `bool` | `true` |

### `DecodeOptions`

| Field | Type | Default |
|---|---|---|
| `password` | `Option<Vec<u8>>` | `None` |
| `limits` | `Limits` | `Limits::default()` |
| `verify_integrity` | `bool` | `true` |

## 3. Encode Path

1. `Image::new()` validates dimensions and allocates `stride × height` bytes.
2. `encode_image()`:
   - Splits pixel data into chunks via `compute_chunks()`.
   - For each chunk, applies scanline filtering row-by-row (filter byte +
     filtered row data concatenated).
   - Compresses each filtered chunk (Store / Zstd / LZ4).
   - Optionally encrypts each compressed chunk: `nonce(24B) \|
     XChaCha20-Poly1305(chunk, aad=chunk_index_LE)`.
   - Builds metadata TLV section (dimensions, pixel format, color space,
     compression, metadata).
   - Builds footer TLV section (chunk index, per-chunk BLAKE3, archive BLAKE3).
   - Computes archive BLAKE3 over `header \| metadata \| payload`.
   - Assembles: `header(64) + metadata + payload + footer`.

## 4. Decode Path

1. `decode_image()`:
   - Decodes and validates ZNF Core header (FormatId must be ZIMG=3).
   - Parses metadata TLVs: dimensions, pixel format, color space, metadata.
   - Derives decryption key if `ENCRYPTED` flag set (password + KDF params).
   - Parses footer TLVs: chunk index, pixel hashes, archive BLAKE3.
   - Verifies archive BLAKE3 over `header(0..payload_end)`.
   - For each chunk: decrypt (if needed), decompress, verify chunk BLAKE3,
     unfilter rows, write into `Image` buffer.

## 5. Chunking

`ChunkStrategy::Scanline` — one chunk per row. Good for progressive decoding.
`ChunkStrategy::Fixed { max_uncompressed }` — groups rows into chunks of up to
`max_uncompressed` bytes (default 1 MiB). Better compression ratio, bounded
memory.

Each `Chunk` record stores uncompressed offset, stored offset, lengths, and
BLAKE3 hash for independent verification and random access.

## 6. Filtering

Five scanline filters (PNG-compatible semantics):

| Filter | Use case |
|--------|----------|
| None | Incompressible/random data |
| Sub | Gradients, horizontal redundancy |
| Up | Vertical redundancy |
| Average | Smooth gradients in both directions |
| Paeth | Sharp edges, photographic content |

Filter is chosen per-image (not per-row) in v1.0. Future versions may select
per-row adaptively.

## 7. Encryption

- Per-chunk XChaCha20-Poly1305 with unique random nonce per chunk.
- Argon2id key derivation from password + KDF params.
- Optional encrypted metadata (`TLV_ZIMG_ENCRYPTED_METADATA`).
- Chunk index and archive structure visible in cleartext (format limitation,
  documented in security model).
- AAD binding: chunk index for chunks, header bytes for metadata.

## 8. Integrity

| Value | Covers | Verified on |
|-------|--------|-------------|
| Header CRC-32 | Header non-CRC bytes | `Header::decode()` |
| Per-chunk BLAKE3 | Uncompressed chunk (filter + data) | Decode (if `verify_integrity`) |
| Archive BLAKE3 | Header + metadata + payload | Decode (always) |
| AEAD tag | Encrypted chunk ciphertext + AAD | Decrypt (if encrypted) |

## 9. Resource Limits

| Limit | Default |
|-------|---------|
| Max width | 1,000,000 |
| Max height | 1,000,000 |
| Max total pixels | 256,000,000 |
| Max header len | 1 MiB |
| Max metadata len | 16 MiB |
| Max expanded (decompressed) | 10 GiB |

All limits configurable via `Limits`. Strict variant available for untrusted input.

## 10. Safety Guarantees

- `#![forbid(unsafe_code)]` across the crate.
- No `serde`; explicit little-endian byte encoding.
- All external input bounds-checked before indexing.
- Overflow-checked dimension and offset arithmetic.
- No `.unwrap()` on untrusted data.
- Chunked processing with bounded memory (no whole-file allocation beyond declared limits).