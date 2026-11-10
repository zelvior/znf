# ZIMG (.zimg) Development Guide

## 1. Prerequisites

- Rust toolchain (stable, see `rust-toolchain.toml`): `rustc`, `cargo`,
  `rustfmt`, `cargo-clippy`.
- All dependencies vendored in `/tmp/znf-vendor` for offline builds.
- Use `/tmp/znf-env.sh` to set `PATH` and `CARGO_CONFIG_FILE`.

```bash
source /tmp/znf-env.sh
```

## 2. Verification Commands

All checks must pass cleanly:

```bash
# 1. Check formatting
cargo fmt --all -- --check

# 2. Run Clippy across all crates with warnings denied
cargo --config /tmp/znf-cargo-config.toml clippy --workspace --all-targets --offline -- -D warnings

# 3. Run unit, integration, and doc tests
cargo --config /tmp/znf-cargo-config.toml test --workspace --offline

# 4. Build documentation
cargo doc --workspace --no-deps --offline
```

## 3. Crate Structure: `crates/znf-img`

```
src/
  lib.rs        - Public API, re-exports
  error.rs      - ZimgError with classification helpers
  format.rs     - TLV types, color models, bit depths, limits
  image.rs      - Image buffer, PixelFormat, row access
  encode.rs     - Scanline filtering, compression, assembly
  decode.rs     - Header parsing, TLV parsing, decompression, unfiltering
  chunk.rs      - Chunk records, chunking strategies
  metadata.rs   - ImageMetadata encode/decode
```

## 4. Adding a Feature

1. Update `specifications/zimg/ZIMG-SPEC.md` for any new TLV type, color model,
   or flag.
2. Implement in `crates/znf-img/`.
3. Add tests in `crates/znf-img/tests/`.
4. Update CLI in `apps/znf-cli/src/main.rs` if user-facing.
5. Run all verification commands.
6. Document behavior changes.

## 5. Coding Standards

- `#![forbid(unsafe_code)]` in every crate.
- No panics on untrusted input.
- Deterministic wire format: explicit `.to_le_bytes()` / `from_le_bytes()`.
- All paths/dimensions validated before use.
- Clippy `#[deny(clippy::all)]` at crate level.
- Overflow-checked arithmetic for dimensions and offsets.

## 6. Testing Strategy

### Unit tests (`src/*.rs` with `#[cfg(test)]`)
- Filter round-trip (filter then unfilter = identity)
- PixelFormat wire encoding/decoding
- Image row access bounds
- Chunk wire encoding/decoding

### Integration tests (`tests/`)
- RGB/RGBA/gray/gray-alpha round-trip at 8-bit and 16-bit
- 1x1, 1xN, Nx1, small, and large images
- Transparent pixels (alpha = 0)
- Stored / Zstd / LZ4 compression
- Different compression levels
- Encrypted payload round-trip
- Metadata preservation and removal
- Corrupted header, payload, and chunk rejection
- Dimension bomb rejection
- Truncated file handling
- Invalid magic / format ID rejection

### Fuzz targets (future)
- Header byte mutation
- Metadata TLV mutation
- Chunk index mutation
- Dimension overflow

## 7. Benchmarks

Create `crates/znf-img/examples/zimg_bench.rs` measuring:

- Encode/decode speed (MiB/s)
- Compression ratio
- Peak memory usage
- Filter effectiveness (None vs Paeth on photographic vs synthetic data)

Run with:
```bash
cargo run --release -p znf-img --example zimg_bench --offline
```

## 8. Image Import/Export

For PNG import/export, integrate an established decoder (e.g., the `image`
crate) in a future milestone. ZIMG itself uses its native binary format.

For raw pixel input, the CLI accepts a binary file plus a `.meta` sidecar:
```
WIDTH HEIGHT COLOR_MODEL BIT_DEPTH
```
