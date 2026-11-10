# Development & Contribution Guide

## 1. Prerequisites

- Rust `1.87.0` or newer (`rustfmt` and `clippy` components installed).
- C compiler (`gcc`, `clang`, or MSVC) for building bundled `zstd-sys`.

## 2. Verification Commands

Before opening or merging a pull request, all three checks must pass cleanly:

```bash
# 1. Check formatting
cargo fmt --all -- --check

# 2. Run Clippy across all crates, binaries, and tests with warnings denied
cargo clippy --workspace --all-targets -- -D warnings

# 3. Run unit, integration, security, and doc tests
cargo test --workspace
```

## 3. Coding Standards

- **`#![forbid(unsafe_code)]`** is required in every ZNF crate.
- **No Panics on Input:** Never use `.unwrap()` or unchecked indexing on data derived from external bytes unless the slice length has already been explicitly verified on the preceding lines.
- **Deterministic Wire Format:** All multi-byte numbers on the wire must use explicit `.to_le_bytes()` / `::from_le_bytes()`.
- **Update Specifications First:** Any addition of a new `FormatId`, `Flags` bit, or standard TLV type (`0x0001..=0x7FFF`) must be documented in `specifications/` alongside test vectors.
