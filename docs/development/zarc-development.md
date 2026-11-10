# ZARC (.zarc) Development Guide

This document describes how to build, test, and benchmark the ZARC archive
engine (`crates/znf-zarc` and `apps/znf-cli`).

## 1. Prerequisites

- Rust toolchain (see `rust-toolchain.toml`): `rustc`, `cargo`, `rustfmt`,
  `cargo-clippy`.
- All dependencies are vendored in `/tmp/znf-vendor` for offline builds.
- Use `/tmp/znf-env.sh` to set `PATH` and `CARGO_CONFIG_FILE`.

```bash
source /tmp/znf-env.sh
```

## 2. Verification Commands

All three checks must pass cleanly before committing:

```bash
# 1. Check formatting
cargo fmt --all -- --check

# 2. Run Clippy across all crates, binaries, and tests with warnings denied
cargo --config /tmp/znf-cargo-config.toml clippy --workspace --all-targets --offline -- -D warnings

# 3. Run unit, integration, security, and doc tests
cargo --config /tmp/znf-cargo-config.toml test --workspace --offline
```

> **Note:** `cargo clippy` requires the vendored config to be present at
> `.cargo/config.toml` in the workspace root (copied from
> `/tmp/znf-cargo-config.toml`) for offline dependency resolution.

## 3. Release Benchmarks

The following measurements were recorded with
`cargo run --release -p znf-zarc --example zarc_bench --offline` on a corpus
of **56 files, 1.50 MiB** of mixed source code, JSON, and binary data.

| Mode       |   Input Size | Archive Size |    Ratio |   Create Speed |   List/Insp |   Verify Speed |  Extract Speed |
|------------|--------------|--------------|----------|----------------|-------------|----------------|----------------|
| Store      |    1572864 B |    1579476 B |   1.00:1 |    213.0 MiB/s |  1459.65 us |    369.3 MiB/s |   1238.6 MiB/s |
| LZ4        |    1572864 B |      20220 B | 115.58:1 |    806.2 MiB/s |    39.83 us |   2923.8 MiB/s |   2510.4 MiB/s |
| Zstd-1     |    1572864 B |      13604 B | 224.95:1 |    391.6 MiB/s |    35.07 us |    636.5 MiB/s |    658.7 MiB/s |
| Zstd-3     |    1572864 B |      13604 B | 224.95:1 |    281.2 MiB/s |    35.48 us |    656.9 MiB/s |    652.8 MiB/s |
| Zstd-9     |    1572864 B |      13604 B | 224.95:1 |     32.0 MiB/s |    43.12 us |    629.8 MiB/s |    636.9 MiB/s |

### Benchmark Harness

The benchmark is in `crates/znf-zarc/examples/zarc_bench.rs`. It measures:

- **Create Speed:** Throughput of writing the archive (compression + encryption).
- **List/Insp:** Time to open and inspect the archive (index decode only).
- **Verify Speed:** Throughput of `verify_all()` (per-entry BLAKE3 + archive BLAKE3).
- **Extract Speed:** Throughput of full extraction to disk.

Run it yourself:

```bash
source /tmp/znf-env.sh
cargo run --release -p znf-zarc --example zarc_bench --offline
```

## 4. Adding a New Feature

1. **Update the specification first** (`specifications/zarc/ZARC-SPEC.md`) for
   any new `FormatId`, `Flags` bit, standard TLV type (`0x0001..=0x7FFF`), or
   entry flag.
2. **Implement** in the relevant crate(s).
3. **Add tests** in `crates/znf-zarc/tests/security_and_vectors.rs` covering the
   new behavior, including malicious-input cases.
4. **Update documentation** (`docs/architecture/zarc.md`,
   `docs/security/zarc-security.md`) as needed.
5. **Run all three verification commands** (fmt, clippy, test).
6. **Add benchmark numbers** if performance characteristics change.

## 5. Coding Standards

- `#![forbid(unsafe_code)]` in every crate.
- No panics on untrusted input; avoid `.unwrap()` on externally derived data
  unless length has been explicitly verified.
- Deterministic wire format: explicit `.to_le_bytes()` / `from_le_bytes()` for
  all multi-byte integers.
- All paths validated by `validate_archive_path` before use.
- Symlinks refused by default in both creation and extraction.
- Integer overflow checked via `checked_add` / `checked_mul`.
- Clippy `#[deny(clippy::all)]` is enabled at the crate level (`lib.rs`).