# ZDOC Development Guide

## Building

ZDOC is part of the ZNF workspace. Build with:

```bash
cargo build -p znf-doc
```

Test with:

```bash
cargo test -p znf-doc
```

Format and lint:

```bash
cargo fmt -p znf-doc -- --check
cargo clippy -p znf-doc --all-targets -- -D warnings
```

## Implementation Status

### Complete

| Feature | Status |
|---------|--------|
| Binary specification | `specifications/zdoc/ZDOC-SPEC.md` |
| Format constants & TLV types | `crates/znf-doc/src/format.rs` |
| Error types with classifiers | `crates/znf-doc/src/error.rs` |
| Document Object Model | `crates/znf-doc/src/dom.rs` |
| Serialization (DOM -> bytes) | `crates/znf-doc/src/serialize.rs` |
| Deserialization (bytes -> DOM) | `crates/znf-doc/src/deserialize.rs` |
| Public API | `crates/znf-doc/src/lib.rs` |
| Functional + security tests | `crates/znf-doc/tests/zdoc_tests.rs` |
| Architecture doc | `docs/architecture/zdoc.md` |
| Security doc | `docs/security/zdoc-security.md` |
| Development doc | `docs/development/zdoc-development.md` |

### Deferred (requires Rust toolchain)

The Rust toolchain is not available in this sandbox, so the following have not been
executed:

- `cargo fmt --check`
- `cargo clippy -D warnings`
- `cargo test`

These must be run once `/tmp/rust-toolchain` is available.

### Planned (not yet implemented)

| Feature | Notes |
|---------|-------|
| CLI commands for ZDOC | `znf zdoc create|inspect|validate|verify|extract-text|sanitize-metadata` |
| JSON output mode | Machine-readable CLI output |
| Import/export (Markdown, HTML, plain text, DOCX, PDF) | Fidelity matrix to be established |
| Streaming deserialization | Incremental object decoding |
| Fuzz targets | cargo-fuzz for binary headers, chunks, metadata |
| Benchmark suite | Small/medium/large document benchmarks |
| Test vectors | Canonical binary fixtures for compatibility |
| Per-object encryption tests | Exercise encrypted object round-trips |

## Coding Conventions

- `#![forbid(unsafe_code)]` — no unsafe Rust.
- `#![deny(clippy::all)]` — clippy warnings are errors.
- All multi-byte integers are little-endian.
- All parsing is strict: malformed input returns `ZdocError`, never panics.
- Text is UTF-8 and preserved exactly; no normalization.
- Reuse ZNF Core crates; do not duplicate compression, encryption, integrity, or streaming.