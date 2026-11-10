# ZNF Architecture Overview

## 1. Crate Dependency Graph

```text
                       +-------------------+
                       |  apps/znf-cli     |
                       |  (`znf` binary)   |
                       +---------+---------+
                                 |
                                 v
                       +-------------------+
                       |     znf-zarc      |
                       | (.zarc container) |
                       +---------+---------+
                                 |
        +-------------+----------+----------+-------------+
        |             |          |          |             |
        v             v          v          v             v
+---------------+ +--------+ +--------+ +--------+ +--------------+
| znf-recovery  | |znf-core| |znf-comp| |znf-cryp| |znf-integrity |
+-------+-------+ +--------+ +--------+ +--------+ +--------------+
        |              ^                                  ^
        +--------------+----------------------------------+

+---------------+
|  znf-stream   |  (standalone bounded chunk framing + BoundedReader)
+---------------+
```

## 2. Responsibility of Each Crate

| Crate | Purpose | Direct Dependencies |
|---|---|---|
| `znf-core` | 64-byte header, FormatId registry, version negotiation, flags, TLV codec, CRC-32, resource `Limits` | `thiserror` |
| `znf-integrity` | Streaming and one-shot `BLAKE3` hashing and verification | `blake3`, `thiserror` |
| `znf-compression` | Lossless streaming compression (`Store`, `Zstd`, `LZ4`) with expanded-size limits | `zstd`, `lz4_flex` (`safe-encode`, `safe-decode`, `checked-decode`), `thiserror` |
| `znf-crypto` | `XChaCha20-Poly1305` AEAD, `Argon2id` v19 KDF with DoS parameter bounds, OS CSPRNG (`getrandom`), key zeroization | `chacha20poly1305`, `argon2`, `getrandom`, `zeroize`, `thiserror` |
| `znf-stream` | Bounded-memory chunk framing (`u32` length-prefixed chunks) and `BoundedReader` | `thiserror` |
| `znf-recovery` | Block XOR parity stripes (`ParityStripe`) and damaged-stream header scanning (`scan_for_headers`) | `znf-core`, `znf-integrity`, `thiserror` |
| `znf-zarc` | `.zarc` archive writer, reader, verifier, parity repair, and traversal-safe extractor | All `znf-*` crates, `thiserror` |
| `znf-cli` | `znf` CLI (`zarc create`, `list`, `extract`, `verify`, `info`) | `clap` (builder API, no proc-macro derive), `rpassword`, `znf-*` |

## 3. Dependency Minimization Decisions

- **No `serde`:** All binary formats use explicit little-endian byte encoding (`to_le_bytes` / `from_le_bytes`) matching the normative specifications.
- **No `clap_derive` or `zeroize_derive`:** Using `clap`'s builder API and manual `Zeroize`/`Drop` implementations avoids redundant proc-macro crates and reduces compile time and attack surface.
- **Pure-Rust Safe LZ4:** `lz4_flex` is configured with `default-features = false, features = ["std", "safe-encode", "safe-decode", "checked-decode"]`, requiring zero transitive dependencies.
- **`#![forbid(unsafe_code)]`:** Enforced across every ZNF crate and binary in the workspace.

## 4. Implemented vs. Planned Capabilities

### Implemented in v0.1.0
- ZNF Core v1.0 specification and parser/encoder (`znf-core`).
- ZARC v1.0 (`.zarc`) archive creation, listing, metadata inspection, integrity verification, and safe extraction (`znf-zarc`, `znf-cli`).
- Lossless `Store`, `Zstandard` (levels 1–22), and `LZ4` compression (`znf-compression`).
- Authenticated encryption (`XChaCha20-Poly1305` + `Argon2id`) covering both file payloads and the entry index (`znf-crypto`).
- Per-file and whole-archive `BLAKE3` digests (`znf-integrity`).
- Single-block XOR parity stripe generation and repair (`znf-recovery`).

### Planned for Future Versions
- Multi-block Reed-Solomon erasure coding in `znf-recovery`.
- Solid archive mode (cross-file dictionary/window sharing) in `znf-zarc` v1.1+.
- Additional ZNF Format IDs (e.g., structured document/media containers).
- Android NDK / JNI bindings and C FFI wrapper crate.
