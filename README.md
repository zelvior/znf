# ZNF — Zelvior Native Format & ZARC (`.zarc`) Archive Container

ZNF is a modular, security-hardened binary format foundation written in safe Rust (`#![forbid(unsafe_code)]`), with **ZARC (`.zarc`)** as its first implemented container format.

- **License:** Apache-2.0
- **Privacy:** Zero telemetry, zero network calls, deterministic binary encoding.
- **Target Platforms:** Linux, Windows, macOS, and Android.

---

## Implemented vs. Planned Status (v0.1.0)

| Component / Capability | Status | Location |
|---|---|---|
| **ZNF Core v1.0** (64B LE header, FormatId registry, version negotiation, flags, TLV codec, CRC-32, resource `Limits`) | **Implemented** | `crates/znf-core`, `specifications/core/ZNF-CORE-SPEC.md` |
| **Lossless Compression** (`Store`, `Zstandard` levels 1–22, `LZ4` bounded block framing, expanded-size bomb limits) | **Implemented** | `crates/znf-compression` |
| **Authenticated Encryption & KDF** (`XChaCha20-Poly1305` AEAD with header AAD binding + encrypted index, `Argon2id` v19 with DoS bounds, OS CSPRNG via `getrandom`, key zeroization) | **Implemented** | `crates/znf-crypto` |
| **Cryptographic Integrity** (Streaming and one-shot `BLAKE3` digests for per-file and whole-archive verification) | **Implemented** | `crates/znf-integrity` |
| **Streaming Framing** (`u32` length-prefixed bounded chunks and `BoundedReader`) | **Implemented** | `crates/znf-stream` |
| **Recovery Primitives** (Single-block XOR `ParityStripe` repair and damaged-stream header magic/CRC scanner) | **Implemented** | `crates/znf-recovery` |
| **ZARC (`.zarc`) v1.0 Container** (Create, list, inspect, verify, parity-repair, and traversal-safe extraction) | **Implemented** | `crates/znf-zarc`, `specifications/zarc/ZARC-SPEC.md` |
| **`znf` CLI** (`znf zarc create`, `list`, `extract`, `verify`, `info`) | **Implemented** | `apps/znf-cli` |
| Multi-erasure Reed-Solomon recovery codes | *Planned* | `crates/znf-recovery` (v0.2+) |
| Solid cross-file dictionary archiving mode | *Planned* | `crates/znf-zarc` (v0.2+) |
| Additional ZNF Format IDs & C/Android JNI FFI bindings | *Planned* | Future crates |

---

## Repository Layout

```text
znf/
├── Cargo.toml                         # Workspace manifest
├── rust-toolchain.toml                # Pinned Rust toolchain (1.87.0+)
├── LICENSE                            # Apache-2.0
├── SECURITY.md                        # Vulnerability reporting policy
├── apps/
│   └── znf-cli/                       # `znf` command-line binary
├── crates/
│   ├── znf-core/                      # Core 64-byte header, Flags, Limits, TLV codec
│   ├── znf-compression/               # Lossless Store, Zstd, and LZ4 codecs
│   ├── znf-crypto/                    # XChaCha20-Poly1305 AEAD, Argon2id KDF, OS RNG
│   ├── znf-integrity/                 # BLAKE3 hashing and verification
│   ├── znf-stream/                    # Bounded chunk framing and BoundedReader
│   ├── znf-recovery/                  # XOR block parity stripe & header scanner
│   └── znf-zarc/                      # .zarc container format implementation
├── specifications/
│   ├── core/ZNF-CORE-SPEC.md          # Normative ZNF Core v1.0 wire specification
│   └── zarc/ZARC-SPEC.md              # Normative ZARC (.zarc) v1.0 wire specification
├── docs/
│   ├── architecture/OVERVIEW.md       # Crate graph & design rationale
│   ├── security/THREAT-MODEL.md       # Threat model & security invariants
│   └── development/CONTRIBUTING.md    # Build, lint, and test workflow
└── tests/
    ├── vectors/                       # Binary test vector documentation
    ├── compatibility/                 # Versioning & forward-compatibility notes
    └── security/                      # Adversarial & truncation test overview
```

---

## Quickstart (`znf` CLI)

```bash
# Build workspace
cargo build --release

# Create a Zstd-compressed .zarc archive with recovery parity
./target/release/znf zarc create -o backup.zarc -c zstd -l 3 --parity ./my_folder

# Inspect container header, flags, BLAKE3 digest, and KDF parameters
./target/release/znf zarc info backup.zarc

# List archive entries
./target/release/znf zarc list backup.zarc

# Verify header CRC-32, whole-archive BLAKE3, parity stripe, and per-file hashes
./target/release/znf zarc verify backup.zarc

# Extract safely into ./output_dir (enforces path traversal & symlink checks)
./target/release/znf zarc extract backup.zarc -d ./output_dir

# Create an encrypted archive (XChaCha20-Poly1305 + Argon2id, encrypts both files and index)
./target/release/znf zarc create -o secret.zarc --encrypt ./sensitive_dir
```

---

## Security & Engineering Guarantees

1. **Explicit Deterministic Binary Encoding:** No Rust struct layouts are ever serialized directly; all multi-byte integers are encoded in explicit little-endian wire format.
2. **Established Cryptography Only:** Uses `chacha20poly1305`, `argon2`, `blake3`, `getrandom`, and `zeroize`. Checksums (`CRC-32`, `BLAKE3`) are strictly distinguished from cryptographic authentication (`XChaCha20-Poly1305`).
3. **Hardened Against Untrusted Input:**
   - Rejects path traversal (`..`, leading `/`, `\`, Windows drive prefixes `C:`, reserved names `CON`/`NUL`/`COM1`, NUL bytes, and symlink escapes).
   - Enforces configurable `Limits` on headers, metadata, TLVs, entry counts, compression ratios, and expanded sizes before allocating memory.
   - Tested against every single-byte truncation offset (`0..EOF`) to ensure zero panics on malformed input.
