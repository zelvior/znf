# ZDOC Architecture

## Overview

ZDOC (`.zdoc`) is a privacy-first, lossless-first document format built on the
ZNF Core v1.0 binary foundation. It is identified by `FormatId::ZDOC` (value
`4`) in the ZNF Core FormatId registry.

## Crate: `znf-doc`

The `znf-doc` crate provides encoding, decoding, and integrity for ZDOC
documents. It reuses the following ZNF Core crates without duplicating their
implementations:

| Crate | Responsibility |
|-------|---------------|
| `znf-core` | 64-byte header, FormatId registry, Flags, Limits, TLV codec, CRC-32 |
| `znf-compression` | Store, Zstandard (levels 1-22), LZ4 bounded block framing |
| `znf-crypto` | XChaCha20-Poly1305 AEAD, Argon2id KDF, OS CSPRNG |
| `znf-integrity` | BLAKE3 streaming and one-shot hashing |
| `znf-stream` | Bounded chunk framing |

## Module Layout

```
crates/znf-doc/src/
├── lib.rs       # Public API re-exports
├── format.rs    # Binary format constants, TLV types, resource limits
├── error.rs     # ZdocError with corruption/auth/unsupported classifiers
├── dom.rs       # Document Object Model (DOM) types
├── serialize.rs # DOM -> ZDOC file bytes
└── deserialize.rs # ZDOC file bytes -> DOM
```

## Binary Format

A ZDOC file is a ZNF Core container:

```
[ ZNF Core Header (64 bytes, FormatId::ZDOC) ]
[ Metadata Section (TLVs) ]
[ Payload Section (serialized DOM objects) ]
[ Footer Section (TLVs + TLV_END) ]
```

### Metadata Section TLVs

| Type | Name | Contents |
|------|------|----------|
| 0x0100 | Document ID | UUID (16 bytes) |
| 0x0101 | Title | UTF-8 |
| 0x0102 | Subject | UTF-8 |
| 0x0103 | Author | UTF-8 |
| 0x0104 | Creator | UTF-8 |
| 0x0105 | Created | RFC 3339 UTF-8 |
| 0x0106 | Modified | RFC 3339 UTF-8 |
| 0x0107 | Language | BCP-47 UTF-8 |
| 0x0108 | Structure | Document structure descriptor |
| 0x0109 | Metadata KV | Sorted UTF-8 key-value map |
| 0x010A | Encrypted Metadata | nonce(24B) \| AEAD(ciphertext+tag) |

### Footer Section TLVs

| Type | Name | Contents |
|------|------|----------|
| 0x0200 | Object Index | Object ID, type, offset, length, hash |
| 0x0201 | Object BLAKE3 | Per-object hashes |
| 0x0202 | Archive BLAKE3 | Whole-archive hash |

## Document Object Model

The DOM is independent of rendering. Core types:

- `Document` — root container with sections, styles, images, attachments, etc.
- `Section` — document section with heading and block content
- `Paragraph` — text runs with direction and heading level
- `TextRun` — span of UTF-8 text with a style
- `Table` — rows, cells, merged cells, column count
- `Style` — named style with parent inheritance
- `Image`, `Attachment`, `Hyperlink`, `Footnote` — embedded resources
- `CodeBlock`, `MathBlock` — structured content blocks
- `List`, `ListItem` — ordered/unordered lists with nesting

All text is UTF-8 and preserved exactly (no normalization).

## Validation

`Document::validate()` checks:
- Duplicate identifiers
- Broken references
- Circular style inheritance
- Excessive nesting depth (max 64)
- Invalid table dimensions (max 10,000 rows × 10,000 columns)
- Page/object/text limits

Validation never modifies the document.

## Security

- No automatic metadata collection
- No remote resource fetching
- Strict UTF-8 validation
- Bounded allocations based on `Limits`
- No panics on malformed input

## Limitations

- The Rust toolchain is not available in this sandbox, so compilation,
  `cargo fmt`, `cargo clippy -D warnings`, and `cargo test` are deferred.
- Per-object encryption is serialized but not yet exercised by tests.
- CLI integration for ZDOC commands is planned but not yet implemented.