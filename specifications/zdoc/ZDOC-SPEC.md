# ZDOC (.zdoc) Binary Format Specification — v1.0

**Status:** Normative specification  
**Format:** `.zdoc`  
**Container:** ZNF Core v1.0 (64-byte header, `FormatId::ZDOC`)  
**License:** Apache-2.0

---

## 1. Overview

ZDOC is a privacy-first, lossless-first document format built on the ZNF Core v1.0 binary foundation. A ZDOC file is a ZNF Core container whose `FormatId` is `ZDOC` (value `4`). It stores a structured document object model (DOM) using a TLV (Type-Length-Value) encoding for both the metadata section (between header and payload) and the footer section (after payload).

Design goals:
- **Lossless fidelity:** exact byte-for-byte round-trip of document text, styles, and embedded resources.
- **Security:** no automatic metadata collection, strict validation of untrusted input, bounded allocations, no remote resource fetching.
- **Composability:** reuses ZNF Core, `znf-compression`, `znf-crypto`, `znf-integrity`, and `znf-stream` without duplicating their implementations.
- **Forward compatibility:** unknown non-critical extensions are safely ignored; unknown critical extensions are rejected.

---

## 2. Container Structure

A ZDOC file uses the ZNF Core 64-byte header:

| Offset | Size | Field |
|--------|------|-------|
| 0      | 4    | Magic: `ZNF\0` (`[0x5A, 0x4E, 0x46, 0x00]`) |
| 4      | 4    | Format ID: `FormatId::ZDOC` = `4` (u32 LE) |
| 8      | 2    | Major version (u16 LE) — must be `1` |
| 10     | 2    | Minor version (u16 LE) — must be `0` |
| 12     | 8    | Feature flags (u64 LE) |
| 20     | 8    | Header length (u64 LE) — `>= 64` |
| 28     | 8    | Payload offset (u64 LE) — `>= header_len` |
| 36     | 8    | Payload length (u64 LE) |
| 44     | 4    | Header CRC-32 (u32 LE) — over bytes 0..44 and 48..64 |
| 48     | 1    | Compression ID — `0=None`, `1=Zstd`, `2=LZ4` |
| 49     | 1    | Encryption ID — `0=None`, `1=XChaCha20-Poly1305` |
| 50     | 14   | Reserved — must be all zero |

File layout (logical):

```
[ ZNF Core Header (64 bytes) ]
[ Metadata Section (TLVs)     ]  — present iff Flags::HAS_METADATA
[ Payload Section (document DOM serialized) ]
[ Footer Section (TLVs)       ]  — present iff Flags::HAS_FOOTER
```

The payload contains the serialized document DOM. The metadata section contains document-level TLV records (dimensions, title, author, etc.). The footer contains integrity hashes and the `TLV_END` marker.

---

## 3. Feature Flags

ZDOC uses the standard ZNF Core `ZnfFeatureFlags`:

| Bit | Flag | Meaning |
|-----|------|---------|
| 0   | `COMPRESSED` | Payload is compressed (compression ID != None) |
| 1   | `ENCRYPTED`  | Payload (and sensitive metadata/index) is AEAD-encrypted |
| 2   | `HAS_METADATA` | Metadata TLV section present between header and payload |
| 3   | `HAS_FOOTER`   | Footer TLV section present after payload |
| 4   | `STREAMING`    | Payload uses chunked/streamed framing |

Bits `5..=31` are reserved for future critical capabilities; readers must reject unknown critical bits. Bits `32..=47` are non-critical advisory; readers must ignore unknown bits. Bits `48..=63` are invalid; readers must reject.

---

## 4. Metadata Section TLVs

The metadata section (between header and payload) uses ZNF Core TLV encoding: `type: u16 LE` \| `length: u32 LE` \| `value: bytes`. The section is terminated by `TLV_END` (`type = 0xFFFF`, `length = 0`).

| TLV Type | Name | Value Format | Required |
|----------|------|--------------|----------|
| `0x0100` | `TLV_ZDOC_DOCUMENT_ID` | UUID (16 bytes) | Yes |
| `0x0101` | `TLV_ZDOC_TITLE` | UTF-8 string | No |
| `0x0102` | `TLV_ZDOC_SUBJECT` | UTF-8 string | No |
| `0x0103` | `TLV_ZDOC_AUTHOR` | UTF-8 string | No |
| `0x0104` | `TLV_ZDOC_CREATOR` | UTF-8 string (software) | No |
| `0x0105` | `TLV_ZDOC_CREATED` | RFC 3339 timestamp (UTF-8) | No |
| `0x0106` | `TLV_ZDOC_MODIFIED` | RFC 3339 timestamp (UTF-8) | No |
| `0x0107` | `TLV_ZDOC_LANGUAGE` | BCP-47 language tag (UTF-8) | No |
| `0x0108` | `TLV_ZDOC_STRUCTURE` | Document structure descriptor (see section 5) | Yes |
| `0x0109` | `TLV_ZDOC_METADATA_KV` | Structured key-value map (see section 6) | No |
| `0x010A` | `TLV_ZDOC_ENCRYPTED_METADATA` | nonce(24B) \| XChaCha20-Poly1305(ciphertext+tag, AAD=header) | No |
| `0x010B` | `TLV_KDF_PARAMS` | Argon2id parameters (28 bytes) | Required if encrypted |

The `TLV_ZDOC_STRUCTURE` value describes the document object model: version, page count, root object offset, and encoding hints. It is the entry point for decoding the payload.

---

## 5. Document Object Model (DOM)

ZDOC documents are modeled as a tree of objects:

```
Document
├── Sections[]
│   ├── Paragraphs[]
│   │   ├── TextRuns[]
│   │   │   ├── text: UTF-8
│   │   │   └── style: StyleRef
│   │   ├── style: StyleRef
│   │   └── direction: LTR/RTL/Auto
│   ├── Tables[]
│   │   ├── Rows[][]
│   │   │   └── Cells[]
│   │   │       └── content: Block[]
│   │   ├── style: StyleRef
│   │   └── merged_cells: [(row, col, rowspan, colspan)]
│   ├── Headers[] (running header content)
│   ├── Footers[] (running footer content)
│   └── style: StyleRef
├── Styles[]
│   ├── ParagraphStyle[]
│   ├── CharacterStyle[]
│   ├── TableStyle[]
│   └── ListStyle[]
├── Images[] (embedded, referenced by ID)
├── Attachments[] (embedded files, referenced by ID)
├── Hyperlinks[] (URI targets, referenced by ID)
├── Footnotes[] (referenced by ID)
├── CodeBlocks[]
├── MathBlocks[]
└── PageNumbering: style + start value
```

### 5.1 Text and Unicode

All text is UTF-8. The original byte sequence is preserved exactly. No normalization, NFC/NFD conversion, or case folding is applied to stored text. If normalization is needed for search indexing, it is performed on a separate index without modifying the document.

### 5.2 Style Inheritance

Styles form a hierarchy: `DocumentStyle` → `SectionStyle` → `ParagraphStyle` → `TextRunStyle`. A child inherits unresolved properties from its parent. Circular style inheritance is invalid and must be rejected.

### 5.3 Identifiers

Every top-level object (section, image, attachment, hyperlink, footnote, style) has a unique identifier within the document. Duplicate identifiers are invalid.

---

## 6. Structured Key-Value Metadata

`TLV_ZDOC_METADATA_KV` encodes a deterministic, sorted key-value map:

```
count: u16 LE
repeat count times:
    key_len: u16 LE
    key: UTF-8 bytes
    val_len: u16 LE
    val: UTF-8 bytes
```

Entries are sorted by key (byte-wise lexicographic) for deterministic output. Both keys and values must be valid UTF-8; invalid UTF-8 is rejected.

---

## 7. Footer Section TLVs

The footer section (after payload) is terminated by `TLV_END`.

| TLV Type | Name | Value Format | Required |
|----------|------|--------------|----------|
| `0x0200` | `TLV_ZDOC_OBJECT_INDEX` | Object index table (see section 8) | Yes |
| `0x0201` | `TLV_ZDOC_OBJECT_BLAKE3` | Per-object BLAKE3 hashes | Yes |
| `0x0202` | `TLV_ARCHIVE_BLAKE3` | Whole-archive BLAKE3 over header \| metadata \| payload | Yes |

---

## 8. Object Index

The object index enables random-access decoding. It consists of:

```
count: u32 LE
repeat count times:
    object_id: u32 LE
    object_type: u8 LE        (1=section, 2=paragraph, 3=table, 4=image, 5=attachment, ...)
    stored_offset: u64 LE     (offset within payload)
    stored_len: u32 LE        (compressed/encrypted size in bytes)
    uncompressed_len: u32 LE  (raw size in bytes)
    blake3_hash: [u8; 32]     (BLAKE3 of uncompressed object bytes)
```

Fixed entry size: `4 + 1 + 8 + 4 + 4 + 32 = 53 bytes`.

---

## 9. Compression

The payload is compressed using one algorithm for the entire payload, as indicated by the header compression ID:

| ID | Algorithm | Notes |
|----|-----------|-------|
| 0  | Stored    | No compression |
| 1  | Zstandard | Levels 1–22 (RFC 8878) |
| 2  | LZ4       | Bounded block framing |

The entire payload is compressed as a single unit. Decompression enforces `max_expanded_len` from `Limits` to prevent decompression bombs.

---

## 10. Encryption

When `Flags::ENCRYPTED` is set, the payload is encrypted with XChaCha20-Poly1305 using a key derived from a password via Argon2id. The `TLV_KDF_PARAMS` TLV in the metadata section stores the Argon2id parameters (salt, memory cost, time cost, parallelism).

Each top-level object may also be individually encrypted with a per-object nonce derived from a base nonce XORed with the object index. Metadata encryption uses `TLV_ZDOC_ENCRYPTED_METADATA` with AAD bound to the header bytes.

- Key: 256-bit
- Nonce: 192-bit (24 bytes)
- Tag: 128-bit (16 bytes)
- KDF: Argon2id v19

Nonces must never be reused with the same key. Authentication failure must never produce partially trusted output.

---

## 11. Integrity

BLAKE3 is used for integrity:

- **Per-object:** `TLV_ZDOC_OBJECT_BLAKE3` contains one BLAKE3 hash per object, over the uncompressed object bytes.
- **Whole-archive:** `TLV_ARCHIVE_BLAKE3` is BLAKE3 over `header \| metadata \| payload` (excluding footer).

BLAKE3 detects corruption but is not authentication; use AEAD (encryption) for authenticity.

---

## 12. Resource Limits

`Limits` (from `znf-core`) constrain parsing to prevent resource exhaustion:

| Limit | Default |
|-------|---------|
| `max_header_len` | 1 MiB |
| `max_metadata_len` | 16 MiB |
| `max_tlv_len` | 16 MiB |
| `max_payload_len` | u64::MAX |
| `max_expanded_len` | 10 GiB |

Additional ZDOC-specific limits:
- Maximum nesting depth: 64 (sections, lists, tables)
- Maximum page count: 100,000
- Maximum objects per document: 1,000,000
- Maximum text run length: 10 MiB
- Maximum table dimensions: 10,000 rows × 10,000 columns
- Maximum attachment size: 1 GiB

All arithmetic is overflow-checked. No unbounded allocations based on attacker-controlled values.

---

## 13. Error Handling

All parsing is strict. Malformed, corrupted, or unsupported input returns a typed error, never a panic. Errors include:

- `InvalidMagic`, `HeaderCrcMismatch`, `UnsupportedMajorVersion`
- `InvalidDimensions`, `MalformedStructure`, `InvalidUtf8`
- `DuplicateIdentifier`, `BrokenReference`, `CircularInheritance`
- `CompressionError`, `CryptoError`, `IntegrityError`
- `LengthExceedsLimit`, `ResourceLimitExceeded`

Error classifiers: `is_authentication_failure()`, `is_corruption()`, `is_unsupported()`.

---

## 14. Forward Compatibility

- Unknown **non-critical** TLV types in metadata/footer are ignored.
- Unknown **critical** TLV types cause rejection (`UnsupportedCriticalExtension`).
- New TLV types may be added in minor versions without breaking readers that skip unknown non-critical types.
- Major version changes may introduce breaking changes.

---

## 15. Security Considerations

- No automatic collection of device, location, or identity information.
- Metadata is optional and user-controlled.
- No remote resource fetching (images, fonts, stylesheets, hyperlinks).
- Imported HTML and external content are treated as untrusted; no script execution.
- Path traversal in attachments is rejected (`..`, leading `/`, drive prefixes, NUL bytes, reserved names).
- Symlink-related extraction risks are mitigated.
- Passwords are never logged, never in command-line arguments, never in error messages.

---

## 16. Version

`ZDOC_SPEC_VERSION = (1, 0)`.

The format version is independent of the ZNF Core version. A ZDOC v1.0 document uses ZNF Core v1.0 header.