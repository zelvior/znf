# ZDOC Security Considerations

## Threat Model

ZDOC is designed to process untrusted documents safely. The primary threats are:

1. **Malformed binary input** — truncated headers, invalid offsets, oversized lengths
2. **Decompression bombs** — small compressed data expanding to huge output
3. **Resource exhaustion** — excessive nesting, object counts, or text lengths
4. **Integer overflow** — in offset/length arithmetic
5. **Path traversal** — in attachment file names
6. **Authentication bypass** — wrong password or tampered ciphertext

## Security Properties

### Input Validation

All parsing is strict and bounded:

- Every header, field, offset, length, chunk, and reference is validated before use.
- Integer overflow is rejected using checked arithmetic.
- Out-of-bounds reads and writes are prevented by bounds checks before every slice operation.
- Maximum nesting depth is enforced (64 levels).
- Document size, page count (100,000), object count (1,000,000), text length (10 MiB per run),
  table dimensions (10,000 × 10,000), and attachment size (1 GiB) are limited.
- No unbounded allocations based on attacker-controlled values.

### No Panics on Malformed Input

All parser functions return `Result<_, ZdocError>`. No `unwrap()`, `expect()`, or
indexing without bounds checks is used in parsing paths.

### Structured Errors

`ZdocError` provides classifiers:

- `is_authentication_failure()` — AEAD authentication failure
- `is_corruption()` — data corruption (BLAKE3 mismatch, CRC failure, compress corrupt data)
- `is_unsupported()` — unsupported version, object type, or critical extension

### Encryption

- XChaCha20-Poly1305 AEAD with 256-bit keys, 192-bit nonces, 128-bit tags.
- Argon2id v19 KDF with DoS bounds (memory 8 KiB–1 GiB, time 1–32, parallelism 1–64).
- Nonces are randomly generated per encryption operation; never reused with the same key.
- Metadata encryption uses header bytes as AAD, binding metadata to the document structure.
- Failed authentication never produces partially trusted output.
- Passwords are never logged, never appear in command-line arguments or error messages.

### Integrity

- BLAKE3 per-object hashes detect corruption of individual objects.
- Whole-archive BLAKE3 (`header || metadata || payload`) detects file-level tampering.
- BLAKE3 is a checksum, not authentication; use encryption for authenticity.

### Metadata Privacy

- Metadata is optional and user-controlled; nothing is collected automatically.
- Document author, creator, timestamps, and custom properties are only stored if explicitly provided.
- Export operations do not leak local file paths.
- Metadata sanitization (removal) is an explicit operation that does not modify document content.

### Rendering Safety

- The DOM is independent of rendering.
- No embedded scripts or macros are executed.
- No remote images, fonts, stylesheets, or hyperlinks are automatically fetched.
- Imported HTML and external content are treated as untrusted.