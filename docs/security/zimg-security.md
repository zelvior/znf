# ZIMG (.zimg) Security Architecture

## 1. Threat Model

All `.zimg` inputs are treated as **untrusted and potentially adversarial**:

1. **Dimension bombs:** Declaring huge width/height to exhaust memory during allocation.
2. **Decompression bombs:** Extreme compression ratios to exhaust RAM after decompression.
3. **Malformed chunks:** Invalid chunk boundaries, offsets, or lengths causing out-of-bounds access.
4. **Integer overflow:** Width × height × bytes_per_pixel overflowing allocation size.
5. **Header tampering:** Modifying format ID, version, flags, or section offsets.
6. **Payload corruption:** Bit flips in compressed or encrypted data.
7. **Authentication bypass:** Wrong password or tampered AEAD tags.
8. **KDF DoS:** Extreme Argon2id parameters from untrusted files.
9. **Metadata leakage:** Sensitive information stored in metadata TLVs.

## 2. Cryptographic Guarantees

| Property | Mechanism |
|---|---|
| Confidentiality | XChaCha20-Poly1305 (256-bit key, 192-bit nonce, 128-bit tag) |
| Authenticity | AEAD tag verification before plaintext release |
| Key derivation | Argon2id v19 with bounded parameters |
| Per-chunk integrity | BLAKE3 over uncompressed chunk data |
| Whole-file integrity | BLAKE3 over header + metadata + payload |
| Header binding | 64-byte header bound as AAD for encrypted metadata |
| Index structure | Chunk index unencrypted (reveals structure, not pixels) |
| Key zeroization | `SecretKey` zeroized on drop via `zeroize::Zeroize` |

**No custom cryptography:** Uses `chacha20poly1305`, `argon2`, `blake3`,
and OS CSPRNG (`getrandom`).

## 3. KDF Parameter Bounds

Enforced by `KdfParams::validate()`:

| Parameter | Min | Max |
|-----------|-----|-----|
| `m_cost_kib` | 8 MiB | 1 GiB |
| `t_cost` | 1 | 32 |
| `p_cost` | 1 | 64 |

## 4. Dimension & Allocation Defenses

- Width and height each capped at 1,000,000 pixels.
- Total pixels capped at 256,000,000.
- Stride = width × bytes_per_pixel computed with `checked_mul`.
- Total buffer = stride × height computed with `checked_mul`.
- Any overflow → `ZimgError::InvalidDimensions` before allocation.
- Decompressed output capped at `Limits::max_expanded_len`.

## 5. Chunk Boundary Validation

- Each chunk's `stored_offset + stored_len` must be within payload bounds.
- Each chunk's `uncompressed_offset + uncompressed_len` must be within pixel buffer bounds.
- Chunk stored data length must accommodate nonce(24B) + tag(16B) minimum when encrypted.
- Filter byte (first byte of each filtered row) must be 0-4.

## 6. Encryption Details

- Each chunk gets a fresh 24-byte random nonce from OS CSPRNG.
- Nonce reuse across chunks is prevented by random generation (24-byte space makes
  collision probability negligible).
- AAD for chunk encryption: chunk index as 8-byte LE (binds chunk to its position).
- AAD for metadata encryption: 64-byte header bytes.
- Decryption failure returns `AuthenticationFailed` (opaque, no oracle leakage).
- No plaintext is released on authentication failure.

## 7. Metadata Privacy

- All metadata fields are optional.
- No device, location, or identity information is automatically collected.
- No telemetry or tracking identifiers.
- `znf image metadata --remove` produces a clean image without metadata.
- Encrypted metadata option hides title/description/etc. from cleartext inspection.

## 8. Information Leakage Boundaries

Even with encryption enabled, the following are visible in cleartext:

- Image dimensions (width, height)
- Pixel format (color model, bit depth, channel count, alpha)
- Compression algorithm and level
- Chunk count and chunk stored sizes
- Archive structure (header, metadata, payload, footer offsets)
- Archive BLAKE3 digest

Pixel data and metadata values are confidential when encrypted.

## 9. Error Classification

`ZimgError` provides:

- `is_authentication_failure()` — AEAD or password failure
- `is_corruption()` — CRC-32, BLAKE3, or compression corruption
- `is_unsupported()` — Unknown format, version, or critical extension

## 10. Atomic Writes

The CLI writes output files directly. For atomic replacement, applications
should write to a temp file and rename, similar to `ZarcArchive::finish_to_path`.

## 11. Residual Risks

- **Compression side channels:** Compressed size may leak information about
  pixel content. No padding is applied.
- **Structure leakage:** Chunk count and sizes reveal image complexity.
- **No digital signatures:** Integrity is corruption detection, not publisher authentication.
- **Sidecar files:** CLI uses `.meta` sidecars for pixel format info; these are
  separate files and must be managed alongside the `.zimg`.
