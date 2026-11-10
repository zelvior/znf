# Security & Adversarial Input Test Suite

Adversarial input and hardening tests live in `crates/znf-zarc/tests/security_and_vectors.rs` and crate unit tests:

- `every_truncation_offset_fails_without_panic`: Truncates a valid `.zarc` archive at every byte offset `0..len` and verifies that `ZarcArchive::open` + `verify_all` always returns `Err` without panicking.
- `tampered_index_path_traversal_rejected_on_open`: Injects `../` into raw index bytes and verifies rejection before extraction.
- `extraction_refuses_symlink_traversal`: Verifies `extract_to` refuses to follow symlinked subdirectories outside the destination root.
- `decompression_bomb_and_ratio_limits_enforced`: Verifies both `max_compression_ratio` and `max_expanded_len` stop decompression bombs.
- `header_tampering_detected_by_aead_aad`: Modifies header fields and recomputes header CRC-32 to prove `XChaCha20-Poly1305` AAD binding catches header tampering.
