# Canonical Binary Test Vectors

Automated binary test vectors are verified in:

1. **IEEE 802.3 CRC-32 (`crates/znf-core/src/lib.rs`):**
   - Input: `"123456789"`
   - Expected: `0xCBF43926`
2. **BLAKE3 Empty Vector (`crates/znf-integrity/src/lib.rs`):**
   - Input: `""`
   - Expected: `af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262`
3. **ZNF Core v1.0 64-Byte Header (`crates/znf-core/tests/core_engine_tests.rs` — `canonical_core_header_hex_vector`):**
   - Parameters: `FormatId::CORE (2)`, `v1.0`, `Flags = COMPRESSED | HAS_FOOTER (0x09)`, `header_len = 64`, `payload_offset = 64`, `payload_len = 128`, `compression = Zstd (1)`, `encryption = None (0)`.
   - Expected 64-byte hex:
     `5a4e460002000000010000000900000000000000400000000000000040000000000000008000000000000000cd4965cd01000000000000000000000000000000`
4. **ZARC v1.0 64-Byte Header (`crates/znf-zarc/tests/security_and_vectors.rs` — `deterministic_core_header_vector`):**
   - Parameters: `FormatId::ZARC (1)`, `v1.0`, `Flags = COMPRESSED | HAS_FOOTER (0x09)`, `header_len = 64`, `payload_offset = 64`, `payload_len = 512`.
5. **Independent Manual Container Construction (`crates/znf-core/tests/core_engine_tests.rs` — `independent_manual_encode_decoded_by_znf_reader_and_vice_versa`):**
   - Verifies byte-for-byte identity between manual specification-driven construction and `ZnfWriter::write_to_vec`.
