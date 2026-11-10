# Forward & Backward Compatibility Test Suite

Compatibility rules for ZNF Core v1.0 and ZARC v1.0 are verified in `crates/znf-zarc/tests/security_and_vectors.rs` and `crates/znf-core/src/header.rs`:

1. **Higher Minor Versions Accepted:** Readers supporting major version `1` accept `1.x` archives (e.g., `1.5`) when unknown non-critical TLVs are present.
2. **Higher Major Versions Rejected:** Readers reject major version `!= 1` with `Error::UnsupportedMajorVersion`.
3. **Unknown Flag Bits Ignored on Read:** Readers ignore reserved flag bits (`bits 5..63`) for forward compatibility, while writers forbid setting undefined flag bits.
4. **Unknown Standard and Vendor TLVs Skipped:** Unrecognized TLV types in metadata and footer sections are skipped cleanly after validating their length bounds.
