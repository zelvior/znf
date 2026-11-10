//! ZNF Recovery: block-level XOR parity and corruption scanning.
//!
//! Provides two concrete, bounded-memory primitives for archive resilience:
//!
//! 1. **Block XOR Parity (`ParityBlock`)**: divides a byte stream into fixed-size
//!    data stripes and computes a parity block (`P = B_0 ^ B_1 ^ ... ^ B_{k-1}`)
//!    plus per-block CRC-32 checksums. If exactly one block in a stripe fails its
//!    CRC check, it can be reconstructed deterministically from the remaining
//!    blocks and `P`.
//! 2. **Header Magic Scanner (`scan_for_headers`)**: scans a potentially damaged
//!    byte slice for candidate ZNF Core headers (`ZNF\0` magic + valid header
//!    CRC-32) to locate surviving records.
//!
//! Reed-Solomon multi-erasure coding is planned for a future version and is
//! documented as such in `specifications/`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::all)]

use thiserror::Error;
use znf_core::{crc32, Header, Limits, HEADER_LEN, MAGIC};

/// Default recovery block size (4 KiB).
pub const DEFAULT_BLOCK_SIZE: usize = 4096;

/// Errors from recovery operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RecoveryError {
    /// Block size must be non-zero and at most 1 MiB.
    #[error("invalid block size: {0}")]
    InvalidBlockSize(usize),

    /// More than one block in a stripe is corrupted; single-parity cannot recover.
    #[error("unrecoverable stripe: {corrupted_count} blocks corrupted (max recoverable is 1)")]
    TooManyCorruptedBlocks {
        /// Number of bad blocks in the stripe.
        corrupted_count: usize,
    },

    /// Parity block itself is corrupted or length-mismatched.
    #[error("invalid parity data: {0}")]
    InvalidParity(String),
}

/// Parity record for a stripe of fixed-size data blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParityStripe {
    /// Block size in bytes.
    pub block_size: u32,
    /// Total original data length in bytes (last block may be zero-padded).
    pub data_len: u64,
    /// CRC-32 of each padded data block.
    pub block_crcs: Vec<u32>,
    /// CRC-32 of the parity block.
    pub parity_crc: u32,
    /// XOR parity block (`block_size` bytes).
    pub parity: Vec<u8>,
}

impl ParityStripe {
    /// Compute parity over `data` using `block_size`-byte blocks.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::InvalidBlockSize`] if `block_size == 0` or `> 1 MiB`.
    pub fn compute(data: &[u8], block_size: usize) -> Result<Self, RecoveryError> {
        if block_size == 0 || block_size > 1024 * 1024 {
            return Err(RecoveryError::InvalidBlockSize(block_size));
        }
        let mut parity = vec![0u8; block_size];
        let mut block_crcs = Vec::new();
        let mut scratch = vec![0u8; block_size];

        for chunk in data.chunks(block_size) {
            scratch.fill(0);
            scratch[..chunk.len()].copy_from_slice(chunk);
            block_crcs.push(crc32(&scratch));
            for (p, &b) in parity.iter_mut().zip(scratch.iter()) {
                *p ^= b;
            }
        }
        let parity_crc = crc32(&parity);
        Ok(ParityStripe {
            block_size: block_size as u32,
            data_len: data.len() as u64,
            block_crcs,
            parity_crc,
            parity,
        })
    }

    /// Encode this parity record into deterministic little-endian bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(20 + self.block_crcs.len() * 4 + self.parity.len());
        out.extend_from_slice(&self.block_size.to_le_bytes());
        out.extend_from_slice(&self.data_len.to_le_bytes());
        out.extend_from_slice(&(self.block_crcs.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.parity_crc.to_le_bytes());
        for &c in &self.block_crcs {
            out.extend_from_slice(&c.to_le_bytes());
        }
        out.extend_from_slice(&self.parity);
        out
    }

    /// Decode a parity record from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError`] if truncated or inconsistent.
    pub fn decode(buf: &[u8]) -> Result<Self, RecoveryError> {
        if buf.len() < 20 {
            return Err(RecoveryError::InvalidParity("too short".into()));
        }
        let block_size = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        if block_size == 0 || block_size > 1024 * 1024 {
            return Err(RecoveryError::InvalidBlockSize(block_size as usize));
        }
        let data_len = u64::from_le_bytes(buf[4..12].try_into().unwrap());
        let count = u32::from_le_bytes(buf[12..16].try_into().unwrap()) as usize;
        if count > 1_000_000 {
            return Err(RecoveryError::InvalidParity("block count too large".into()));
        }
        let parity_crc = u32::from_le_bytes(buf[16..20].try_into().unwrap());
        let needed = 20usize
            .checked_add(
                count
                    .checked_mul(4)
                    .ok_or_else(|| RecoveryError::InvalidParity("count overflow".into()))?,
            )
            .and_then(|v| v.checked_add(block_size as usize))
            .ok_or_else(|| RecoveryError::InvalidParity("length overflow".into()))?;
        if buf.len() < needed {
            return Err(RecoveryError::InvalidParity(
                "truncated parity record".into(),
            ));
        }
        let mut block_crcs = Vec::with_capacity(count);
        for i in 0..count {
            let off = 20 + i * 4;
            block_crcs.push(u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()));
        }
        let p_off = 20 + count * 4;
        let parity = buf[p_off..p_off + block_size as usize].to_vec();
        if crc32(&parity) != parity_crc {
            return Err(RecoveryError::InvalidParity("parity CRC mismatch".into()));
        }
        Ok(ParityStripe {
            block_size,
            data_len,
            block_crcs,
            parity_crc,
            parity,
        })
    }

    /// Verify `data` against block CRCs and repair in place if at most one
    /// block is damaged. Returns the number of repaired blocks (`0` or `1`).
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError`] if more than one block is damaged or the
    /// parity block itself is corrupt.
    pub fn verify_and_repair(&self, data: &mut [u8]) -> Result<usize, RecoveryError> {
        let bs = self.block_size as usize;
        if data.len() as u64 != self.data_len {
            return Err(RecoveryError::InvalidParity("data length mismatch".into()));
        }
        if crc32(&self.parity) != self.parity_crc {
            return Err(RecoveryError::InvalidParity(
                "parity block corrupted".into(),
            ));
        }

        let mut bad_indices = Vec::new();
        let mut scratch = vec![0u8; bs];
        for (idx, chunk) in data.chunks(bs).enumerate() {
            let expected = *self
                .block_crcs
                .get(idx)
                .ok_or_else(|| RecoveryError::InvalidParity("block count mismatch".into()))?;
            scratch.fill(0);
            scratch[..chunk.len()].copy_from_slice(chunk);
            if crc32(&scratch) != expected {
                bad_indices.push(idx);
            }
        }

        if bad_indices.is_empty() {
            return Ok(0);
        }
        if bad_indices.len() > 1 {
            return Err(RecoveryError::TooManyCorruptedBlocks {
                corrupted_count: bad_indices.len(),
            });
        }

        let bad_idx = bad_indices[0];
        let mut recovered = self.parity.clone();
        for (idx, chunk) in data.chunks(bs).enumerate() {
            if idx == bad_idx {
                continue;
            }
            scratch.fill(0);
            scratch[..chunk.len()].copy_from_slice(chunk);
            for (r, &b) in recovered.iter_mut().zip(scratch.iter()) {
                *r ^= b;
            }
        }
        if crc32(&recovered) != self.block_crcs[bad_idx] {
            return Err(RecoveryError::InvalidParity(
                "reconstructed block failed CRC check".into(),
            ));
        }

        let start = bad_idx * bs;
        let end = (start + bs).min(data.len());
        data[start..end].copy_from_slice(&recovered[..(end - start)]);
        Ok(1)
    }
}

/// Scan `buf` for byte offsets that contain a valid ZNF Core header
/// (matching `ZNF\0` magic and passing header CRC-32 + limits validation).
#[must_use]
pub fn scan_for_headers(buf: &[u8], limits: &Limits) -> Vec<(usize, Header)> {
    let mut found = Vec::new();
    if buf.len() < HEADER_LEN {
        return found;
    }
    for offset in 0..=(buf.len() - HEADER_LEN) {
        if buf[offset..offset + 4] == MAGIC {
            if let Ok(hdr) = Header::decode(&buf[offset..], limits, None) {
                found.push((offset, hdr));
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use znf_core::FormatId;

    #[test]
    fn single_block_corruption_repaired() {
        let original: Vec<u8> = (0..10_000).map(|i| (i % 251) as u8).collect();
        let stripe = ParityStripe::compute(&original, 1024).unwrap();
        let encoded = stripe.encode();
        let decoded = ParityStripe::decode(&encoded).unwrap();

        let mut damaged = original.clone();
        // Corrupt bytes inside block 3.
        damaged[3100] ^= 0xFF;
        damaged[3500] ^= 0xAA;

        let repaired = decoded.verify_and_repair(&mut damaged).unwrap();
        assert_eq!(repaired, 1);
        assert_eq!(damaged, original);
    }

    #[test]
    fn two_block_corruption_fails_cleanly() {
        let original = vec![42u8; 4096];
        let stripe = ParityStripe::compute(&original, 1024).unwrap();
        let mut damaged = original;
        damaged[10] ^= 1;
        damaged[2000] ^= 1;
        assert!(matches!(
            stripe.verify_and_repair(&mut damaged),
            Err(RecoveryError::TooManyCorruptedBlocks { corrupted_count: 2 })
        ));
    }

    #[test]
    fn scans_embedded_header() {
        let hdr = Header::new(FormatId::ZARC, 1, 0);
        let mut hbuf = [0u8; HEADER_LEN];
        hdr.encode(&mut hbuf).unwrap();

        let mut stream = vec![0xFFu8; 50];
        stream.extend_from_slice(&hbuf);
        stream.extend_from_slice(&[0u8; 20]);

        let hits = scan_for_headers(&stream, &Limits::default());
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, 50);
        assert_eq!(hits[0].1, hdr);
    }
}
