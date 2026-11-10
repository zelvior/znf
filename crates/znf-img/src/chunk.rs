//! Chunked pixel data storage for ZIMG.
//!
//! Pixel data is divided into independently compressed chunks (rows or tiles)
//! to allow bounded memory usage and random-access decoding.

use znf_integrity::{Hash, HASH_LEN};

/// A single compressed chunk of pixel data.
#[derive(Debug, Clone)]
pub struct Chunk {
    /// Logical chunk index (0-based).
    pub index: u32,
    /// Uncompressed byte offset within the full pixel buffer.
    pub uncompressed_offset: u64,
    /// Stored byte offset within the payload section.
    pub stored_offset: u64,
    /// Uncompressed length in bytes.
    pub uncompressed_len: u32,
    /// Stored (compressed/encrypted) length in bytes.
    pub stored_len: u32,
    /// BLAKE3 hash of the uncompressed pixel data.
    pub blake3_hash: Hash,
}

impl Chunk {
    /// Encode into the 60-byte wire format.
    #[must_use]
    pub fn to_wire_bytes(&self) -> [u8; super::format::CHUNK_INDEX_ENTRY_LEN] {
        let mut out = [0u8; super::format::CHUNK_INDEX_ENTRY_LEN];
        out[0..4].copy_from_slice(&self.index.to_le_bytes());
        out[4..12].copy_from_slice(&self.uncompressed_offset.to_le_bytes());
        out[12..20].copy_from_slice(&self.stored_offset.to_le_bytes());
        out[20..24].copy_from_slice(&self.uncompressed_len.to_le_bytes());
        out[24..28].copy_from_slice(&self.stored_len.to_le_bytes());
        out[28..60].copy_from_slice(self.blake3_hash.as_bytes());
        out
    }

    /// Decode from 60-byte wire format.
    #[must_use]
    pub fn from_wire_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < super::format::CHUNK_INDEX_ENTRY_LEN {
            return None;
        }
        Some(Chunk {
            index: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            uncompressed_offset: u64::from_le_bytes(bytes[4..12].try_into().unwrap()),
            stored_offset: u64::from_le_bytes(bytes[12..20].try_into().unwrap()),
            uncompressed_len: u32::from_le_bytes(bytes[20..24].try_into().unwrap()),
            stored_len: u32::from_le_bytes(bytes[24..28].try_into().unwrap()),
            blake3_hash: Hash::from_bytes(bytes[28..60].try_into().unwrap()),
        })
    }
}

/// Chunking strategy: how pixel data is divided into chunks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkStrategy {
    /// Each row is a separate chunk (scanline-based).
    Scanline,
    /// Fixed-size chunks of `max_uncompressed` bytes.
    Fixed { max_uncompressed: usize },
}

impl Default for ChunkStrategy {
    fn default() -> Self {
        ChunkStrategy::Fixed {
            max_uncompressed: super::format::DEFAULT_CHUNK_UNCOMPRESSED_MAX,
        }
    }
}

/// Compute chunk boundaries for an image buffer.
pub fn compute_chunks(
    width: u32,
    height: u32,
    bytes_per_pixel: usize,
    stride: usize,
    strategy: ChunkStrategy,
) -> Vec<(u32, u64, u32)> {
    // Returns (row_start, uncompressed_offset, row_count) for each chunk.
    let mut chunks = Vec::new();
    let bpp = bytes_per_pixel;
    let row_bytes = width as usize * bpp;

    match strategy {
        ChunkStrategy::Scanline => {
            for y in 0..height {
                chunks.push((y, (y as u64) * stride as u64, 1));
            }
        }
        ChunkStrategy::Fixed { max_uncompressed } => {
            let mut remaining_rows = height;
            let mut y = 0u32;
            while remaining_rows > 0 {
                // How many rows fit in max_uncompressed bytes?
                let rows_in_chunk = (max_uncompressed / row_bytes).max(1);
                let rows_this_chunk = rows_in_chunk.min(remaining_rows as usize);
                chunks.push((y, (y as u64) * stride as u64, rows_this_chunk as u32));
                y += rows_this_chunk as u32;
                remaining_rows -= rows_this_chunk as u32;
            }
        }
    }
    chunks
}
