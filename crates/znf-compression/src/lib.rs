//! ZNF Compression: lossless streaming compression.
//!
//! Supported algorithms (all lossless, exact byte-for-byte restore):
//!
//! - **Stored** (`None`): no compression, zero overhead beyond framing.
//! - **Zstandard** (`Zstd`): high-ratio, configurable level (1-22).
//! - **LZ4** (`Lz4`): fast, pure-Rust implementation (`lz4_flex`).
//!
//! Lossy compression is never used in ZNF Core or ZARC.
//!
//! All decompression enforces an expanded-size limit to prevent
//! decompression bombs. Streaming APIs use bounded memory.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::all)]

use std::io::{Read, Write};
use thiserror::Error;

/// Compression algorithm identifier (stored in ZARC entry flags).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Algorithm {
    /// No compression (stored).
    None = 0,
    /// Zstandard.
    Zstd = 1,
    /// LZ4 (frame format via `lz4_flex`).
    Lz4 = 2,
}

impl Algorithm {
    /// Parse from stored byte.
    ///
    /// # Errors
    ///
    /// Returns [`CompressionError::UnknownAlgorithm`] for unknown values.
    pub fn from_byte(b: u8) -> Result<Self, CompressionError> {
        match b {
            0 => Ok(Algorithm::None),
            1 => Ok(Algorithm::Zstd),
            2 => Ok(Algorithm::Lz4),
            _ => Err(CompressionError::UnknownAlgorithm(b)),
        }
    }

    /// Stored byte value.
    #[must_use]
    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Compression configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// Algorithm to use.
    pub algorithm: Algorithm,
    /// Zstandard level (1-22; ignored for other algorithms).
    /// Higher is slower with better ratio. Default: 3.
    pub zstd_level: i32,
    /// Maximum expanded (decompressed) size in bytes.
    /// Enforced on decompression to prevent bombs.
    pub max_expanded_len: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            algorithm: Algorithm::Zstd,
            zstd_level: 3,
            max_expanded_len: 10 * 1024 * 1024 * 1024, // 10 GiB
        }
    }
}

impl Config {
    /// Stored (no compression) config.
    #[must_use]
    pub fn stored() -> Self {
        Config {
            algorithm: Algorithm::None,
            ..Config::default()
        }
    }

    /// Zstandard config at the given level (clamped to 1-22).
    #[must_use]
    pub fn zstd(level: i32) -> Self {
        Config {
            algorithm: Algorithm::Zstd,
            zstd_level: level.clamp(1, 22),
            ..Config::default()
        }
    }

    /// LZ4 config.
    #[must_use]
    pub fn lz4() -> Self {
        Config {
            algorithm: Algorithm::Lz4,
            ..Config::default()
        }
    }
}

/// Errors from compression operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CompressionError {
    /// Unknown algorithm byte.
    #[error("unknown compression algorithm: {0}")]
    UnknownAlgorithm(u8),

    /// Decompressed size exceeds the configured limit.
    #[error("decompressed size exceeds limit {limit} (got {got})")]
    ExpandedSizeExceedsLimit {
        /// Configured limit.
        limit: u64,
        /// Size observed (or declared).
        got: u64,
    },

    /// Corrupt compressed data.
    #[error("corrupt compressed data: {0}")]
    CorruptData(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(String),
}

impl From<std::io::Error> for CompressionError {
    fn from(e: std::io::Error) -> Self {
        CompressionError::Io(e.to_string())
    }
}

fn read_exact_lz4<R: Read>(reader: &mut R, mut buf: &mut [u8]) -> Result<(), CompressionError> {
    while !buf.is_empty() {
        match reader.read(buf) {
            Ok(0) => {
                return Err(CompressionError::CorruptData(
                    "unexpected EOF in lz4 stream".into(),
                ))
            }
            Ok(n) => buf = &mut buf[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(CompressionError::Io(e.to_string())),
        }
    }
    Ok(())
}

/// Compress all bytes from `input` into `output` (streaming, bounded memory).
///
/// # Errors
///
/// Returns [`CompressionError`] on I/O failure or corrupt input.
pub fn compress<R: Read, W: Write>(
    mut input: R,
    mut output: W,
    config: &Config,
) -> Result<u64, CompressionError> {
    match config.algorithm {
        Algorithm::None => {
            let mut buf = [0u8; 8192];
            let mut total: u64 = 0;
            loop {
                let n = input.read(&mut buf).map_err(CompressionError::from)?;
                if n == 0 {
                    break;
                }
                output
                    .write_all(&buf[..n])
                    .map_err(CompressionError::from)?;
                total += n as u64;
            }
            Ok(total)
        }
        Algorithm::Zstd => {
            let mut encoder = zstd::Encoder::new(output, config.zstd_level)
                .map_err(|e| CompressionError::CorruptData(format!("zstd encoder: {e}")))?;
            let mut buf = [0u8; 8192];
            let mut total: u64 = 0;
            loop {
                let n = input.read(&mut buf).map_err(CompressionError::from)?;
                if n == 0 {
                    break;
                }
                encoder
                    .write_all(&buf[..n])
                    .map_err(CompressionError::from)?;
                total += n as u64;
            }
            encoder
                .finish()
                .map_err(|e| CompressionError::CorruptData(format!("zstd finish: {e}")))?;
            Ok(total)
        }
        Algorithm::Lz4 => {
            // Bounded 64 KiB block-framed LZ4 stream:
            //   repeated: uncomp_len (u32 LE) | comp_len (u32 LE) | compressed_block
            //   terminated by: 0u32 LE
            const LZ4_BLOCK_MAX: usize = 64 * 1024;
            let mut buf = [0u8; LZ4_BLOCK_MAX];
            let mut total: u64 = 0;
            loop {
                let n = input.read(&mut buf).map_err(CompressionError::from)?;
                if n == 0 {
                    break;
                }
                let compressed = lz4_flex::block::compress(&buf[..n]);
                let u_len = n as u32;
                let c_len = compressed.len() as u32;
                output
                    .write_all(&u_len.to_le_bytes())
                    .map_err(CompressionError::from)?;
                output
                    .write_all(&c_len.to_le_bytes())
                    .map_err(CompressionError::from)?;
                output
                    .write_all(&compressed)
                    .map_err(CompressionError::from)?;
                total += n as u64;
            }
            output
                .write_all(&0u32.to_le_bytes())
                .map_err(CompressionError::from)?;
            Ok(total)
        }
    }
}

/// Decompress all bytes from `input` into `output`, enforcing the
/// expanded-size limit.
///
/// # Errors
///
/// Returns [`CompressionError`] on corrupt data, I/O failure, or
/// if the expanded size exceeds `config.max_expanded_len`.
pub fn decompress<R: Read, W: Write>(
    mut input: R,
    mut output: W,
    algorithm: Algorithm,
    config: &Config,
) -> Result<u64, CompressionError> {
    match algorithm {
        Algorithm::None => {
            let mut buf = [0u8; 8192];
            let mut total: u64 = 0;
            loop {
                let n = input.read(&mut buf).map_err(CompressionError::from)?;
                if n == 0 {
                    break;
                }
                total += n as u64;
                if total > config.max_expanded_len {
                    return Err(CompressionError::ExpandedSizeExceedsLimit {
                        limit: config.max_expanded_len,
                        got: total,
                    });
                }
                output
                    .write_all(&buf[..n])
                    .map_err(CompressionError::from)?;
            }
            Ok(total)
        }
        Algorithm::Zstd => {
            let mut decoder = zstd::Decoder::new(input)
                .map_err(|e| CompressionError::CorruptData(format!("zstd decoder: {e}")))?;
            let mut buf = [0u8; 8192];
            let mut total: u64 = 0;
            loop {
                let n = decoder
                    .read(&mut buf)
                    .map_err(|e| CompressionError::CorruptData(format!("zstd read: {e}")))?;
                if n == 0 {
                    break;
                }
                total += n as u64;
                if total > config.max_expanded_len {
                    return Err(CompressionError::ExpandedSizeExceedsLimit {
                        limit: config.max_expanded_len,
                        got: total,
                    });
                }
                output
                    .write_all(&buf[..n])
                    .map_err(CompressionError::from)?;
            }
            Ok(total)
        }
        Algorithm::Lz4 => {
            const LZ4_BLOCK_MAX: usize = 1024 * 1024; // 1 MiB max block
            let mut total: u64 = 0;
            let mut c_buf = Vec::new();
            loop {
                let mut u_bytes = [0u8; 4];
                read_exact_lz4(&mut input, &mut u_bytes)?;
                let u_len = u32::from_le_bytes(u_bytes) as usize;
                if u_len == 0 {
                    break;
                }
                if u_len > LZ4_BLOCK_MAX {
                    return Err(CompressionError::CorruptData(format!(
                        "lz4 block uncompressed size {u_len} exceeds max {LZ4_BLOCK_MAX}"
                    )));
                }
                total = total.saturating_add(u_len as u64);
                if total > config.max_expanded_len {
                    return Err(CompressionError::ExpandedSizeExceedsLimit {
                        limit: config.max_expanded_len,
                        got: total,
                    });
                }
                let mut c_bytes = [0u8; 4];
                read_exact_lz4(&mut input, &mut c_bytes)?;
                let c_len = u32::from_le_bytes(c_bytes) as usize;
                if c_len == 0 || c_len > LZ4_BLOCK_MAX * 2 {
                    return Err(CompressionError::CorruptData(format!(
                        "lz4 block compressed size {c_len} invalid"
                    )));
                }
                c_buf.resize(c_len, 0);
                read_exact_lz4(&mut input, &mut c_buf)?;
                let decompressed = lz4_flex::block::decompress(&c_buf, u_len).map_err(|e| {
                    CompressionError::CorruptData(format!("lz4 block decompress: {e}"))
                })?;
                if decompressed.len() != u_len {
                    return Err(CompressionError::CorruptData(
                        "lz4 block size mismatch".into(),
                    ));
                }
                output
                    .write_all(&decompressed)
                    .map_err(CompressionError::from)?;
            }
            Ok(total)
        }
    }
}

/// One-shot compress (for small buffers; prefer streaming for large data).
///
/// # Errors
///
/// Returns [`CompressionError`] on failure.
pub fn compress_bytes(data: &[u8], config: &Config) -> Result<Vec<u8>, CompressionError> {
    let mut out = Vec::new();
    compress(data, &mut out, config)?;
    Ok(out)
}

/// One-shot decompress (for small buffers).
///
/// # Errors
///
/// Returns [`CompressionError`] on failure.
pub fn decompress_bytes(
    data: &[u8],
    algorithm: Algorithm,
    config: &Config,
) -> Result<Vec<u8>, CompressionError> {
    let mut out = Vec::new();
    decompress(data, &mut out, algorithm, config)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(algo: Algorithm, data: &[u8]) {
        let cfg = Config {
            algorithm: algo,
            ..Config::default()
        };
        let compressed = compress_bytes(data, &cfg).unwrap();
        let decompressed = decompress_bytes(&compressed, algo, &cfg).unwrap();
        assert_eq!(decompressed, data, "roundtrip failed for {algo:?}");
    }

    #[test]
    fn stored_roundtrip() {
        roundtrip(Algorithm::None, b"hello world");
        roundtrip(Algorithm::None, b"");
    }

    #[test]
    fn zstd_roundtrip() {
        roundtrip(Algorithm::Zstd, b"hello world, hello world, hello world");
        roundtrip(Algorithm::Zstd, b"");
        // Larger repetitive data compresses well.
        let data = vec![b'A'; 100_000];
        let cfg = Config::zstd(3);
        let c = compress_bytes(&data, &cfg).unwrap();
        assert!(c.len() < data.len(), "zstd should compress repetitive data");
        assert_eq!(decompress_bytes(&c, Algorithm::Zstd, &cfg).unwrap(), data);
    }

    #[test]
    fn lz4_roundtrip() {
        roundtrip(Algorithm::Lz4, b"hello world, hello world");
        roundtrip(Algorithm::Lz4, b"");
    }

    #[test]
    fn rejects_unknown_algorithm() {
        assert!(Algorithm::from_byte(99).is_err());
    }

    #[test]
    fn enforces_expanded_limit() {
        let cfg = Config {
            algorithm: Algorithm::Zstd,
            max_expanded_len: 10,
            ..Config::default()
        };
        let data = vec![b'X'; 1000];
        let compressed = compress_bytes(&data, &Config::zstd(3)).unwrap();
        let err = decompress_bytes(&compressed, Algorithm::Zstd, &cfg).unwrap_err();
        assert!(matches!(
            err,
            CompressionError::ExpandedSizeExceedsLimit { .. }
        ));
    }

    #[test]
    fn rejects_corrupt_data() {
        let cfg = Config::zstd(3);
        let err = decompress_bytes(b"not zstd data at all", Algorithm::Zstd, &cfg).unwrap_err();
        assert!(matches!(err, CompressionError::CorruptData(_)));
    }
}
