//! ZNF Stream: bounded-memory chunk framing and I/O adapters.
//!
//! All large payloads in ZNF are processed in bounded chunks so memory
//! usage never scales with file size.
//!
//! Chunk wire format (little-endian):
//!
//! ```text
//! ChunkLen (u32) | ChunkData (ChunkLen bytes)
//! ```
//!
//! A `ChunkLen` of `0` marks the end of a chunked stream. Every read
//! validates `ChunkLen` against the configured `max_chunk_size` before
//! allocating or reading.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::all)]

use std::io::{Read, Write};
use thiserror::Error;

/// Default chunk size (1 MiB).
pub const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;

/// Hard maximum chunk size accepted from untrusted input (16 MiB).
pub const MAX_CHUNK_SIZE: usize = 16 * 1024 * 1024;

/// Errors from streaming operations.
#[derive(Debug, Error)]
pub enum StreamError {
    /// Declared chunk length exceeds the configured maximum.
    #[error("chunk length {len} exceeds maximum {max}")]
    ChunkTooLarge {
        /// Declared length.
        len: u32,
        /// Configured max.
        max: usize,
    },

    /// Read exceeded the configured byte limit.
    #[error("stream exceeded limit of {limit} bytes")]
    LimitExceeded {
        /// Configured limit.
        limit: u64,
    },

    /// Unexpected EOF inside a chunk header or body.
    #[error("unexpected end of stream")]
    UnexpectedEof,

    /// Underlying I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Write a single framed chunk (`u32` little-endian length + bytes).
///
/// An empty `data` slice is not written here; call [`write_end_chunk`]
/// to write the terminal zero-length marker.
///
/// # Errors
///
/// Returns [`StreamError`] if `data.len() > max_chunk_size` or on I/O failure.
pub fn write_chunk<W: Write>(
    mut writer: W,
    data: &[u8],
    max_chunk_size: usize,
) -> Result<(), StreamError> {
    if data.len() > max_chunk_size || data.len() > u32::MAX as usize {
        return Err(StreamError::ChunkTooLarge {
            len: data.len().min(u32::MAX as usize) as u32,
            max: max_chunk_size,
        });
    }
    if data.is_empty() {
        return Ok(());
    }
    let len = data.len() as u32;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(data)?;
    Ok(())
}

/// Write the terminal zero-length chunk marker (`0u32`).
///
/// # Errors
///
/// Returns [`StreamError::Io`] on write failure.
pub fn write_end_chunk<W: Write>(mut writer: W) -> Result<(), StreamError> {
    writer.write_all(&0u32.to_le_bytes())?;
    Ok(())
}

/// Read the next framed chunk into `buf`.
///
/// Returns `Ok(Some(len))` for a non-empty chunk (with `buf` resized to `len`),
/// or `Ok(None)` when the terminal zero-length marker is reached.
///
/// # Errors
///
/// Returns [`StreamError`] on oversized chunk, truncated stream, or I/O error.
pub fn read_chunk<R: Read>(
    mut reader: R,
    buf: &mut Vec<u8>,
    max_chunk_size: usize,
) -> Result<Option<usize>, StreamError> {
    let mut len_bytes = [0u8; 4];
    read_exact_or_eof(&mut reader, &mut len_bytes)?;
    let len = u32::from_le_bytes(len_bytes);
    if len == 0 {
        buf.clear();
        return Ok(None);
    }
    if (len as usize) > max_chunk_size {
        return Err(StreamError::ChunkTooLarge {
            len,
            max: max_chunk_size,
        });
    }
    buf.resize(len as usize, 0);
    read_exact_or_eof(&mut reader, buf)?;
    Ok(Some(len as usize))
}

fn read_exact_or_eof<R: Read>(reader: &mut R, mut buf: &mut [u8]) -> Result<(), StreamError> {
    while !buf.is_empty() {
        match reader.read(buf) {
            Ok(0) => return Err(StreamError::UnexpectedEof),
            Ok(n) => buf = &mut buf[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(StreamError::Io(e)),
        }
    }
    Ok(())
}

/// A `Read` adapter that returns an error (rather than silently truncating
/// like `Read::take`) if the underlying reader yields more than `limit` bytes.
#[derive(Debug)]
pub struct BoundedReader<R> {
    inner: R,
    limit: u64,
    read_so_far: u64,
}

impl<R: Read> BoundedReader<R> {
    /// Wrap `inner` with a hard byte limit.
    #[must_use]
    pub fn new(inner: R, limit: u64) -> Self {
        BoundedReader {
            inner,
            limit,
            read_so_far: 0,
        }
    }

    /// Bytes read so far.
    #[must_use]
    pub fn bytes_read(&self) -> u64 {
        self.read_so_far
    }
}

impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read_so_far = self.read_so_far.saturating_add(n as u64);
        if self.read_so_far > self.limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("stream exceeded limit of {} bytes", self.limit),
            ));
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_roundtrip() {
        let mut wire = Vec::new();
        write_chunk(&mut wire, b"first chunk", 1024).unwrap();
        write_chunk(&mut wire, b"second", 1024).unwrap();
        write_end_chunk(&mut wire).unwrap();

        let mut cursor = &wire[..];
        let mut buf = Vec::new();
        assert_eq!(read_chunk(&mut cursor, &mut buf, 1024).unwrap(), Some(11));
        assert_eq!(buf, b"first chunk");
        assert_eq!(read_chunk(&mut cursor, &mut buf, 1024).unwrap(), Some(6));
        assert_eq!(buf, b"second");
        assert_eq!(read_chunk(&mut cursor, &mut buf, 1024).unwrap(), None);
    }

    #[test]
    fn rejects_oversized_chunk() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&5000u32.to_le_bytes());
        wire.extend_from_slice(&[0u8; 10]);
        let mut cursor = &wire[..];
        let mut buf = Vec::new();
        let err = read_chunk(&mut cursor, &mut buf, 1024).unwrap_err();
        assert!(matches!(err, StreamError::ChunkTooLarge { len: 5000, .. }));
    }

    #[test]
    fn bounded_reader_errors_past_limit() {
        let data = b"0123456789";
        let mut r = BoundedReader::new(&data[..], 5);
        let mut out = Vec::new();
        assert!(r.read_to_end(&mut out).is_err());
    }
}
