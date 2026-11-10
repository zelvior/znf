//! Type-Length-Value (TLV) encoding for metadata and footer extensions.
//!
//! Wire format (all integers little-endian):
//!
//! ```text
//! Type (u16 LE) | Length (u32 LE) | Value (Length bytes)
//! ```
//!
//! Type ranges:
//! - `0x0000`: Reserved (must not appear; readers error).
//! - `0x0001..=0x3FFF`: Standard ZNF Core and format-specific TLV types.
//! - `0x4000..=0x6FFF`: **Critical Extension TLV types** (readers **must** reject
//!   if unrecognized with [`crate::ZnfError::UnsupportedCriticalExtension`]).
//! - `0x7000..=0xFFFE`: **Non-Critical / Vendor Extension TLV types** (readers
//!   safely skip or preserve verbatim if unrecognized).
//! - `0xFFFF`: End marker (`Length` must be `0`; terminates a TLV sequence).

use crate::error::Error;
use crate::limits::Limits;

/// TLV type: end-of-sequence marker.
pub const TLV_END: u16 = 0xFFFF;

/// TLV type: reserved (must not appear).
pub const TLV_RESERVED: u16 = 0x0000;

/// Lower bound of the Critical Extension TLV range.
pub const TLV_CRITICAL_EXT_MIN: u16 = 0x4000;

/// Upper bound of the Critical Extension TLV range.
pub const TLV_CRITICAL_EXT_MAX: u16 = 0x6FFF;

/// Returns `true` if `ty` is in the critical extension range (`0x4000..=0x6FFF`).
///
/// Unrecognized TLVs in this range **must** be rejected by readers.
#[must_use]
pub const fn is_critical_extension_type(ty: u16) -> bool {
    ty >= TLV_CRITICAL_EXT_MIN && ty <= TLV_CRITICAL_EXT_MAX
}

/// A single parsed TLV (borrowing the value bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// TLV type.
    pub ty: u16,
    /// Value bytes (borrowed).
    pub value: &'a [u8],
    /// Byte offset where this TLV's 6-byte header begins in the underlying slice.
    pub start_offset: usize,
}

impl<'a> Tlv<'a> {
    /// Whether this is the end marker.
    #[must_use]
    pub const fn is_end(&self) -> bool {
        self.ty == TLV_END
    }

    /// Whether this TLV type is in the critical extension range (`0x4000..=0x6FFF`).
    #[must_use]
    pub const fn is_critical_extension(&self) -> bool {
        is_critical_extension_type(self.ty)
    }
}

/// Incremental TLV reader over a byte slice.
///
/// Parses TLVs one at a time, validating each length before advancing.
/// Stops at the end marker or when the buffer is exhausted.
#[derive(Debug)]
pub struct TlvReader<'a> {
    buf: &'a [u8],
    offset: usize,
    limits: Limits,
    done: bool,
}

impl<'a> TlvReader<'a> {
    /// Create a reader over `buf`.
    #[must_use]
    pub fn new(buf: &'a [u8], limits: Limits) -> Self {
        TlvReader {
            buf,
            offset: 0,
            limits,
            done: false,
        }
    }

    /// Bytes consumed so far.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// Bytes remaining.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.offset)
    }

    /// Whether the end marker was reached.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        self.done
    }

    /// Read the next TLV, or `None` at end of buffer / after end marker.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] for truncated headers, oversized lengths,
    /// or reserved types. Never panics.
    pub fn next_tlv(&mut self) -> Result<Option<Tlv<'a>>, Error> {
        if self.done {
            return Ok(None);
        }
        let rem = self.remaining();
        if rem == 0 {
            self.done = true;
            return Ok(None);
        }
        if rem < 6 {
            return Err(Error::UnexpectedEof {
                offset: self.offset as u64,
            });
        }
        let base = self.offset;
        let ty = u16::from_le_bytes(self.buf[base..base + 2].try_into().unwrap());
        let len = u32::from_le_bytes(self.buf[base + 2..base + 6].try_into().unwrap());

        if ty == TLV_RESERVED {
            return Err(Error::ReservedTlvType(ty));
        }
        if ty == TLV_END {
            if len != 0 {
                return Err(Error::TlvLengthExceedsRemaining {
                    len,
                    remaining: rem - 6,
                });
            }
            self.offset += 6;
            self.done = true;
            return Ok(Some(Tlv {
                ty,
                value: &[],
                start_offset: base,
            }));
        }

        self.limits
            .check("tlv", len as u64, self.limits.max_tlv_len)?;
        let avail = rem - 6;
        if (len as usize) > avail {
            return Err(Error::TlvLengthExceedsRemaining {
                len,
                remaining: avail,
            });
        }
        let start = base + 6;
        let end = start + len as usize;
        let value = &self.buf[start..end];
        self.offset = end;
        Ok(Some(Tlv {
            ty,
            value,
            start_offset: base,
        }))
    }

    /// Consume all TLVs, invoking `f` for each (including end marker).
    pub fn for_each<F>(&mut self, mut f: F) -> Result<(), Error>
    where
        F: FnMut(Tlv<'a>),
    {
        while let Some(tlv) = self.next_tlv()? {
            let is_end = tlv.is_end();
            f(tlv);
            if is_end {
                break;
            }
        }
        Ok(())
    }
}

/// TLV writer: appends encoded TLVs to a buffer.
#[derive(Debug, Default, Clone)]
pub struct TlvWriter {
    buf: Vec<u8>,
}

impl TlvWriter {
    /// Create an empty writer.
    #[must_use]
    pub fn new() -> Self {
        TlvWriter { buf: Vec::new() }
    }

    /// Append a TLV.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if `ty` is reserved or `value` exceeds limits.
    pub fn push(&mut self, ty: u16, value: &[u8], limits: &Limits) -> Result<(), Error> {
        if ty == TLV_RESERVED || ty == TLV_END {
            return Err(Error::ReservedTlvType(ty));
        }
        if value.len() > u32::MAX as usize {
            return Err(Error::LengthExceedsLimit {
                what: "tlv",
                len: value.len() as u64,
                limit: u32::MAX as u64,
            });
        }
        limits.check("tlv", value.len() as u64, limits.max_tlv_len)?;
        self.buf.extend_from_slice(&ty.to_le_bytes());
        self.buf
            .extend_from_slice(&(value.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(value);
        Ok(())
    }

    /// Append the end marker (`0xFFFF`, length `0`).
    pub fn push_end(&mut self) {
        self.buf.extend_from_slice(&TLV_END.to_le_bytes());
        self.buf.extend_from_slice(&0u32.to_le_bytes());
    }

    /// Encoded bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Encoded length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Consume and return the buffer.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlv_roundtrip() {
        let limits = Limits::default();
        let mut w = TlvWriter::new();
        w.push(0x0001, b"hello", &limits).unwrap();
        w.push(0x8001, &[1, 2, 3], &limits).unwrap();
        w.push_end();
        let bytes = w.into_bytes();

        let mut r = TlvReader::new(&bytes, limits);
        let t1 = r.next_tlv().unwrap().unwrap();
        assert_eq!(t1.ty, 0x0001);
        assert_eq!(t1.value, b"hello");
        assert_eq!(t1.start_offset, 0);
        let t2 = r.next_tlv().unwrap().unwrap();
        assert_eq!(t2.ty, 0x8001);
        assert_eq!(t2.value, &[1, 2, 3]);
        assert_eq!(t2.start_offset, 11);
        let end = r.next_tlv().unwrap().unwrap();
        assert!(end.is_end());
        assert!(r.next_tlv().unwrap().is_none());
    }

    #[test]
    fn rejects_truncated_tlv() {
        let limits = Limits::default();
        let buf = [0x01, 0x00, 0xFF];
        let mut r = TlvReader::new(&buf, limits);
        assert!(r.next_tlv().is_err());
    }

    #[test]
    fn rejects_oversized_tlv() {
        let limits = Limits::default();
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x0001u16.to_le_bytes());
        buf.extend_from_slice(&100u32.to_le_bytes());
        buf.extend_from_slice(&[1, 2, 3]);
        let mut r = TlvReader::new(&buf, limits);
        let e = r.next_tlv().unwrap_err();
        assert!(matches!(e, Error::TlvLengthExceedsRemaining { .. }));
    }

    #[test]
    fn rejects_reserved_type() {
        let limits = Limits::default();
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x0000u16.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        let mut r = TlvReader::new(&buf, limits);
        assert!(r.next_tlv().is_err());
    }

    #[test]
    fn skips_unknown_types() {
        let limits = Limits::default();
        let mut w = TlvWriter::new();
        w.push(0x7FFF, b"x", &limits).unwrap();
        w.push_end();
        let bytes = w.into_bytes();
        let mut r = TlvReader::new(&bytes, limits);
        assert_eq!(r.next_tlv().unwrap().unwrap().ty, 0x7FFF);
    }
}
