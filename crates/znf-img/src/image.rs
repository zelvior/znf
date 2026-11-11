//! Strongly typed image data model for ZIMG.
//!
//! Defines pixel formats, color models, and the in-memory [`Image`] buffer
//! used by both encoder and decoder. Pixel samples are stored in native
//! little-endian byte order for 16-bit depths, matching the wire format.

use crate::error::ZimgError;
use znf_integrity::Hash;

/// Color model describing how channels are interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ColorModel {
    /// Single luminance channel.
    Gray = 0,
    /// Luminance + alpha.
    GrayAlpha = 1,
    /// Red, green, blue.
    Rgb = 2,
    /// Red, green, blue, alpha.
    Rgba = 3,
}

impl ColorModel {
    /// Number of channels for this color model (excluding alpha handling).
    #[must_use]
    pub fn channel_count(self) -> usize {
        match self {
            ColorModel::Gray => 1,
            ColorModel::GrayAlpha => 2,
            ColorModel::Rgb => 3,
            ColorModel::Rgba => 4,
        }
    }

    /// Decode from wire byte.
    #[must_use]
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(ColorModel::Gray),
            1 => Some(ColorModel::GrayAlpha),
            2 => Some(ColorModel::Rgb),
            3 => Some(ColorModel::Rgba),
            _ => None,
        }
    }

    /// Wire byte value.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Alpha channel information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AlphaInfo {
    /// No alpha channel.
    None = 0,
    /// Alpha channel is present.
    Present = 1,
}

impl AlphaInfo {
    #[must_use]
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(AlphaInfo::None),
            1 => Some(AlphaInfo::Present),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Color space identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ColorSpace {
    /// sRGB.
    Srgb = 0,
    /// Linear RGB.
    Linear = 1,
    /// ICC profile embedded.
    Icc = 2,
}

impl ColorSpace {
    #[must_use]
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(ColorSpace::Srgb),
            1 => Some(ColorSpace::Linear),
            2 => Some(ColorSpace::Icc),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Bit depth per sample (per channel).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BitDepth {
    /// 8 bits per sample.
    Bits8 = 8,
    /// 16 bits per sample.
    Bits16 = 16,
}

impl BitDepth {
    /// Bytes per sample for this bit depth.
    #[must_use]
    pub const fn bytes_per_sample(self) -> usize {
        match self {
            BitDepth::Bits8 => 1,
            BitDepth::Bits16 => 2,
        }
    }

    #[must_use]
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            8 => Some(BitDepth::Bits8),
            16 => Some(BitDepth::Bits16),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Full pixel format descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PixelFormat {
    pub color_model: ColorModel,
    pub bit_depth: BitDepth,
    pub channel_count: u8,
    pub alpha: AlphaInfo,
    pub color_space: ColorSpace,
}

impl PixelFormat {
    /// Validate that the channel count matches the color model and alpha.
    #[must_use]
    pub fn is_consistent(self) -> bool {
        let expected = self.color_model.channel_count() as u8;
        self.channel_count == expected
    }

    /// Bytes per pixel sample.
    #[must_use]
    pub const fn bytes_per_pixel(self) -> usize {
        self.channel_count as usize * self.bit_depth.bytes_per_sample()
    }

    /// Encode the pixel format into the 4-byte wire descriptor used by
    /// `TLV_ZIMG_PIXEL_FORMAT`.
    #[must_use]
    pub fn to_wire_bytes(self) -> [u8; 4] {
        [
            self.color_model.as_byte(),
            self.bit_depth.as_byte(),
            self.channel_count,
            self.alpha.as_byte(),
        ]
    }

    /// Decode from the 4-byte wire descriptor.
    #[must_use]
    pub fn from_wire_bytes(bytes: [u8; 4]) -> Option<Self> {
        let color_model = ColorModel::from_byte(bytes[0])?;
        let bit_depth = BitDepth::from_byte(bytes[1])?;
        let channel_count = bytes[2];
        let alpha = AlphaInfo::from_byte(bytes[3])?;
        let pf = PixelFormat {
            color_model,
            bit_depth,
            channel_count,
            alpha,
            color_space: ColorSpace::Srgb,
        };
        if !pf.is_consistent() {
            return None;
        }
        Some(pf)
    }
}

/// In-memory image buffer with explicit row stride and pixel layout.
#[derive(Debug, Clone)]
pub struct Image {
    /// Image width in pixels.
    pub width: u32,
    /// Image height in pixels.
    pub height: u32,
    /// Pixel format descriptor.
    pub pixel_format: PixelFormat,
    /// Row stride in bytes (must be >= width * bytes_per_pixel).
    pub stride: usize,
    /// Pixel data, row-major, little-endian for 16-bit samples.
    /// Row `y` starts at `y * stride`.
    pub data: Vec<u8>,
    /// Optional per-chunk BLAKE3 hashes (set after decoding for verification).
    pub chunk_hashes: Vec<Hash>,
}

impl Image {
    /// Create a new image buffer with a contiguous row stride.
    #[must_use]
    pub fn new(width: u32, height: u32, pixel_format: PixelFormat) -> Result<Self, ZimgError> {
        let bpp = pixel_format.bytes_per_pixel();
        // Check for overflow in stride calculation.
        let stride = width.checked_mul(bpp as u32).ok_or_else(|| {
            ZimgError::InvalidDimensions(format!("width {width} * bytes_per_pixel {bpp} overflows"))
        })? as usize;
        // Check for overflow in total size.
        let total = stride.checked_mul(height as usize).ok_or_else(|| {
            ZimgError::InvalidDimensions(format!("stride {stride} * height {} overflows", height))
        })?;
        let total_pixels = (width as u64)
            .checked_mul(height as u64)
            .ok_or_else(|| ZimgError::InvalidDimensions("width * height overflows".into()))?;
        if total_pixels > crate::format::MAX_TOTAL_PIXELS {
            return Err(ZimgError::InvalidDimensions(format!(
                "total pixels {total_pixels} exceeds max {}",
                crate::format::MAX_TOTAL_PIXELS
            )));
        }
        Ok(Image {
            width,
            height,
            pixel_format,
            stride,
            data: vec![0u8; total],
            chunk_hashes: Vec::new(),
        })
    }

    /// Return the byte offset of the start of row `y`.
    #[must_use]
    pub fn row_offset(&self, y: u32) -> Result<usize, ZimgError> {
        self.stride
            .checked_mul(y as usize)
            .ok_or_else(|| ZimgError::InvalidDimensions(format!("row {y} offset overflows")))
    }

    /// Return a mutable slice for row `y`.
    pub fn row_mut(&mut self, y: u32) -> Result<&mut [u8], ZimgError> {
        let off = self.row_offset(y)?;
        Ok(&mut self.data[off..off + self.width as usize * self.pixel_format.bytes_per_pixel()])
    }

    /// Return an immutable slice for row `y`.
    #[must_use]
    pub fn row(&self, y: u32) -> Result<&[u8], ZimgError> {
        let off = self.row_offset(y)?;
        Ok(&self.data[off..off + self.width as usize * self.pixel_format.bytes_per_pixel()])
    }

    /// Total number of pixels.
    #[must_use]
    pub const fn total_pixels(&self) -> u64 {
        self.width as u64 * self.height as u64
    }

    /// Total bytes of pixel data (stride * height).
    #[must_use]
    pub const fn data_len(&self) -> usize {
        self.data.len()
    }
}
