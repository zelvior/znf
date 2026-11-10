//! Structured image metadata system for ZIMG.
//!
//! Supports optional title, description, creator, creation timestamp,
//! software, copyright, and user-defined key-value metadata. All metadata
//! is optional and never automatically collected.

use crate::error::ZimgError;
use std::collections::BTreeMap;

/// Structured image metadata. All fields are optional.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImageMetadata {
    /// Human-readable title.
    pub title: Option<String>,
    /// Human-readable description.
    pub description: Option<String>,
    /// Creator / author.
    pub creator: Option<String>,
    /// Creation timestamp (RFC 3339 / ISO 8601 string).
    pub created: Option<String>,
    /// Software used to create the image.
    pub software: Option<String>,
    /// Copyright information.
    pub copyright: Option<String>,
    /// User-defined key-value metadata (sorted by key).
    pub custom: BTreeMap<String, String>,
}

impl ImageMetadata {
    /// Create empty metadata.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Encode metadata as UTF-8 key-value bytes suitable for `TLV_ZIMG_METADATA`.
    /// Format: `count: u16 LE` followed by `count` entries of
    /// `key_len: u16 LE || key_utf8 || val_len: u16 LE || val_utf8`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut count: u16 = 0;
        let mut entries: Vec<(String, String)> = Vec::new();
        macro_rules! maybe {
            ($key:expr, $val:expr) => {
                if let Some(v) = $val {
                    entries.push(($key.to_string(), v));
                }
            };
        }
        maybe!("title", self.title.as_deref());
        maybe!("description", self.description.as_deref());
        maybe!("creator", self.creator.as_deref());
        maybe!("created", self.created.as_deref());
        maybe!("software", self.software.as_deref());
        maybe!("copyright", self.copyright.as_deref());
        for (k, v) in &self.custom {
            entries.push((k.clone(), v.clone()));
        }
        // Sort by key for deterministic output.
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        count = entries.len() as u16;
        out.extend_from_slice(&count.to_le_bytes());
        for (key, val) in entries {
            let kb = key.as_bytes();
            let vb = val.as_bytes();
            out.extend_from_slice(&(kb.len() as u16).to_le_bytes());
            out.extend_from_slice(kb);
            out.extend_from_slice(&(vb.len() as u16).to_le_bytes());
            out.extend_from_slice(vb);
        }
        out
    }

    /// Decode metadata from `TLV_ZIMG_METADATA` bytes.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Result<Self, ZimgError> {
        if bytes.len() < 2 {
            return Err(ZimgError::MalformedImage(
                "metadata TLV too short for entry count".into(),
            ));
        }
        let count = u16::from_le_bytes(bytes[0..2].try_into().unwrap()) as usize;
        let mut offset = 2;
        let mut meta = ImageMetadata::new();
        let mut custom = BTreeMap::new();
        for _ in 0..count {
            if offset + 2 > bytes.len() {
                return Err(ZimgError::MalformedImage(
                    "metadata TLV truncated at key length".into(),
                ));
            }
            let key_len = u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap()) as usize;
            offset += 2;
            if offset + key_len > bytes.len() {
                return Err(ZimgError::MalformedImage(
                    "metadata TLV truncated at key".into(),
                ));
            }
            let key = String::from_utf8_lossy(&bytes[offset..offset + key_len]).into_owned();
            offset += key_len;
            if offset + 2 > bytes.len() {
                return Err(ZimgError::MalformedImage(
                    "metadata TLV truncated at value length".into(),
                ));
            }
            let val_len = u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap()) as usize;
            offset += 2;
            if offset + val_len > bytes.len() {
                return Err(ZimgError::MalformedImage(
                    "metadata TLV truncated at value".into(),
                ));
            }
            let val = String::from_utf8_lossy(&bytes[offset..offset + val_len]).into_owned();
            offset += val_len;
            match key.as_str() {
                "title" => meta.title = Some(val),
                "description" => meta.description = Some(val),
                "creator" => meta.creator = Some(val),
                "created" => meta.created = Some(val),
                "software" => meta.software = Some(val),
                "copyright" => meta.copyright = Some(val),
                _ => {
                    custom.insert(key, val);
                }
            }
        }
        meta.custom = custom;
        Ok(meta)
    }
}

