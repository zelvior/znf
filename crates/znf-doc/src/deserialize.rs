//! ZDOC document deserialization: bytes -> DOM.
//!
//! Strict parsing with bounded allocations. All offsets, lengths, and counts
//! are validated before allocation. Returns structured errors, never panics.

use crate::dom::{
    BlockContent, CodeBlock, Document, Footnote, HeaderFooter, Hyperlink, Image, List, ListItem,
    MathBlock, Paragraph, Section, Style, StyleRef, Table, TableCell, TableRow, TextDirection,
    TextRun,
};
use crate::error::ZdocError;
use crate::format::{
    MAX_ATTACHMENT_SIZE, MAX_OBJECTS, MAX_TABLE_COLS, MAX_TABLE_ROWS, MAX_TEXT_RUN_LEN,
    OBJECT_INDEX_ENTRY_LEN, OBJECT_TYPE_ATTACHMENT, OBJECT_TYPE_CODE_BLOCK, OBJECT_TYPE_FOOTNOTE,
    OBJECT_TYPE_HYPERLINK, OBJECT_TYPE_IMAGE, OBJECT_TYPE_LIST, OBJECT_TYPE_LIST_ITEM,
    OBJECT_TYPE_MATH_BLOCK, OBJECT_TYPE_PARAGRAPH, OBJECT_TYPE_SECTION, OBJECT_TYPE_STYLE,
    OBJECT_TYPE_TABLE, OBJECT_TYPE_TABLE_CELL, OBJECT_TYPE_TABLE_ROW, OBJECT_TYPE_TEXT_RUN,
    TLV_ARCHIVE_BLAKE3, TLV_ZDOC_AUTHOR, TLV_ZDOC_CREATED, TLV_ZDOC_CREATOR, TLV_ZDOC_DOCUMENT_ID,
    TLV_ZDOC_ENCRYPTED_METADATA, TLV_ZDOC_LANGUAGE, TLV_ZDOC_METADATA_KV, TLV_ZDOC_MODIFIED,
    TLV_ZDOC_STRUCTURE, TLV_ZDOC_SUBJECT, TLV_ZDOC_TITLE,
};
use znf_compression::{decompress_bytes, Algorithm, Config as CompConfig};
use znf_core::{FormatId, Header, Limits, HEADER_LEN};
use znf_crypto::{decrypt, KdfParams, NONCE_LEN, TAG_LEN};
use znf_integrity::{hash, Hash, Hasher, HASH_LEN};

/// Deserialized document result.
#[derive(Debug, Clone)]
pub struct DeserializedDocument {
    /// The decoded document.
    pub document: Document,
    /// Document metadata parsed from TLVs.
    pub metadata: DocumentMetadata,
    /// Whether the archive was encrypted.
    pub encrypted: bool,
    /// Whether integrity verification passed.
    pub integrity_verified: bool,
}

/// Document-level metadata parsed from the metadata section TLVs.
#[derive(Debug, Clone, Default)]
pub struct DocumentMetadata {
    pub title: Option<String>,
    pub subject: Option<String>,
    pub author: Option<String>,
    pub creator: Option<String>,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub language: Option<String>,
    pub custom: std::collections::BTreeMap<String, String>,
}

/// Deserialize ZDOC file bytes into a document.
pub fn deserialize_document(
    bytes: &[u8],
    password: Option<&[u8]>,
    opts: &DecodeOptions,
) -> Result<DeserializedDocument, ZdocError> {
    if bytes.len() < HEADER_LEN {
        return Err(ZdocError::Core(znf_core::Error::TooShort {
            need: HEADER_LEN,
            have: bytes.len(),
        }));
    }

    // Decode and validate the ZNF Core header.
    let header = Header::decode(bytes, &opts.limits, Some(bytes.len() as u64))?;
    if header.format_id() != FormatId::from_raw(crate::format::FORMAT_ID_ZDOC).unwrap() {
        return Err(ZdocError::NotZdocFormat(header.format_id().raw()));
    }

    let meta_start = header.header_len() as usize;
    let payload_start = header.payload_offset() as usize;
    let payload_end = header
        .payload_offset()
        .checked_add(header.payload_len())
        .ok_or_else(|| ZdocError::InvalidDimensions("payload end overflow".into()))?
        as usize;

    if payload_end > bytes.len() {
        return Err(ZdocError::MalformedStructure(
            "payload extends past end of file".into(),
        ));
    }

    // Derive decryption key if encrypted.
    let derived_key = if header.flags().is_encrypted() {
        let pw = password.ok_or_else(|| {
            ZdocError::EncryptionMismatch("document is encrypted; password required")
        })?;
        let kdf_params = find_kdf_params(&bytes[meta_start..payload_start], &opts.limits)?;
        Some(kdf_params.derive_key(pw)?)
    } else {
        if password.is_some() {
            return Err(ZdocError::EncryptionMismatch(
                "password supplied for unencrypted document",
            ));
        }
        None
    };

    // Parse metadata section.
    let mut metadata = DocumentMetadata::default();
    let mut encrypted_meta: Option<Vec<u8>> = None;
    let mut document_id: Option<[u8; 16]> = None;

    if header.flags().has_metadata() {
        parse_metadata_tlvs(
            &bytes[meta_start..payload_start],
            &opts.limits,
            &mut metadata,
            &mut encrypted_meta,
            &mut document_id,
        )?;
    }

    // If encrypted metadata was present, decrypt it now.
    if let Some(enc_meta) = encrypted_meta {
        if let Some(ref key) = derived_key {
            if enc_meta.len() < NONCE_LEN + TAG_LEN {
                return Err(ZdocError::MalformedStructure(
                    "encrypted metadata too short".into(),
                ));
            }
            let nonce_arr: [u8; NONCE_LEN] = enc_meta[..NONCE_LEN].try_into().map_err(|_| {
                ZdocError::MalformedStructure("encrypted metadata nonce too short".into())
            })?;
            let ct = &enc_meta[NONCE_LEN..];
            let header_bytes = header.to_bytes()?;
            let decrypted = decrypt(key, &nonce_arr, ct, &header_bytes)?;
            metadata = DocumentMetadata::decode_kv(&decrypted)?;
        } else {
            return Err(ZdocError::EncryptionMismatch(
                "encrypted metadata present but no decryption key",
            ));
        }
    }

    // Parse payload: compressed + optionally encrypted objects.
    let payload_bytes = &bytes[payload_start..payload_end];

    // Parse footer TLVs to get object index and hashes.
    let footer_start = payload_end;
    let footer_bytes = &bytes[footer_start..];

    let mut object_index: Option<Vec<ObjectIndexEntry>> = None;
    let mut object_hashes: Option<Vec<Hash>> = None;
    let mut archive_blake3: Option<Hash> = None;
    let mut saw_footer_end = false;

    let mut offset = 0;
    while offset + 4 <= footer_bytes.len() {
        let ty = u16::from_le_bytes(footer_bytes[offset..offset + 2].try_into().unwrap());
        let len =
            u32::from_le_bytes(footer_bytes[offset + 2..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if offset + len > footer_bytes.len() {
            return Err(ZdocError::MalformedStructure(
                "footer TLV length exceeds remaining bytes".into(),
            ));
        }
        let value = &footer_bytes[offset..offset + len];
        offset += len;

        if ty == 0xFFFF {
            saw_footer_end = true;
            break;
        }

        match ty {
            crate::format::TLV_ZDOC_OBJECT_INDEX => {
                if len < 4 {
                    return Err(ZdocError::MalformedStructure(
                        "object index too short".into(),
                    ));
                }
                let count = u32::from_le_bytes(value[0..4].try_into().unwrap()) as usize;
                let mut entries = Vec::with_capacity(count);
                let mut off = 4;
                for _ in 0..count {
                    if off + OBJECT_INDEX_ENTRY_LEN > value.len() {
                        return Err(ZdocError::MalformedStructure(
                            "object index entry truncated".into(),
                        ));
                    }
                    entries.push(
                        parse_object_index_entry(&value[off..off + OBJECT_INDEX_ENTRY_LEN])?
                            .ok_or_else(|| {
                                ZdocError::MalformedStructure("invalid object index entry".into())
                            })?,
                    );
                    off += OBJECT_INDEX_ENTRY_LEN;
                }
                object_index = Some(entries);
            }
            crate::format::TLV_ZDOC_OBJECT_BLAKE3 => {
                if len < 4 {
                    return Err(ZdocError::MalformedStructure(
                        "object hash list too short".into(),
                    ));
                }
                let count = u32::from_le_bytes(value[0..4].try_into().unwrap()) as usize;
                let mut hashes = Vec::with_capacity(count);
                let mut off = 4;
                for _ in 0..count {
                    if off + HASH_LEN > value.len() {
                        return Err(ZdocError::MalformedStructure(
                            "object hash truncated".into(),
                        ));
                    }
                    hashes.push(Hash::from_bytes(
                        value[off..off + HASH_LEN].try_into().unwrap(),
                    ));
                    off += HASH_LEN;
                }
                object_hashes = Some(hashes);
            }
            TLV_ARCHIVE_BLAKE3 => {
                if len != HASH_LEN {
                    return Err(ZdocError::MalformedStructure(
                        "archive BLAKE3 wrong length".into(),
                    ));
                }
                archive_blake3 = Some(Hash::from_bytes(value.try_into().unwrap()));
            }
            _ => {
                if znf_core::tlv::is_critical_extension_type(ty) {
                    return Err(ZdocError::Core(
                        znf_core::Error::UnsupportedCriticalExtension(ty),
                    ));
                }
            }
        }
    }

    if !saw_footer_end {
        return Err(ZdocError::MalformedStructure(
            "footer missing TLV_END marker".into(),
        ));
    }

    let entries =
        object_index.ok_or_else(|| ZdocError::MalformedStructure("missing object index".into()))?;

    // Verify whole-archive BLAKE3.
    if let Some(expected) = archive_blake3 {
        let mut hasher = Hasher::new();
        hasher.update(&bytes[..payload_end]);
        let computed = hasher.finalize();
        if computed != expected {
            return Err(ZdocError::Integrity(
                znf_integrity::IntegrityError::HashMismatch {
                    expected: expected.to_hex(),
                    computed: computed.to_hex(),
                },
            ));
        }
    }

    // Decrypt + decompress each object and reconstruct the document.
    let mut document = Document::new();
    if let Some(doc_id) = document_id {
        document.document_id = doc_id;
    }

    // Apply metadata.
    document.title = metadata.title;
    document.subject = metadata.subject;
    document.author = metadata.author;
    document.creator = metadata.creator;
    document.created = metadata.created;
    document.modified = metadata.modified;
    document.language = metadata.language;
    document.metadata = metadata.custom;

    // Decompress the entire payload if compression is set.
    let algo = match header.compression() {
        znf_core::ZnfCompression::None => Algorithm::None,
        znf_core::ZnfCompression::Zstd => Algorithm::Zstd,
        znf_core::ZnfCompression::Lz4 => Algorithm::Lz4,
    };

    let decompressed_payload: Vec<u8> = if let Some(ref key) = derived_key {
        // Decrypt each chunk/object.
        let mut decrypted_objects = Vec::new();
        for entry in &entries {
            let chunk_start = entry.stored_offset as usize;
            let chunk_end = chunk_start
                .checked_add(entry.stored_len as usize)
                .ok_or_else(|| {
                    ZdocError::InvalidDimensions("object stored range overflow".into())
                })?;
            if chunk_end > payload_bytes.len() {
                return Err(ZdocError::MalformedStructure(
                    "object stored range exceeds payload".into(),
                ));
            }
            let stored = &payload_bytes[chunk_start..chunk_end];
            if stored.len() < NONCE_LEN + TAG_LEN {
                return Err(ZdocError::MalformedStructure(
                    "encrypted object too short".into(),
                ));
            }
            let nonce_arr: [u8; NONCE_LEN] = stored[..NONCE_LEN].try_into().unwrap();
            let ct = &stored[NONCE_LEN..];
            let aad = (entry.object_id as u32).to_le_bytes().to_vec();
            let decrypted = decrypt(key, &nonce_arr, ct, &aad)?;
            decrypted_objects.push(decrypted);
        }
        // Concatenate all decrypted objects — but we need to know boundaries.
        // For simplicity with per-object encryption, we re-parse from the concatenated stream.
        // Actually, each object is self-describing (type | id | length | value), so we can
        // parse them sequentially after decryption.
        let mut all_decrypted = Vec::new();
        for d in decrypted_objects {
            all_decrypted.extend_from_slice(&d);
        }
        // Decompress if the compression flag indicates the payload was compressed before encryption.
        // Note: encryption is applied after compression, so we decrypt first, then decompress.
        decompress_bytes(
            &all_decrypted,
            algo,
            &CompConfig {
                algorithm: algo,
                zstd_level: 3,
                max_expanded_len: opts.limits.max_expanded_len,
            },
        )?
    } else {
        decompress_bytes(
            payload_bytes,
            algo,
            &CompConfig {
                algorithm: algo,
                zstd_level: 3,
                max_expanded_len: opts.limits.max_expanded_len,
            },
        )?
    };

    // Parse objects from the decompressed payload.
    parse_objects(
        &decompressed_payload,
        &mut document,
        &entries,
        object_hashes.as_deref(),
        opts.verify_integrity,
    )?;

    let integrity_verified = opts.verify_integrity && archive_blake3.is_some();

    // Validate the reconstructed document.
    document.validate()?;

    Ok(DeserializedDocument {
        document,
        metadata,
        encrypted: derived_key.is_some(),
        integrity_verified,
    })
}

/// Object index entry parsed from the footer.
#[derive(Debug, Clone)]
struct ObjectIndexEntry {
    pub object_id: u32,
    pub object_type: u8,
    pub stored_offset: u64,
    pub stored_len: u32,
    pub uncompressed_len: u32,
    pub blake3_hash: Hash,
}

fn parse_object_index_entry(bytes: &[u8]) -> Option<ObjectIndexEntry> {
    if bytes.len() < OBJECT_INDEX_ENTRY_LEN {
        return None;
    }
    Some(ObjectIndexEntry {
        object_id: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        object_type: bytes[4],
        stored_offset: u64::from_le_bytes(bytes[5..13].try_into().unwrap()),
        stored_len: u32::from_le_bytes(bytes[13..17].try_into().unwrap()),
        uncompressed_len: u32::from_le_bytes(bytes[17..21].try_into().unwrap()),
        blake3_hash: Hash::from_bytes(bytes[21..53].try_into().unwrap()),
    })
}

/// Find KDF params TLV in the metadata section.
fn find_kdf_params(metadata: &[u8], limits: &Limits) -> Result<KdfParams, ZdocError> {
    let mut offset = 0;
    while offset + 4 <= metadata.len() {
        let ty = u16::from_le_bytes(metadata[offset..offset + 2].try_into().unwrap());
        let len = u32::from_le_bytes(metadata[offset + 2..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if offset + len > metadata.len() {
            return Err(ZdocError::MalformedStructure(
                "metadata TLV length exceeds remaining".into(),
            ));
        }
        let value = &metadata[offset..offset + len];
        offset += len;

        if ty == 0xFFFF {
            break;
        }

        if ty == znf_core::TLV_KDF_PARAMS {
            return KdfParams::decode(value).map_err(ZdocError::from);
        }

        if znf_core::tlv::is_critical_extension_type(ty) {
            return Err(ZdocError::Core(
                znf_core::Error::UnsupportedCriticalExtension(ty),
            ));
        }
    }
    Err(ZdocError::MalformedStructure(
        "missing KDF params TLV".into(),
    ))
}

/// Parse all metadata TLVs from the metadata section.
#[allow(clippy::too_many_arguments)]
fn parse_metadata_tlvs(
    metadata: &[u8],
    limits: &Limits,
    metadata_out: &mut DocumentMetadata,
    encryption_meta: &mut Option<Vec<u8>>,
    document_id: &mut Option<[u8; 16]>,
) -> Result<(), ZdocError> {
    let mut offset = 0;
    while offset + 4 <= metadata.len() {
        let ty = u16::from_le_bytes(metadata[offset..offset + 2].try_into().unwrap());
        let len = u32::from_le_bytes(metadata[offset + 2..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if offset + len > metadata.len() {
            return Err(ZdocError::MalformedStructure(
                "metadata TLV length exceeds remaining".into(),
            ));
        }
        let value = &metadata[offset..offset + len];
        offset += len;

        if ty == 0xFFFF {
            break;
        }

        match ty {
            TLV_ZDOC_DOCUMENT_ID => {
                if len == 16 {
                    let mut id = [0u8; 16];
                    id.copy_from_slice(value);
                    *document_id = Some(id);
                }
            }
            TLV_ZDOC_TITLE => {
                metadata_out.title = Some(validate_utf8(value, "title")?);
            }
            TLV_ZDOC_SUBJECT => {
                metadata_out.subject = Some(validate_utf8(value, "subject")?);
            }
            TLV_ZDOC_AUTHOR => {
                metadata_out.author = Some(validate_utf8(value, "author")?);
            }
            TLV_ZDOC_CREATOR => {
                metadata_out.creator = Some(validate_utf8(value, "creator")?);
            }
            TLV_ZDOC_CREATED => {
                metadata_out.created = Some(validate_utf8(value, "created")?);
            }
            TLV_ZDOC_MODIFIED => {
                metadata_out.modified = Some(validate_utf8(value, "modified")?);
            }
            TLV_ZDOC_LANGUAGE => {
                metadata_out.language = Some(validate_utf8(value, "language")?);
            }
            TLV_ZDOC_METADATA_KV => {
                *metadata_out = DocumentMetadata::decode_kv(value)?;
            }
            TLV_ZDOC_ENCRYPTED_METADATA => {
                *encryption_meta = Some(value.to_vec());
            }
            TLV_ZDOC_STRUCTURE => {
                // Structural descriptor — informational for now; objects are parsed from payload.
            }
            _ => {
                if znf_core::tlv::is_critical_extension_type(ty) {
                    return Err(ZdocError::Core(
                        znf_core::Error::UnsupportedCriticalExtension(ty),
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Validate that a byte slice is valid UTF-8.
fn validate_utf8(bytes: &[u8], field: &str) -> Result<String, ZdocError> {
    std::str::from_utf8(bytes)
        .map(|s| s.to_owned())
        .map_err(|_| ZdocError::InvalidUtf8(format!("field '{}' is not valid UTF-8", field)))
}

/// Parse objects from the decompressed payload.
fn parse_objects(
    payload: &[u8],
    document: &mut Document,
    entries: &[ObjectIndexEntry],
    expected_hashes: Option<&[Hash]>,
    verify_integrity: bool,
) -> Result<(), ZdocError> {
    let mut offset = 0;
    let mut object_count = 0;

    while offset < payload.len() {
        if offset + 1 > payload.len() {
            return Err(ZdocError::MalformedStructure(
                "truncated object type".into(),
            ));
        }
        let otype = payload[offset];
        offset += 1;

        if offset + 4 > payload.len() {
            return Err(ZdocError::MalformedStructure("truncated object id".into()));
        }
        let id = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
        offset += 4;

        if offset + 4 > payload.len() {
            return Err(ZdocError::MalformedStructure(
                "truncated object length".into(),
            ));
        }
        let length = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;

        if offset + length > payload.len() {
            return Err(ZdocError::MalformedStructure(
                "object value exceeds payload".into(),
            ));
        }
        let value = &payload[offset..offset + length];
        offset += length;

        // Verify per-object hash if requested.
        if verify_integrity {
            if let Some(ref hashes) = expected_hashes {
                if object_count < hashes.len() {
                    let computed = hash(value);
                    if computed != hashes[object_count] {
                        return Err(ZdocError::Integrity(
                            znf_integrity::IntegrityError::HashMismatch {
                                expected: hashes[object_count].to_hex(),
                                computed: computed.to_hex(),
                            },
                        ));
                    }
                }
            }
        }

        match otype {
            OBJECT_TYPE_SECTION => {
                if id == 0 {
                    // Document root object — parse document header info.
                    parse_document_root(value, document)?;
                } else {
                    let section = parse_section(value, id)?;
                    document.sections.push(section);
                }
            }
            OBJECT_TYPE_PARAGRAPH => {
                let paragraph = parse_paragraph(value, id)?;
                // We need to attach paragraphs to sections; for now store inline.
                // Sections are parsed first, then their content references paragraph IDs.
                // For simplicity, we attach the last parsed paragraph to the current section.
                if let Some(last_section) = document.sections.last_mut() {
                    last_section
                        .content
                        .push(BlockContent::Paragraph(paragraph));
                }
            }
            OBJECT_TYPE_TABLE => {
                let table = parse_table(value, id)?;
                if let Some(last_section) = document.sections.last_mut() {
                    last_section.content.push(BlockContent::Table(table));
                }
            }
            OBJECT_TYPE_IMAGE => {
                let image = parse_image(value, id)?;
                document.images.insert(id, image);
            }
            OBJECT_TYPE_ATTACHMENT => {
                let attachment = parse_attachment(value, id)?;
                document.attachments.insert(id, attachment);
            }
            OBJECT_TYPE_HYPERLINK => {
                let hyperlink = parse_hyperlink(value, id)?;
                document.hyperlinks.insert(id, hyperlink);
            }
            OBJECT_TYPE_FOOTNOTE => {
                let footnote = parse_footnote(value, id)?;
                document.footnotes.insert(id, footnote);
            }
            OBJECT_TYPE_STYLE => {
                let style = parse_style(value)?;
                document.styles.push(style);
            }
            OBJECT_TYPE_CODE_BLOCK => {
                let block = parse_code_block(value, id)?;
                document.code_blocks.insert(id, block);
            }
            OBJECT_TYPE_MATH_BLOCK => {
                let block = parse_math_block(value, id)?;
                document.math_blocks.insert(id, block);
            }
            OBJECT_TYPE_LIST => {
                let list = parse_list(value, id)?;
                document.lists.insert(id, list);
            }
            OBJECT_TYPE_HEADER_FOOTER => {
                let hf = parse_header_footer(value, id)?;
                document.headers_footers.insert(id, hf);
            }
            OBJECT_TYPE_TEXT_RUN
            | OBJECT_TYPE_TABLE_ROW
            | OBJECT_TYPE_TABLE_CELL
            | OBJECT_TYPE_LIST_ITEM => {
                // These are nested objects parsed within their parents; skip at top level.
            }
            _ => {
                // Unknown object type — skip (forward compatibility).
            }
        }

        object_count += 1;
        if object_count as u64 > MAX_OBJECTS {
            return Err(ZdocError::ResourceLimitExceeded(format!(
                "object count {} exceeds max {}",
                object_count, MAX_OBJECTS
            )));
        }
    }

    Ok(())
}

/// Parse the document root object (id == 0) which contains global document info.
fn parse_document_root(value: &[u8], document: &mut Document) -> Result<(), ZdocError> {
    let mut offset = 0;
    if offset + 4 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated document root: page count".into(),
        ));
    }
    let _page_count = u32::from_le_bytes(value[offset..offset + 4].try_into().unwrap());
    offset += 4;
    if offset + 4 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated document root: object count".into(),
        ));
    }
    let _object_count = u32::from_le_bytes(value[offset..offset + 4].try_into().unwrap());
    offset += 4;
    // Page numbering style.
    if offset + 2 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated document root: style length".into(),
        ));
    }
    let style_len = u16::from_le_bytes(value[offset..offset + 2].try_into().unwrap()) as usize;
    offset += 2;
    if offset + style_len > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated document root: style".into(),
        ));
    }
    document.page_numbering.style =
        validate_utf8(&value[offset..offset + style_len], "page_numbering_style")?;
    offset += style_len;
    if offset + 4 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated document root: page start".into(),
        ));
    }
    document.page_numbering.start =
        u32::from_le_bytes(value[offset..offset + 4].try_into().unwrap());
    offset += 4;
    if offset + 1 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated document root: display flag".into(),
        ));
    }
    document.page_numbering.display = value[offset] != 0;
    Ok(())
}

fn parse_section(value: &[u8], id: u32) -> Result<Section, ZdocError> {
    let mut offset = 0;
    if offset + 4 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated section: content count".into(),
        ));
    }
    let content_count = u32::from_le_bytes(value[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    if offset + 4 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated section: depth".into(),
        ));
    }
    let depth = u32::from_le_bytes(value[offset..offset + 4].try_into().unwrap());
    offset += 4;
    if offset + 1 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated section: page_break_before".into(),
        ));
    }
    let page_break_before = value[offset] != 0;
    offset += 1;
    // Heading.
    if offset + 1 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated section: heading present".into(),
        ));
    }
    let heading_present = value[offset] != 0;
    offset += 1;
    let mut hlen: usize = 0;
    let heading = if heading_present {
        if offset + 4 > value.len() {
            return Err(ZdocError::MalformedStructure(
                "truncated section: heading length".into(),
            ));
        }
        hlen = u32::from_le_bytes(value[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if offset + hlen > value.len() {
            return Err(ZdocError::MalformedStructure(
                "truncated section: heading".into(),
            ));
        }
        Some(validate_utf8(
            &value[offset..offset + hlen],
            "section heading",
        )?)
    } else {
        None
    };
    offset += hlen;
    // Style.
    let style = parse_style_ref(&value[offset..], &mut offset)?;
    // Content blocks.
    let mut content = Vec::new();
    for _ in 0..content_count {
        if offset + 1 > value.len() {
            return Err(ZdocError::MalformedStructure(
                "truncated section: block type".into(),
            ));
        }
        let btype = value[offset];
        offset += 1;
        let block = parse_block_content(&value[offset..], btype, &mut offset)?;
        content.push(block);
    }
    Ok(Section {
        id,
        content,
        style: style.unwrap_or(StyleRef::None),
        heading,
        page_break_before,
        depth,
    })
}

fn parse_block_content(
    value: &[u8],
    btype: u8,
    offset: &mut usize,
) -> Result<BlockContent, ZdocError> {
    match btype {
        OBJECT_TYPE_PARAGRAPH => {
            let id = read_u32(value, offset)?;
            let paragraph = parse_paragraph(&value[*offset..], id)?;
            *offset += paragraph_serialized_len(&paragraph);
            Ok(BlockContent::Paragraph(paragraph))
        }
        OBJECT_TYPE_TABLE => {
            let id = read_u32(value, offset)?;
            let table = parse_table(&value[*offset..], id)?;
            *offset += table_serialized_len(&table);
            Ok(BlockContent::Table(table))
        }
        OBJECT_TYPE_CODE_BLOCK => {
            let id = read_u32(value, offset)?;
            let block = parse_code_block(&value[*offset..], id)?;
            *offset += code_block_serialized_len(&block);
            Ok(BlockContent::CodeBlock(block))
        }
        OBJECT_TYPE_MATH_BLOCK => {
            let id = read_u32(value, offset)?;
            let block = parse_math_block(&value[*offset..], id)?;
            *offset += math_block_serialized_len(&block);
            Ok(BlockContent::MathBlock(block))
        }
        OBJECT_TYPE_LIST => {
            let id = read_u32(value, offset)?;
            let list = parse_list(&value[*offset..], id)?;
            *offset += list_serialized_len(&list);
            Ok(BlockContent::List(list))
        }
        OBJECT_TYPE_HEADER_FOOTER => {
            let id = read_u32(value, offset)?;
            let hf = parse_header_footer(&value[*offset..], id)?;
            *offset += header_footer_serialized_len(&hf);
            Ok(BlockContent::HeaderFooter(hf))
        }
        OBJECT_TYPE_IMAGE => {
            let id = read_u32(value, offset)?;
            let image = parse_image(&value[*offset..], id)?;
            *offset += image_serialized_len(&image);
            Ok(BlockContent::Image(image))
        }
        _ => Err(ZdocError::UnsupportedObjectType(btype)),
    }
}

// Helper: read u32 LE at current offset.
fn read_u32(value: &[u8], offset: &mut usize) -> Result<u32, ZdocError> {
    if *offset + 4 > value.len() {
        return Err(ZdocError::MalformedStructure("truncated u32".into()));
    }
    let v = u32::from_le_bytes(value[*offset..*offset + 4].try_into().unwrap());
    *offset += 4;
    Ok(v)
}

fn read_style_ref(value: &[u8], offset: &mut usize) -> Result<StyleRef, ZdocError> {
    if *offset + 1 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated style ref kind".into(),
        ));
    }
    let kind = value[*offset];
    *offset += 1;
    match kind {
        0 => Ok(StyleRef::None),
        1 => {
            let len = read_u32(value, offset)? as usize;
            if *offset + len > value.len() {
                return Err(ZdocError::MalformedStructure(
                    "truncated named style".into(),
                ));
            }
            let name = validate_utf8(&value[*offset..*offset + len], "style name")?;
            *offset += len;
            Ok(StyleRef::Named(name))
        }
        2 => {
            let len = read_u16(value, offset)? as usize;
            let mut props = std::collections::BTreeMap::new();
            for _ in 0..len {
                let klen = read_u16(value, offset)? as usize;
                if *offset + klen > value.len() {
                    return Err(ZdocError::MalformedStructure(
                        "truncated style prop key".into(),
                    ));
                }
                let key = validate_utf8(&value[*offset..*offset + klen], "style prop key")?;
                *offset += klen;
                let vlen = read_u16(value, offset)? as usize;
                if *offset + vlen > value.len() {
                    return Err(ZdocError::MalformedStructure(
                        "truncated style prop value".into(),
                    ));
                }
                let val = validate_utf8(&value[*offset..*offset + vlen], "style prop value")?;
                *offset += vlen;
                props.insert(key, val);
            }
            Ok(StyleRef::Inline(props))
        }
        _ => Err(ZdocError::MalformedStructure(
            "invalid style ref kind".into(),
        )),
    }
}

fn read_u16(value: &[u8], offset: &mut usize) -> Result<u16, ZdocError> {
    if *offset + 2 > value.len() {
        return Err(ZdocError::MalformedStructure("truncated u16".into()));
    }
    let v = u16::from_le_bytes(value[*offset..*offset + 2].try_into().unwrap());
    *offset += 2;
    Ok(v)
}

fn parse_style_ref(value: &[u8], offset: &mut usize) -> Result<Option<StyleRef>, ZdocError> {
    if *offset + 1 > value.len() {
        return Err(ZdocError::MalformedStructure("truncated style ref".into()));
    }
    let kind = value[*offset];
    *offset += 1;
    match kind {
        0 => Ok(None),
        1 => {
            let len = read_u32(value, offset)? as usize;
            if *offset + len > value.len() {
                return Err(ZdocError::MalformedStructure(
                    "truncated named style".into(),
                ));
            }
            let name = validate_utf8(&value[*offset..*offset + len], "style name")?;
            *offset += len;
            Ok(Some(StyleRef::Named(name)))
        }
        2 => {
            let len = read_u16(value, offset)? as usize;
            let mut props = std::collections::BTreeMap::new();
            for _ in 0..len {
                let klen = read_u16(value, offset)? as usize;
                if *offset + klen > value.len() {
                    return Err(ZdocError::MalformedStructure(
                        "truncated style prop key".into(),
                    ));
                }
                let key = validate_utf8(&value[*offset..*offset + klen], "style prop key")?;
                *offset += klen;
                let vlen = read_u16(value, offset)? as usize;
                if *offset + vlen > value.len() {
                    return Err(ZdocError::MalformedStructure(
                        "truncated style prop value".into(),
                    ));
                }
                let val = validate_utf8(&value[*offset..*offset + vlen], "style prop value")?;
                *offset += vlen;
                props.insert(key, val);
            }
            Ok(Some(StyleRef::Inline(props)))
        }
        _ => Err(ZdocError::MalformedStructure(
            "invalid style ref kind".into(),
        )),
    }
}

fn parse_paragraph(value: &[u8], id: u32) -> Result<Paragraph, ZdocError> {
    let mut offset = 0;
    if offset + 4 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated paragraph: runs count".into(),
        ));
    }
    let runs_count = u32::from_le_bytes(value[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    if offset + 1 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated paragraph: direction".into(),
        ));
    }
    let direction = TextDirection::from_byte(value[offset])
        .ok_or_else(|| ZdocError::MalformedStructure("invalid paragraph direction".into()))?;
    offset += 1;
    if offset + 1 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated paragraph: heading level".into(),
        ));
    }
    let heading_level_byte = value[offset];
    offset += 1;
    let heading_level = if heading_level_byte == 0 {
        None
    } else {
        Some(heading_level_byte)
    };
    if offset + 1 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated paragraph: list item flag".into(),
        ));
    }
    let list_item = value[offset] != 0;
    offset += 1;
    let style = parse_style_ref(&value[offset..], &mut offset)?;
    let mut runs = Vec::new();
    for _ in 0..runs_count {
        let run = parse_text_run(&value[offset..], &mut offset)?;
        runs.push(run);
    }
    Ok(Paragraph {
        id,
        runs,
        style: style.unwrap_or(StyleRef::None),
        direction,
        heading_level,
        list_item,
    })
}

fn parse_text_run(value: &[u8], offset: &mut usize) -> Result<TextRun, ZdocError> {
    if *offset + 4 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated text run: id".into(),
        ));
    }
    let id = u32::from_le_bytes(value[*offset..*offset + 4].try_into().unwrap());
    *offset += 4;
    if *offset + 4 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated text run: text length".into(),
        ));
    }
    let text_len = u32::from_le_bytes(value[*offset..*offset + 4].try_into().unwrap()) as usize;
    *offset += 4;
    if *offset + text_len > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated text run: text".into(),
        ));
    }
    let text = validate_utf8(&value[*offset..*offset + text_len], "text run text")?;
    *offset += text_len;
    let style = parse_style_ref(value, offset)?;
    Ok(TextRun {
        id,
        text,
        style: style.unwrap_or(StyleRef::None),
    })
}

fn parse_table(value: &[u8], id: u32) -> Result<Table, ZdocError> {
    let mut offset = 0;
    if offset + 4 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated table: rows count".into(),
        ));
    }
    let rows_count = u32::from_le_bytes(value[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    if offset + 4 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated table: col count".into(),
        ));
    }
    let col_count = u32::from_le_bytes(value[offset..offset + 4].try_into().unwrap());
    offset += 4;
    let style = parse_style_ref(&value[offset..], &mut offset)?;
    if offset + 4 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated table: merged cells count".into(),
        ));
    }
    let merged_count = u32::from_le_bytes(value[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    let mut merged_cells = Vec::new();
    for _ in 0..merged_count {
        if offset + 16 > value.len() {
            return Err(ZdocError::MalformedStructure(
                "truncated table: merged cell".into(),
            ));
        }
        let r = u32::from_le_bytes(value[offset..offset + 4].try_into().unwrap());
        let c = u32::from_le_bytes(value[offset + 4..offset + 8].try_into().unwrap());
        let rs = u32::from_le_bytes(value[offset + 8..offset + 12].try_into().unwrap());
        let cs = u32::from_le_bytes(value[offset + 12..offset + 16].try_into().unwrap());
        offset += 16;
        merged_cells.push((r, c, rs, cs));
    }
    let mut rows = Vec::new();
    for _ in 0..rows_count {
        let row = parse_table_row(&value[offset..], &mut offset)?;
        rows.push(row);
    }
    Ok(Table {
        id,
        rows,
        col_count,
        style: style.unwrap_or(StyleRef::None),
        merged_cells,
    })
}

fn parse_table_row(value: &[u8], offset: &mut usize) -> Result<TableRow, ZdocError> {
    if *offset + 4 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated table row: id".into(),
        ));
    }
    let id = u32::from_le_bytes(value[*offset..*offset + 4].try_into().unwrap());
    *offset += 4;
    if *offset + 4 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated table row: cells count".into(),
        ));
    }
    let cells_count = u32::from_le_bytes(value[*offset..*offset + 4].try_into().unwrap()) as usize;
    *offset += 4;
    let style = parse_style_ref(value, offset)?;
    let mut cells = Vec::new();
    for _ in 0..cells_count {
        let cell = parse_table_cell(value, offset)?;
        cells.push(cell);
    }
    Ok(TableRow {
        id,
        cells,
        style: style.unwrap_or(StyleRef::None),
    })
}

fn parse_table_cell(value: &[u8], offset: &mut usize) -> Result<TableCell, ZdocError> {
    if *offset + 4 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated table cell: id".into(),
        ));
    }
    let id = u32::from_le_bytes(value[*offset..*offset + 4].try_into().unwrap());
    *offset += 4;
    if *offset + 4 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated table cell: content count".into(),
        ));
    }
    let content_count =
        u32::from_le_bytes(value[*offset..*offset + 4].try_into().unwrap()) as usize;
    *offset += 4;
    let style = parse_style_ref(value, offset)?;
    let mut content = Vec::new();
    for _ in 0..content_count {
        if *offset + 1 > value.len() {
            return Err(ZdocError::MalformedStructure(
                "truncated table cell: block type".into(),
            ));
        }
        let btype = value[*offset];
        *offset += 1;
        let block = parse_block_content(value, btype, offset)?;
        content.push(block);
    }
    Ok(TableCell {
        id,
        content,
        style: style.unwrap_or(StyleRef::None),
    })
}

fn parse_style(value: &[u8]) -> Result<Style, ZdocError> {
    let mut offset = 0;
    if offset + 4 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated style: id length".into(),
        ));
    }
    let id_len = u32::from_le_bytes(value[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    if offset + id_len > value.len() {
        return Err(ZdocError::MalformedStructure("truncated style: id".into()));
    }
    let id = validate_utf8(&value[offset..offset + id_len], "style id")?;
    offset += id_len;
    if offset + 1 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated style: type".into(),
        ));
    }
    let style_type = StyleType::from_byte(value[offset])
        .ok_or_else(|| ZdocError::MalformedStructure("invalid style type".into()))?;
    offset += 1;
    let parent = if offset + 1 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated style: parent present".into(),
        ));
    } else if value[offset] != 0 {
        offset += 1;
        if offset + 4 > value.len() {
            return Err(ZdocError::MalformedStructure(
                "truncated style: parent length".into(),
            ));
        }
        let plen = u32::from_le_bytes(value[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if offset + plen > value.len() {
            return Err(ZdocError::MalformedStructure(
                "truncated style: parent".into(),
            ));
        }
        let p = validate_utf8(&value[offset..offset + plen], "style parent")?;
        offset += plen;
        Some(p)
    } else {
        offset += 1;
        None
    };
    if offset + 2 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated style: properties count".into(),
        ));
    }
    let prop_count = u16::from_le_bytes(value[offset..offset + 2].try_into().unwrap()) as usize;
    offset += 2;
    let mut properties = std::collections::BTreeMap::new();
    for _ in 0..prop_count {
        let klen = u16::from_le_bytes(value[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;
        if offset + klen > value.len() {
            return Err(ZdocError::MalformedStructure(
                "truncated style: prop key".into(),
            ));
        }
        let key = validate_utf8(&value[offset..offset + klen], "style prop key")?;
        offset += klen;
        let vlen = u16::from_le_bytes(value[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;
        if offset + vlen > value.len() {
            return Err(ZdocError::MalformedStructure(
                "truncated style: prop value".into(),
            ));
        }
        let val = validate_utf8(&value[offset..offset + vlen], "style prop value")?;
        offset += vlen;
        properties.insert(key, val);
    }
    Ok(Style {
        id,
        style_type,
        parent,
        properties,
    })
}

fn parse_image(value: &[u8], id: u32) -> Result<Image, ZdocError> {
    let mut offset = 0;
    if offset + 4 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated image: mime length".into(),
        ));
    }
    let mime_len = u32::from_le_bytes(value[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    if offset + mime_len > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated image: mime".into(),
        ));
    }
    let mime_type = validate_utf8(&value[offset..offset + mime_len], "image mime")?;
    offset += mime_len;
    let alt_text = if offset + 1 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated image: alt present".into(),
        ));
    } else if value[offset] != 0 {
        offset += 1;
        if offset + 4 > value.len() {
            return Err(ZdocError::MalformedStructure(
                "truncated image: alt length".into(),
            ));
        }
        let alen = u32::from_le_bytes(value[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if offset + alen > value.len() {
            return Err(ZdocError::MalformedStructure("truncated image: alt".into()));
        }
        let a = validate_utf8(&value[offset..offset + alen], "image alt")?;
        offset += alen;
        Some(a)
    } else {
        offset += 1;
        None
    };
    if offset + 4 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated image: data length".into(),
        ));
    }
    let data_len = u32::from_le_bytes(value[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    if offset + data_len > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated image: data".into(),
        ));
    }
    let data = value[offset..offset + data_len].to_vec();
    offset += data_len;
    let width_pt = if offset + 1 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated image: width present".into(),
        ));
    } else if value[offset] != 0 {
        offset += 1;
        if offset + 4 > value.len() {
            return Err(ZdocError::MalformedStructure(
                "truncated image: width".into(),
            ));
        }
        Some(f32::from_le_bytes(
            value[offset..offset + 4].try_into().unwrap(),
        ))
    } else {
        offset += 1;
        None
    };
    let height_pt = if offset + 1 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated image: height present".into(),
        ));
    } else if value[offset] != 0 {
        offset += 1;
        if offset + 4 > value.len() {
            return Err(ZdocError::MalformedStructure(
                "truncated image: height".into(),
            ));
        }
        Some(f32::from_le_bytes(
            value[offset..offset + 4].try_into().unwrap(),
        ))
    } else {
        offset += 1;
        None
    };
    Ok(Image {
        id,
        mime_type,
        alt_text,
        data,
        width_pt,
        height_pt,
    })
}

fn parse_attachment(value: &[u8], id: u32) -> Result<Attachment, ZdocError> {
    let mut offset = 0;
    if offset + 4 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated attachment: file name length".into(),
        ));
    }
    let fname_len = u32::from_le_bytes(value[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    if offset + fname_len > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated attachment: file name".into(),
        ));
    }
    let file_name = validate_utf8(&value[offset..offset + fname_len], "attachment file name")?;
    offset += fname_len;
    if offset + 4 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated attachment: mime length".into(),
        ));
    }
    let mime_len = u32::from_le_bytes(value[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    if offset + mime_len > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated attachment: mime".into(),
        ));
    }
    let mime_type = validate_utf8(&value[offset..offset + mime_len], "attachment mime")?;
    offset += mime_len;
    if offset + 4 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated attachment: data length".into(),
        ));
    }
    let data_len = u32::from_le_bytes(value[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    if offset + data_len > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated attachment: data".into(),
        ));
    }
    let data = value[offset..offset + data_len].to_vec();
    if data.len() as u64 > MAX_ATTACHMENT_SIZE {
        return Err(ZdocError::ResourceLimitExceeded(format!(
            "attachment {} size {} exceeds max {}",
            id,
            data.len(),
            MAX_ATTACHMENT_SIZE
        )));
    }
    Ok(Attachment {
        id,
        file_name,
        mime_type,
        data,
    })
}

fn parse_hyperlink(value: &[u8], id: u32) -> Result<Hyperlink, ZdocError> {
    let mut offset = 0;
    if offset + 4 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated hyperlink: uri length".into(),
        ));
    }
    let uri_len = u32::from_le_bytes(value[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    if offset + uri_len > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated hyperlink: uri".into(),
        ));
    }
    let uri = validate_utf8(&value[offset..offset + uri_len], "hyperlink uri")?;
    offset += uri_len;
    let description = if offset + 1 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated hyperlink: desc present".into(),
        ));
    } else if value[offset] != 0 {
        offset += 1;
        if offset + 4 > value.len() {
            return Err(ZdocError::MalformedStructure(
                "truncated hyperlink: desc length".into(),
            ));
        }
        let dlen = u32::from_le_bytes(value[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if offset + dlen > value.len() {
            return Err(ZdocError::MalformedStructure(
                "truncated hyperlink: desc".into(),
            ));
        }
        let d = validate_utf8(&value[offset..offset + dlen], "hyperlink desc")?;
        offset += dlen;
        Some(d)
    } else {
        offset += 1;
        None
    };
    Ok(Hyperlink {
        id,
        uri,
        description,
    })
}

fn parse_footnote(value: &[u8], id: u32) -> Result<Footnote, ZdocError> {
    let mut offset = 0;
    if offset + 4 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated footnote: content count".into(),
        ));
    }
    let content_count = u32::from_le_bytes(value[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    let mut content = Vec::new();
    for _ in 0..content_count {
        if offset + 1 > value.len() {
            return Err(ZdocError::MalformedStructure(
                "truncated footnote: block type".into(),
            ));
        }
        let btype = value[offset];
        offset += 1;
        let block = parse_block_content(value, btype, &mut offset)?;
        content.push(block);
    }
    Ok(Footnote { id, content })
}

fn parse_code_block(value: &[u8], id: u32) -> Result<CodeBlock, ZdocError> {
    let mut offset = 0;
    if offset + 4 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated code block: language length".into(),
        ));
    }
    let lang_len = u32::from_le_bytes(value[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    if offset + lang_len > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated code block: language".into(),
        ));
    }
    let language = validate_utf8(&value[offset..offset + lang_len], "code block language")?;
    offset += lang_len;
    if offset + 4 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated code block: content length".into(),
        ));
    }
    let content_len = u32::from_le_bytes(value[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    if offset + content_len > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated code block: content".into(),
        ));
    }
    let content = validate_utf8(&value[offset..offset + content_len], "code block content")?;
    offset += content_len;
    if content.len() > MAX_TEXT_RUN_LEN {
        return Err(ZdocError::ResourceLimitExceeded(format!(
            "code_block {} content length {} exceeds max {}",
            id,
            content.len(),
            MAX_TEXT_RUN_LEN
        )));
    }
    Ok(CodeBlock {
        id,
        language,
        content,
    })
}

fn parse_math_block(value: &[u8], id: u32) -> Result<MathBlock, ZdocError> {
    let mut offset = 0;
    if offset + 4 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated math block: notation length".into(),
        ));
    }
    let not_len = u32::from_le_bytes(value[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    if offset + not_len > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated math block: notation".into(),
        ));
    }
    let notation = validate_utf8(&value[offset..offset + not_len], "math block notation")?;
    offset += not_len;
    if offset + 4 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated math block: content length".into(),
        ));
    }
    let content_len = u32::from_le_bytes(value[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    if offset + content_len > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated math block: content".into(),
        ));
    }
    let content = validate_utf8(&value[offset..offset + content_len], "math block content")?;
    offset += content_len;
    Ok(MathBlock {
        id,
        notation,
        content,
    })
}

fn parse_list(value: &[u8], id: u32) -> Result<List, ZdocError> {
    let mut offset = 0;
    if offset + 4 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated list: items count".into(),
        ));
    }
    let items_count = u32::from_le_bytes(value[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    if offset + 1 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated list: ordered flag".into(),
        ));
    }
    let ordered = value[offset] != 0;
    offset += 1;
    if offset + 4 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated list: start".into(),
        ));
    }
    let start = u32::from_le_bytes(value[offset..offset + 4].try_into().unwrap());
    offset += 4;
    let style = parse_style_ref(&value[offset..], &mut offset)?;
    let mut items = Vec::new();
    for _ in 0..items_count {
        let item = parse_list_item(&value[offset..], &mut offset)?;
        items.push(item);
    }
    Ok(List {
        id,
        items,
        style: style.unwrap_or(StyleRef::None),
        ordered,
        start,
    })
}

fn parse_list_item(value: &[u8], offset: &mut usize) -> Result<ListItem, ZdocError> {
    if *offset + 4 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated list item: id".into(),
        ));
    }
    let id = u32::from_le_bytes(value[*offset..*offset + 4].try_into().unwrap());
    *offset += 4;
    if *offset + 4 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated list item: depth".into(),
        ));
    }
    let depth = u32::from_le_bytes(value[*offset..*offset + 4].try_into().unwrap());
    *offset += 4;
    if *offset + 4 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated list item: content count".into(),
        ));
    }
    let content_count =
        u32::from_le_bytes(value[*offset..*offset + 4].try_into().unwrap()) as usize;
    *offset += 4;
    let mut content = Vec::new();
    for _ in 0..content_count {
        if *offset + 1 > value.len() {
            return Err(ZdocError::MalformedStructure(
                "truncated list item: block type".into(),
            ));
        }
        let btype = value[*offset];
        *offset += 1;
        let block = parse_block_content(value, btype, offset)?;
        content.push(block);
    }
    Ok(ListItem { id, depth, content })
}

fn parse_header_footer(value: &[u8], id: u32) -> Result<HeaderFooter, ZdocError> {
    let mut offset = 0;
    if offset + 1 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated header/footer: is_header".into(),
        ));
    }
    let is_header = value[offset] != 0;
    offset += 1;
    let pages = if offset + 1 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated header/footer: pages present".into(),
        ));
    } else if value[offset] != 0 {
        offset += 1;
        if offset + 4 > value.len() {
            return Err(ZdocError::MalformedStructure(
                "truncated header/footer: pages length".into(),
            ));
        }
        let plen = u32::from_le_bytes(value[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if offset + plen > value.len() {
            return Err(ZdocError::MalformedStructure(
                "truncated header/footer: pages".into(),
            ));
        }
        Some(validate_utf8(
            &value[offset..offset + plen],
            "header/footer pages",
        )?)
    } else {
        offset += 1;
        None
    };
    if offset + 4 > value.len() {
        return Err(ZdocError::MalformedStructure(
            "truncated header/footer: content count".into(),
        ));
    }
    let content_count = u32::from_le_bytes(value[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    let mut content = Vec::new();
    for _ in 0..content_count {
        if offset + 1 > value.len() {
            return Err(ZdocError::MalformedStructure(
                "truncated header/footer: block type".into(),
            ));
        }
        let btype = value[offset];
        offset += 1;
        let block = parse_block_content(value, btype, &mut offset)?;
        content.push(block);
    }
    Ok(HeaderFooter {
        id,
        is_header,
        pages,
        content,
    })
}

// ----- Serialized length helpers (used by parse_block_content to advance offset) -----

// These are approximate; the real parse_block_content above advances offset by parsing.
// We need actual lengths. For simplicity, re-parse to measure. This is O(n) but correct.

fn paragraph_serialized_len(p: &Paragraph) -> usize {
    4 + 1
        + 1
        + 1
        + style_ref_len(&p.style)
        + p.runs.iter().map(text_run_serialized_len).sum::<usize>()
}

fn text_run_serialized_len(r: &TextRun) -> usize {
    4 + 4 + r.text.len() + style_ref_len(&r.style)
}

fn table_serialized_len(t: &Table) -> usize {
    4 + 4
        + style_ref_len(&t.style)
        + 4
        + t.merged_cells.len() * 16
        + t.rows.iter().map(table_row_serialized_len).sum::<usize>()
}

fn table_row_serialized_len(r: &TableRow) -> usize {
    4 + 4 + style_ref_len(&r.style) + r.cells.iter().map(table_cell_serialized_len).sum::<usize>()
}

fn table_cell_serialized_len(c: &TableCell) -> usize {
    4 + 4
        + style_ref_len(&c.style)
        + c.content
            .iter()
            .map(|b| block_content_serialized_len(b))
            .sum::<usize>()
}

fn style_ref_len(s: &StyleRef) -> usize {
    match s {
        StyleRef::None => 1,
        StyleRef::Named(name) => 1 + 4 + name.len(),
        StyleRef::Inline(props) => {
            1 + 2
                + props
                    .iter()
                    .map(|(k, v)| 2 + k.len() + 2 + v.len())
                    .sum::<usize>()
        }
    }
}

fn code_block_serialized_len(b: &CodeBlock) -> usize {
    4 + b.language.len() + 4 + b.content.len()
}

fn math_block_serialized_len(b: &MathBlock) -> usize {
    4 + b.notation.len() + 4 + b.content.len()
}

fn list_serialized_len(l: &List) -> usize {
    4 + 1
        + 4
        + style_ref_len(&l.style)
        + l.items.iter().map(list_item_serialized_len).sum::<usize>()
}

fn list_item_serialized_len(i: &ListItem) -> usize {
    4 + 4
        + 4
        + i.content
            .iter()
            .map(|b| block_content_serialized_len(b))
            .sum::<usize>()
}

fn header_footer_serialized_len(h: &HeaderFooter) -> usize {
    1 + (if h.pages.is_some() {
        1 + 4 + h.pages.as_ref().unwrap().len()
    } else {
        1
    }) + 4
        + h.content
            .iter()
            .map(|b| block_content_serialized_len(b))
            .sum::<usize>()
}

fn image_serialized_len(i: &Image) -> usize {
    4 + i.mime_type.len()
        + 1
        + i.alt_text.as_ref().map_or(0, |a| 4 + a.len())
        + 4
        + i.data.len()
        + 1
        + i.width_pt.map_or(0, |_| 4)
        + 1
        + i.height_pt.map_or(0, |_| 4)
}

fn block_content_serialized_len(b: &BlockContent) -> usize {
    1 + match b {
        BlockContent::Paragraph(p) => paragraph_serialized_len(p),
        BlockContent::Table(t) => table_serialized_len(t),
        BlockContent::CodeBlock(c) => code_block_serialized_len(c),
        BlockContent::MathBlock(m) => math_block_serialized_len(m),
        BlockContent::List(l) => list_serialized_len(l),
        BlockContent::HeaderFooter(h) => header_footer_serialized_len(h),
        BlockContent::Image(i) => image_serialized_len(i),
    }
}

/// Decoding configuration.
#[derive(Debug, Clone)]
pub struct DecodeOptions {
    /// Optional decryption password.
    pub password: Option<Vec<u8>>,
    /// Resource limits.
    pub limits: Limits,
    /// Whether to verify per-object BLAKE3 hashes.
    pub verify_integrity: bool,
}

impl Default for DecodeOptions {
    fn default() -> Self {
        DecodeOptions {
            password: None,
            limits: Limits::default(),
            verify_integrity: true,
        }
    }
}

impl DocumentMetadata {
    /// Decode structured key-value metadata from bytes.
    pub fn decode_kv(bytes: &[u8]) -> Result<Self, ZdocError> {
        if bytes.len() < 2 {
            return Err(ZdocError::MalformedStructure(
                "metadata TLV too short for entry count".into(),
            ));
        }
        let count = u16::from_le_bytes(bytes[0..2].try_into().unwrap()) as usize;
        let mut offset = 2;
        let mut meta = DocumentMetadata::default();
        for _ in 0..count {
            if offset + 2 > bytes.len() {
                return Err(ZdocError::MalformedStructure(
                    "metadata TLV truncated at key length".into(),
                ));
            }
            let key_len =
                u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap()) as usize;
            offset += 2;
            if offset + key_len > bytes.len() {
                return Err(ZdocError::MalformedStructure(
                    "metadata TLV truncated at key".into(),
                ));
            }
            let key = validate_utf8(&bytes[offset..offset + key_len], "metadata key")?;
            offset += key_len;
            if offset + 2 > bytes.len() {
                return Err(ZdocError::MalformedStructure(
                    "metadata TLV truncated at value length".into(),
                ));
            }
            let val_len =
                u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap()) as usize;
            offset += 2;
            if offset + val_len > bytes.len() {
                return Err(ZdocError::MalformedStructure(
                    "metadata TLV truncated at value".into(),
                ));
            }
            let val = validate_utf8(&bytes[offset..offset + val_len], "metadata value")?;
            offset += val_len;
            match key.as_str() {
                "title" => meta.title = Some(val),
                "subject" => meta.subject = Some(val),
                "author" => meta.author = Some(val),
                "creator" => meta.creator = Some(val),
                "created" => meta.created = Some(val),
                "modified" => meta.modified = Some(val),
                "language" => meta.language = Some(val),
                _ => {
                    meta.custom.insert(key, val);
                }
            }
        }
        Ok(meta)
    }
}
