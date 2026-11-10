//! ZDOC document serialization: DOM -> bytes.
//!
//! The payload is encoded as a sequence of tagged objects. Each object is:
//!   type: u8 | id: u32 LE | length: u32 LE | value: bytes
//! Objects are written sequentially. The object index (footer) maps object
//! IDs to payload offsets for random-access decoding.

use crate::dom::{
    Attachment, BlockContent, CodeBlock, Document, Footnote, HeaderFooter, Hyperlink, Image, List,
    ListItem, MathBlock, Paragraph, Section, Style, StyleRef, Table, TableCell, TableRow,
    TextDirection, TextRun,
};
use crate::error::ZdocError;
use crate::format::{
    MAX_ATTACHMENT_SIZE, MAX_TEXT_RUN_LEN, OBJECT_INDEX_ENTRY_LEN,
    OBJECT_TYPE_ATTACHMENT, OBJECT_TYPE_CODE_BLOCK, OBJECT_TYPE_FOOTNOTE, OBJECT_TYPE_HYPERLINK,
    OBJECT_TYPE_IMAGE, OBJECT_TYPE_LIST, OBJECT_TYPE_LIST_ITEM, OBJECT_TYPE_MATH_BLOCK,
    OBJECT_TYPE_PARAGRAPH, OBJECT_TYPE_SECTION, OBJECT_TYPE_STYLE, OBJECT_TYPE_TABLE,
    OBJECT_TYPE_TABLE_CELL, OBJECT_TYPE_TABLE_ROW, OBJECT_TYPE_TEXT_RUN,
};
use znf_compression::{compress_bytes, Algorithm, Config as CompConfig};
use znf_core::{Flags, FormatId, Header, ZnfCompression, ZnfEncryption, HEADER_LEN};
use znf_crypto::{encrypt, generate_nonce, KdfParams, NONCE_LEN};
use znf_integrity::{hash, Hasher, HASH_LEN};

/// Serialized document output, ready to be written to a file.
#[derive(Debug, Clone)]
pub struct SerializedDocument {
    /// Raw file bytes (header + metadata + payload + footer).
    pub bytes: Vec<u8>,
    /// Document info returned after serialization.
    pub info: DocumentInfo,
}

/// Information about a serialized document.
#[derive(Debug, Clone)]
pub struct DocumentInfo {
    pub document_id: [u8; 16],
    pub object_count: usize,
    pub uncompressed_len: u64,
    pub stored_len: u64,
    pub encrypted: bool,
}

/// Serialize a `Document` into ZDOC file bytes.
pub fn serialize_document(
    document: &Document,
    compression: &CompConfig,
    password: Option<&[u8]>,
    kdf_params: Option<&KdfParams>,
) -> Result<SerializedDocument, ZdocError> {
    // Validate the document before serializing.
    document.validate()?;

    // Serialize each object into the payload.
    let mut payload = Vec::new();
    let mut object_index: Vec<(u32, u8, u64, u32, u32, Hash)> = Vec::new();
    let mut total_uncompressed: u64 = 0;

    // Write document-level metadata objects first (document_id, title, etc. as object 0).
    // We write the document header object.
    let doc_header = serialize_document_header(document)?;
    let (offset, stored, hash) = write_object(
        &mut payload,
        OBJECT_TYPE_SECTION, // document root is a pseudo-section
        0,
        &doc_header,
        compression,
    )?;
    object_index.push((0, OBJECT_TYPE_SECTION, offset, stored.len() as u32, doc_header.len() as u32, hash));
    total_uncompressed += doc_header.len() as u64;

    // Serialize sections.
    for section in &document.sections {
        let data = serialize_section(section)?;
        let (offset, stored, hash) = write_object(
            &mut payload,
            OBJECT_TYPE_SECTION,
            section.id,
            &data,
            compression,
        )?;
        object_index.push((section.id, OBJECT_TYPE_SECTION, offset, stored.len() as u32, data.len() as u32, hash));
        total_uncompressed += data.len() as u64;
    }

    // Serialize styles.
    for style in &document.styles {
        let data = serialize_style(style)?;
        let (offset, stored, hash) = write_object(
            &mut payload,
            OBJECT_TYPE_STYLE,
            style.id.parse::<u32>().unwrap_or(0),
            &data,
            compression,
        )?;
        object_index.push((
            style.id.parse::<u32>().unwrap_or(0),
            OBJECT_TYPE_STYLE,
            offset,
            stored.len() as u32,
            data.len() as u32,
            hash,
        ));
        total_uncompressed += data.len() as u64;
    }

    // Serialize images.
    for (id, image) in &document.images {
        let data = serialize_image(image)?;
        let (offset, stored, hash) = write_object(
            &mut payload,
            OBJECT_TYPE_IMAGE,
            *id,
            &data,
            compression,
        )?;
        object_index.push((*id, OBJECT_TYPE_IMAGE, offset, stored.len() as u32, data.len() as u32, hash));
        total_uncompressed += data.len() as u64;
    }

    // Serialize attachments.
    for (id, attachment) in &document.attachments {
        let data = serialize_attachment(attachment)?;
        let (offset, stored, hash) = write_object(
            &mut payload,
            OBJECT_TYPE_ATTACHMENT,
            *id,
            &data,
            compression,
        )?;
        object_index.push((
            *id,
            OBJECT_TYPE_ATTACHMENT,
            offset,
            stored.len() as u32,
            data.len() as u32,
            hash,
        ));
        total_uncompressed += data.len() as u64;
    }

    // Serialize hyperlinks.
    for (id, hyperlink) in &document.hyperlinks {
        let data = serialize_hyperlink(hyperlink)?;
        let (offset, stored, hash) = write_object(
            &mut payload,
            OBJECT_TYPE_HYPERLINK,
            *id,
            &data,
            compression,
        )?;
        object_index.push((
            *id,
            OBJECT_TYPE_HYPERLINK,
            offset,
            stored.len() as u32,
            data.len() as u32,
            hash,
        ));
        total_uncompressed += data.len() as u64;
    }

    // Serialize footnotes.
    for (id, footnote) in &document.footnotes {
        let data = serialize_footnote(footnote)?;
        let (offset, stored, hash) = write_object(
            &mut payload,
            OBJECT_TYPE_FOOTNOTE,
            *id,
            &data,
            compression,
        )?;
        object_index.push((
            *id,
            OBJECT_TYPE_FOOTNOTE,
            offset,
            stored.len() as u32,
            data.len() as u32,
            hash,
        ));
        total_uncompressed += data.len() as u64;
    }

    // Serialize code blocks.
    for (id, code_block) in &document.code_blocks {
        let data = serialize_code_block(code_block)?;
        let (offset, stored, hash) = write_object(
            &mut payload,
            OBJECT_TYPE_CODE_BLOCK,
            *id,
            &data,
            compression,
        )?;
        object_index.push((
            *id,
            OBJECT_TYPE_CODE_BLOCK,
            offset,
            stored.len() as u32,
            data.len() as u32,
            hash,
        ));
        total_uncompressed += data.len() as u64;
    }

    // Serialize math blocks.
    for (id, math_block) in &document.math_blocks {
        let data = serialize_math_block(math_block)?;
        let (offset, stored, hash) = write_object(
            &mut payload,
            OBJECT_TYPE_MATH_BLOCK,
            *id,
            &data,
            compression,
        )?;
        object_index.push((
            *id,
            OBJECT_TYPE_MATH_BLOCK,
            offset,
            stored.len() as u32,
            data.len() as u32,
            hash,
        ));
        total_uncompressed += data.len() as u64;
    }

    // Serialize lists.
    for (id, list) in &document.lists {
        let data = serialize_list(list)?;
        let (offset, stored, hash) = write_object(
            &mut payload,
            OBJECT_TYPE_LIST,
            *id,
            &data,
            compression,
        )?;
        object_index.push((*id, OBJECT_TYPE_LIST, offset, stored.len() as u32, data.len() as u32, hash));
        total_uncompressed += data.len() as u64;
    }

    // Serialize headers/footers.
    for (id, hf) in &document.headers_footers {
        let data = serialize_header_footer(hf)?;
        let (offset, stored, hash) = write_object(
            &mut payload,
            OBJECT_TYPE_HEADER_FOOTER,
            *id,
            &data,
            compression,
        )?;
        object_index.push((
            *id,
            OBJECT_TYPE_HEADER_FOOTER,
            offset,
            stored.len() as u32,
            data.len() as u32,
            hash,
        ));
        total_uncompressed += data.len() as u64;
    }

    // Encrypt if requested.
    let derived_key = if let Some(pw) = password {
        let params = kdf_params
            .ok_or_else(|| ZdocError::EncryptionMismatch("password set but no KDF params"))?;
        Some(params.derive_key(pw)?)
    } else {
        None
    };

    // Apply encryption to stored payload chunks if key is present.
    let mut encrypted_payload = Vec::new();
    let mut chunk_stored_lens: Vec<u32> = Vec::new();
    let mut chunk_stored_offsets: Vec<u64> = Vec::new();

    if let Some(ref key) = derived_key {
        // Encrypt each stored chunk separately with per-chunk nonce.
        // For simplicity, encrypt the whole payload as one chunk with chunk index 0.
        let nonce = generate_nonce()?;
        let aad = 0u32.to_le_bytes().to_vec();
        let encrypted = encrypt(key, &nonce, &payload, &aad)?;
        encrypted_payload.extend_from_slice(&nonce);
        encrypted_payload.extend_from_slice(&encrypted);
        chunk_stored_offsets.push(0);
        chunk_stored_lens.push((NONCE_LEN + encrypted.len()) as u32);
    } else {
        encrypted_payload = payload.clone();
        // stored_lens will be filled from object_index
        for (_, _, offset, stored_len, _, _) in &object_index {
            chunk_stored_offsets.push(*offset);
            chunk_stored_lens.push(*stored_len);
        }
    }

    let payload_len = encrypted_payload.len() as u64;

    // Build metadata section TLVs.
    let mut metadata_bytes = Vec::new();

    // Document ID.
    {
        let mut buf = Vec::new();
        buf.extend_from_slice(&document.document_id);
        write_tlv(&mut metadata_bytes, crate::format::TLV_ZDOC_DOCUMENT_ID, &buf);
    }

    // Title.
    if let Some(ref title) = document.title {
        write_tlv(&mut metadata_bytes, crate::format::TLV_ZDOC_TITLE, title.as_bytes());
    }
    // Subject.
    if let Some(ref subject) = document.subject {
        write_tlv(&mut metadata_bytes, crate::format::TLV_ZDOC_SUBJECT, subject.as_bytes());
    }
    // Author.
    if let Some(ref author) = document.author {
        write_tlv(&mut metadata_bytes, crate::format::TLV_ZDOC_AUTHOR, author.as_bytes());
    }
    // Creator.
    if let Some(ref creator) = document.creator {
        write_tlv(&mut metadata_bytes, crate::format::TLV_ZDOC_CREATOR, creator.as_bytes());
    }
    // Created.
    if let Some(ref created) = document.created {
        write_tlv(&mut metadata_bytes, crate::format::TLV_ZDOC_CREATED, created.as_bytes());
    }
    // Modified.
    if let Some(ref modified) = document.modified {
        write_tlv(&mut metadata_bytes, crate::format::TLV_ZDOC_MODIFIED, modified.as_bytes());
    }
    // Language.
    if let Some(ref language) = document.language {
        write_tlv(&mut metadata_bytes, crate::format::TLV_ZDOC_LANGUAGE, language.as_bytes());
    }

    // Structured key-value metadata.
    if !document.metadata.is_empty() {
        let kv = encode_metadata_kv(&document.metadata);
        write_tlv(&mut metadata_bytes, crate::format::TLV_ZDOC_METADATA_KV, &kv);
    }

    let meta_len = metadata_bytes.len() as u64;

    // Build footer section.
    let mut footer = Vec::new();

    // Object index.
    {
        let mut idx = Vec::new();
        idx.extend_from_slice(&(object_index.len() as u32).to_le_bytes());
        for (oid, otype, offset, stored_len, uncompressed_len, hash) in &object_index {
            let mut entry = Vec::new();
            entry.extend_from_slice(&oid.to_le_bytes());
            entry.push(*otype);
            entry.extend_from_slice(&offset.to_le_bytes());
            entry.extend_from_slice(&stored_len.to_le_bytes());
            entry.extend_from_slice(&uncompressed_len.to_le_bytes());
            entry.extend_from_slice(hash.as_bytes());
            debug_assert_eq!(entry.len(), OBJECT_INDEX_ENTRY_LEN);
            idx.extend_from_slice(&entry);
        }
        write_tlv(&mut footer, crate::format::TLV_ZDOC_OBJECT_INDEX, &idx);
    }

    // Per-object BLAKE3 hashes.
    {
        let mut hashes = Vec::new();
        hashes.extend_from_slice(&(object_index.len() as u32).to_le_bytes());
        for (_, _, _, _, _, hash) in &object_index {
            hashes.extend_from_slice(hash.as_bytes());
        }
        write_tlv(&mut footer, crate::format::TLV_ZDOC_OBJECT_BLAKE3, &hashes);
    }

    // Build flags.
    let mut flags = Flags::default();
    flags.set(Flags::HAS_METADATA, meta_len > 0);
    flags.set(Flags::HAS_FOOTER, true);
    if compression.algorithm != Algorithm::None {
        flags.set(Flags::COMPRESSED, true);
    }
    if derived_key.is_some() {
        flags.set(Flags::ENCRYPTED, true);
    }

    // Build header.
    let mut hdr = Header::new(FormatId::from_raw(FORMAT_ID_ZDOC).unwrap(), 1, 0);
    hdr.flags_mut().set(Flags::HAS_METADATA, meta_len > 0);
    hdr.flags_mut().set(Flags::HAS_FOOTER, true);
    hdr.set_compression(ZnfCompression::from_algorithm(compression.algorithm));
    if derived_key.is_some() {
        hdr.set_encryption(ZnfEncryption::XChaCha20Poly1305);
    }
    let payload_offset = HEADER_LEN as u64 + meta_len;
    hdr.set_payload_span(payload_offset, payload_len);

    let mut header_bytes = [0u8; HEADER_LEN];
    hdr.encode(&mut header_bytes)?;

    // Compute whole-archive BLAKE3 over header || metadata || payload.
    let mut hasher = Hasher::new();
    hasher.update(&header_bytes);
    hasher.update(&metadata_bytes);
    hasher.update(&encrypted_payload);
    let archive_hash = hasher.finalize();

    // Add archive BLAKE3 to footer.
    footer.extend_from_slice(&(TLV_ARCHIVE_BLAKE3 as u16).to_le_bytes());
    footer.extend_from_slice(&(HASH_LEN as u32).to_le_bytes());
    footer.extend_from_slice(archive_hash.as_bytes());

    // Add TLV_END.
    footer.extend_from_slice(&0xFFFFu16.to_le_bytes());
    footer.extend_from_slice(&0u32.to_le_bytes());

    // Assemble final file.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&header_bytes);
    bytes.extend_from_slice(&metadata_bytes);
    bytes.extend_from_slice(&encrypted_payload);
    bytes.extend_from_slice(&footer);

    Ok(SerializedDocument {
        bytes,
        info: DocumentInfo {
            document_id: document.document_id,
            object_count: object_index.len(),
            uncompressed_len: total_uncompressed,
            stored_len: payload_len,
            encrypted: derived_key.is_some(),
        },
    })
}

/// Write a single tagged object to the payload, compressing if configured.
fn write_object(
    payload: &mut Vec<u8>,
    otype: u8,
    id: u32,
    data: &[u8],
    compression: &CompConfig,
) -> Result<(u64, Vec<u8>, Hash), ZdocError> {
    let offset = payload.len() as u64;

    // Build the object frame: type | id | length | value
    let mut frame = Vec::new();
    frame.push(otype);
    frame.extend_from_slice(&id.to_le_bytes());
    frame.extend_from_slice(&(data.len() as u32).to_le_bytes());
    frame.extend_from_slice(data);

    let hash = hash(&frame);

    // Compress the frame if configured.
    let stored = match compression.algorithm {
        Algorithm::None => frame,
        Algorithm::Zstd | Algorithm::Lz4 => compress_bytes(&frame, compression)?,
    };

    payload.extend_from_slice(&stored);
    Ok((offset, stored, hash))
}

/// Encode structured key-value metadata into deterministic bytes.
fn encode_metadata_kv(metadata: &std::collections::BTreeMap<String, String>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(metadata.len() as u16).to_le_bytes());
    for (key, val) in metadata {
        let kb = key.as_bytes();
        let vb = val.as_bytes();
        out.extend_from_slice(&(kb.len() as u16).to_le_bytes());
        out.extend_from_slice(kb);
        out.extend_from_slice(&(vb.len() as u16).to_le_bytes());
        out.extend_from_slice(vb);
    }
    out
}

/// Write a TLV record to a buffer.
fn write_tlv(buf: &mut Vec<u8>, ty: u16, value: &[u8]) {
    buf.extend_from_slice(&ty.to_le_bytes());
    buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
    buf.extend_from_slice(value);
}

// ----- Object serialization helpers -----

fn serialize_document_header(document: &Document) -> Result<Vec<u8>, ZdocError> {
    let mut out = Vec::new();
    // Page count.
    out.extend_from_slice(&(document.sections.len() as u32).to_le_bytes());
    // Object count.
    out.extend_from_slice(&(document.object_count() as u32).to_le_bytes());
    // Page numbering style.
    out.extend_from_slice(&(document.page_numbering.style.len() as u16).to_le_bytes());
    out.extend_from_slice(document.page_numbering.style.as_bytes());
    out.extend_from_slice(&document.page_numbering.start.to_le_bytes());
    out.extend_from_slice(&document.page_numbering.display as u8).to_le_bytes();
    Ok(out)
}

fn serialize_section(section: &Section) -> Result<Vec<u8>, ZdocError> {
    let mut out = Vec::new();
    out.extend_from_slice(&(section.content.len() as u32).to_le_bytes());
    out.extend_from_slice(&(section.depth as u32).to_le_bytes());
    out.push(section.page_break_before as u8);
    // Heading.
    match &section.heading {
        Some(h) => {
            out.push(1);
            out.extend_from_slice(&(h.len() as u32).to_le_bytes());
            out.extend_from_slice(h.as_bytes());
        }
        None => out.push(0),
    }
    // Style.
    serialize_style_ref(&mut out, &section.style)?;
    // Content blocks.
    for block in &section.content {
        serialize_block_content(&mut out, block)?;
    }
    Ok(out)
}

fn serialize_block_content(out: &mut Vec<u8>, block: &BlockContent) -> Result<(), ZdocError> {
    match block {
        BlockContent::Paragraph(p) => {
            out.push(OBJECT_TYPE_PARAGRAPH);
            serialize_paragraph(out, p)?;
        }
        BlockContent::Table(t) => {
            out.push(OBJECT_TYPE_TABLE);
            serialize_table(out, t)?;
        }
        BlockContent::CodeBlock(c) => {
            out.push(OBJECT_TYPE_CODE_BLOCK);
            serialize_code_block_inline(out, c)?;
        }
        BlockContent::MathBlock(m) => {
            out.push(OBJECT_TYPE_MATH_BLOCK);
            serialize_math_block_inline(out, m)?;
        }
        BlockContent::List(l) => {
            out.push(OBJECT_TYPE_LIST);
            serialize_list_inline(out, l)?;
        }
        BlockContent::HeaderFooter(h) => {
            out.push(OBJECT_TYPE_HEADER_FOOTER);
            serialize_header_footer_inline(out, h)?;
        }
        BlockContent::Image(i) => {
            out.push(OBJECT_TYPE_IMAGE);
            serialize_image_inline(out, i)?;
        }
    }
    Ok(())
}

fn serialize_paragraph(out: &mut Vec<u8>, p: &Paragraph) -> Result<(), ZdocError> {
    out.extend_from_slice(&p.id.to_le_bytes());
    let runs_len = p.runs.len() as u32;
    out.extend_from_slice(&runs_len.to_le_bytes());
    out.push(p.direction.as_byte());
    out.push(p.heading_level.map_or(0, |l| l));
    out.push(p.list_item as u8);
    serialize_style_ref(out, &p.style)?;
    for run in &p.runs {
        serialize_text_run(out, run)?;
    }
    Ok(())
}

fn serialize_text_run(out: &mut Vec<u8>, run: &TextRun) -> Result<(), ZdocError> {
    out.extend_from_slice(&run.id.to_le_bytes());
    let tb = run.text.as_bytes();
    if tb.len() > MAX_TEXT_RUN_LEN {
        return Err(ZdocError::ResourceLimitExceeded(format!(
            "text_run {} length {} exceeds max {}",
            run.id, tb.len(), MAX_TEXT_RUN_LEN
        )));
    }
    out.extend_from_slice(&(tb.len() as u32).to_le_bytes());
    out.extend_from_slice(tb);
    serialize_style_ref(out, &run.style)?;
    Ok(())
}

fn serialize_table(out: &mut Vec<u8>, t: &Table) -> Result<(), ZdocError> {
    out.extend_from_slice(&t.id.to_le_bytes());
    out.extend_from_slice(&(t.rows.len() as u32).to_le_bytes());
    out.extend_from_slice(&t.col_count.to_le_bytes());
    serialize_style_ref(out, &t.style)?;
    out.extend_from_slice(&(t.merged_cells.len() as u32).to_le_bytes());
    for (r, c, rs, cs) in &t.merged_cells {
        out.extend_from_slice(&r.to_le_bytes());
        out.extend_from_slice(&c.to_le_bytes());
        out.extend_from_slice(&rs.to_le_bytes());
        out.extend_from_slice(&cs.to_le_bytes());
    }
    for row in &t.rows {
        serialize_table_row(out, row)?;
    }
    Ok(())
}

fn serialize_table_row(out: &mut Vec<u8>, row: &TableRow) -> Result<(), ZdocError> {
    out.extend_from_slice(&row.id.to_le_bytes());
    out.extend_from_slice(&(row.cells.len() as u32).to_le_bytes());
    serialize_style_ref(out, &row.style)?;
    for cell in &row.cells {
        serialize_table_cell(out, cell)?;
    }
    Ok(())
}

fn serialize_table_cell(out: &mut Vec<u8>, cell: &TableCell) -> Result<(), ZdocError> {
    out.extend_from_slice(&cell.id.to_le_bytes());
    out.extend_from_slice(&(cell.content.len() as u32).to_le_bytes());
    serialize_style_ref(out, &cell.style)?;
    for block in &cell.content {
        serialize_block_content(out, block)?;
    }
    Ok(())
}

fn serialize_style_ref(out: &mut Vec<u8>, style: &StyleRef) -> Result<(), ZdocError> {
    match style {
        StyleRef::Named(name) => {
            out.push(1);
            out.extend_from_slice(&(name.len() as u32).to_le_bytes());
            out.extend_from_slice(name.as_bytes());
        }
        StyleRef::Inline(props) => {
            out.push(2);
            out.extend_from_slice(&(props.len() as u16).to_le_bytes());
            for (k, v) in props {
                let kb = k.as_bytes();
                let vb = v.as_bytes();
                out.extend_from_slice(&(kb.len() as u16).to_le_bytes());
                out.extend_from_slice(kb);
                out.extend_from_slice(&(vb.len() as u16).to_le_bytes());
                out.extend_from_slice(vb);
            }
        }
        StyleRef::None => out.push(0),
    }
    Ok(())
}

fn serialize_style(out: &mut Vec<u8>, style: &Style) -> Result<(), ZdocError> {
    let id_bytes = style.id.as_bytes();
    out.extend_from_slice(&(id_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(id_bytes);
    out.push(style.style_type.as_byte());
    match &style.parent {
        Some(p) => {
            out.push(1);
            let pb = p.as_bytes();
            out.extend_from_slice(&(pb.len() as u32).to_le_bytes());
            out.extend_from_slice(pb);
        }
        None => out.push(0),
    }
    out.extend_from_slice(&(style.properties.len() as u16).to_le_bytes());
    for (k, v) in &style.properties {
        let kb = k.as_bytes();
        let vb = v.as_bytes();
        out.extend_from_slice(&(kb.len() as u16).to_le_bytes());
        out.extend_from_slice(kb);
        out.extend_from_slice(&(vb.len() as u16).to_le_bytes());
        out.extend_from_slice(vb);
    }
    Ok(())
}

fn serialize_image(image: &Image) -> Result<Vec<u8>, ZdocError> {
    let mut out = Vec::new();
    let mb = image.mime_type.as_bytes();
    out.extend_from_slice(&(mb.len() as u32).to_le_bytes());
    out.extend_from_slice(mb);
    match &image.alt_text {
        Some(a) => {
            out.push(1);
            let ab = a.as_bytes();
            out.extend_from_slice(&(ab.len() as u32).to_le_bytes());
            out.extend_from_slice(ab);
        }
        None => out.push(0),
    }
    out.extend_from_slice(&(image.data.len() as u32).to_le_bytes());
    out.extend_from_slice(&image.data);
    match image.width_pt {
        Some(w) => {
            out.push(1);
            out.extend_from_slice(&w.to_le_bytes());
        }
        None => out.push(0),
    }
    match image.height_pt {
        Some(h) => {
            out.push(1);
            out.extend_from_slice(&h.to_le_bytes());
        }
        None => out.push(0),
    }
    Ok(out)
}

fn serialize_image_inline(out: &mut Vec<u8>, image: &Image) -> Result<(), ZdocError> {
    let id_bytes = image.id.to_le_bytes();
    out.extend_from_slice(&id_bytes);
    let data = serialize_image(image)?;
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&data);
    Ok(())
}

fn serialize_attachment(attachment: &Attachment) -> Result<Vec<u8>, ZdocError> {
    if attachment.data.len() as u64 > MAX_ATTACHMENT_SIZE {
        return Err(ZdocError::ResourceLimitExceeded(format!(
            "attachment {} size {} exceeds max {}",
            attachment.id, attachment.data.len(), MAX_ATTACHMENT_SIZE
        )));
    }
    let mut out = Vec::new();
    let fnb = attachment.file_name.as_bytes();
    out.extend_from_slice(&(fnb.len() as u32).to_le_bytes());
    out.extend_from_slice(fnb);
    let mtb = attachment.mime_type.as_bytes();
    out.extend_from_slice(&(mtb.len() as u32).to_le_bytes());
    out.extend_from_slice(mtb);
    out.extend_from_slice(&(attachment.data.len() as u32).to_le_bytes());
    out.extend_from_slice(&attachment.data);
    Ok(out)
}

fn serialize_hyperlink(hyperlink: &Hyperlink) -> Result<Vec<u8>, ZdocError> {
    let mut out = Vec::new();
    let ub = hyperlink.uri.as_bytes();
    out.extend_from_slice(&(ub.len() as u32).to_le_bytes());
    out.extend_from_slice(ub);
    match &hyperlink.description {
        Some(d) => {
            out.push(1);
            let db = d.as_bytes();
            out.extend_from_slice(&(db.len() as u32).to_le_bytes());
            out.extend_from_slice(db);
        }
        None => out.push(0),
    }
    Ok(out)
}

fn serialize_footnote(footnote: &Footnote) -> Result<Vec<u8>, ZdocError> {
    let mut out = Vec::new();
    out.extend_from_slice(&(footnote.content.len() as u32).to_le_bytes());
    for block in &footnote.content {
        serialize_block_content(out, block)?;
    }
    Ok(out)
}

fn serialize_code_block(block: &CodeBlock) -> Result<Vec<u8>, ZdocError> {
    let mut out = Vec::new();
    let lb = block.language.as_bytes();
    out.extend_from_slice(&(lb.len() as u32).to_le_bytes());
    out.extend_from_slice(lb);
    let cb = block.content.as_bytes();
    if cb.len() > MAX_TEXT_RUN_LEN {
        return Err(ZdocError::ResourceLimitExceeded(format!(
            "code_block {} content length {} exceeds max {}",
            block.id, cb.len(), MAX_TEXT_RUN_LEN
        )));
    }
    out.extend_from_slice(&(cb.len() as u32).to_le_bytes());
    out.extend_from_slice(cb);
    Ok(out)
}

fn serialize_code_block_inline(out: &mut Vec<u8>, block: &CodeBlock) -> Result<(), ZdocError> {
    out.extend_from_slice(&block.id.to_le_bytes());
    let data = serialize_code_block(block)?;
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&data);
    Ok(())
}

fn serialize_math_block(block: &MathBlock) -> Result<Vec<u8>, ZdocError> {
    let mut out = Vec::new();
    let nb = block.notation.as_bytes();
    out.extend_from_slice(&(nb.len() as u32).to_le_bytes());
    out.extend_from_slice(nb);
    let cb = block.content.as_bytes();
    out.extend_from_slice(&(cb.len() as u32).to_le_bytes());
    out.extend_from_slice(cb);
    Ok(out)
}

fn serialize_math_block_inline(out: &mut Vec<u8>, block: &MathBlock) -> Result<(), ZdocError> {
    out.extend_from_slice(&block.id.to_le_bytes());
    let data = serialize_math_block(block)?;
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&data);
    Ok(())
}

fn serialize_list(list: &List) -> Result<Vec<u8>, ZdocError> {
    let mut out = Vec::new();
    out.extend_from_slice(&(list.items.len() as u32).to_le_bytes());
    out.push(list.ordered as u8);
    out.extend_from_slice(&list.start.to_le_bytes());
    serialize_style_ref(out, &list.style)?;
    for item in &list.items {
        serialize_list_item(out, item)?;
    }
    Ok(out)
}

fn serialize_list_inline(out: &mut Vec<u8>, list: &List) -> Result<(), ZdocError> {
    out.extend_from_slice(&list.id.to_le_bytes());
    let data = serialize_list(list)?;
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&data);
    Ok(())
}

fn serialize_list_item(out: &mut Vec<u8>, item: &ListItem) -> Result<(), ZdocError> {
    out.extend_from_slice(&item.id.to_le_bytes());
    out.extend_from_slice(&item.depth.to_le_bytes());
    out.extend_from_slice(&(item.content.len() as u32).to_le_bytes());
    for block in &item.content {
        serialize_block_content(out, block)?;
    }
    Ok(())
}

fn serialize_header_footer(hf: &HeaderFooter) -> Result<Vec<u8>, ZdocError> {
    let mut out = Vec::new();
    out.push(hf.is_header as u8);
    match &hf.pages {
        Some(p) => {
            out.push(1);
            let pb = p.as_bytes();
            out.extend_from_slice(&(pb.len() as u32).to_le_bytes());
            out.extend_from_slice(pb);
        }
        None => out.push(0),
    }
    out.extend_from_slice(&(hf.content.len() as u32).to_le_bytes());
    for block in &hf.content {
        serialize_block_content(out, block)?;
    }
    Ok(out)
}

fn serialize_header_footer_inline(out: &mut Vec<u8>, hf: &HeaderFooter) -> Result<(), ZdocError> {
    out.extend_from_slice(&hf.id.to_le_bytes());
    let data = serialize_header_footer(hf)?;
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&data);
    Ok(())
}
