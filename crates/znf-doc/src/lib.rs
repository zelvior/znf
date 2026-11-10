//! ZDOC (`.zdoc`) Lossless Document Format.
//!
//! `znf-doc` implements a modern, privacy-focused, lossless-first document format
//! built on the ZNF Core v1.0 binary foundation. It provides:
//!
//! - **Lossless document preservation:** exact byte-for-byte round-trip of document
//!   text, styles, tables, images, and embedded resources.
//! - **Rich document object model:** sections, paragraphs, text runs, tables with
//!   merged cells, styles, lists, code blocks, math blocks, images, attachments,
//!   hyperlinks, footnotes, headers, and footers.
//! - **Excellent compression:** Zstandard and LZ4 integration with bounded memory.
//! - **Metadata privacy:** optional, user-controlled metadata; no automatic collection
//!   of device, location, or identity information.
//! - **Optional encryption:** XChaCha20-Poly1305 + Argon2id for payload and metadata.
//! - **Integrity verification:** BLAKE3 per-object and whole-file hashing.
//! - **Resource limits:** configurable bounds against decompression bombs and
//!   oversized documents.
//!
//! See `specifications/zdoc/ZDOC-SPEC.md` for the normative binary specification.
//!
//! # Example
//!
//! ```rust
//! use znf_doc::{serialize_document, deserialize_document, Document, DecodeOptions};
//!
//! let mut doc = Document::new();
//! doc.title = Some("Hello World".into());
//! doc.author = Some("ZNF Labs".into());
//!
//! let encoded = serialize_document(
//!     &doc,
//!     &znf_compression::Config::zstd(3),
//!     None,
//!     None,
//! ).unwrap();
//!
//! let decoded = deserialize_document(&encoded.bytes, None, &DecodeOptions::default()).unwrap();
//! assert_eq!(decoded.document.title, Some("Hello World".into()));
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::all)]

pub mod deserialize;
pub mod dom;
pub mod error;
pub mod format;
pub mod serialize;

pub use deserialize::{
    deserialize_document, DecodeOptions, DeserializedDocument, DocumentMetadata,
};
pub use dom::{
    BlockContent, CodeBlock, Document, Footnote, HeaderFooter, Hyperlink, Image, List, ListItem,
    MathBlock, PageNumbering, Paragraph, Section, Style, StyleRef, Table, TableCell, TableRow,
    TextDirection, TextRun,
};
pub use error::ZdocError;
pub use format::{
    MAX_ATTACHMENT_SIZE, MAX_NESTING_DEPTH, MAX_OBJECTS, MAX_PAGE_COUNT, MAX_TABLE_COLS,
    MAX_TABLE_ROWS, MAX_TEXT_RUN_LEN, OBJECT_INDEX_ENTRY_LEN, TLV_ARCHIVE_BLAKE3, TLV_ZDOC_AUTHOR,
    TLV_ZDOC_CREATED, TLV_ZDOC_CREATOR, TLV_ZDOC_DOCUMENT_ID, TLV_ZDOC_ENCRYPTED_METADATA,
    TLV_ZDOC_LANGUAGE, TLV_ZDOC_METADATA_KV, TLV_ZDOC_MODIFIED, TLV_ZDOC_OBJECT_BLAKE3,
    TLV_ZDOC_OBJECT_INDEX, TLV_ZDOC_STRUCTURE, TLV_ZDOC_SUBJECT, TLV_ZDOC_TITLE, ZDOC_SPEC_VERSION,
};
pub use serialize::{serialize_document, DocumentInfo, SerializedDocument};
