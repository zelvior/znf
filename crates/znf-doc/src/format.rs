//! ZDOC (.zdoc) binary format constants and TLV type definitions.
//!
//! All multi-byte integers are little-endian. The file uses the ZNF Core
//! 64-byte header with `FormatId::ZDOC` (4).

/// ZDOC specification version implemented by this crate.
pub const ZDOC_SPEC_VERSION: (u16, u16) = (1, 0);

/// Format ID for ZDOC in the ZNF Core FormatId registry.
pub const FORMAT_ID_ZDOC: u32 = 4;

/// --- TLV Types for the Metadata Section (between header and payload) ---

/// Document unique identifier: UUID (16 bytes).
pub const TLV_ZDOC_DOCUMENT_ID: u16 = 0x0100;

/// Document title: UTF-8 string.
pub const TLV_ZDOC_TITLE: u16 = 0x0101;

/// Document subject: UTF-8 string.
pub const TLV_ZDOC_SUBJECT: u16 = 0x0102;

/// Document author: UTF-8 string.
pub const TLV_ZDOC_AUTHOR: u16 = 0x0103;

/// Document creator (software): UTF-8 string.
pub const TLV_ZDOC_CREATOR: u16 = 0x0104;

/// Document creation timestamp: RFC 3339 UTF-8 string.
pub const TLV_ZDOC_CREATED: u16 = 0x0105;

/// Document last-modified timestamp: RFC 3339 UTF-8 string.
pub const TLV_ZDOC_MODIFIED: u16 = 0x0106;

/// Document language: BCP-47 language tag, UTF-8 string.
pub const TLV_ZDOC_LANGUAGE: u16 = 0x0107;

/// Document structure descriptor: entry point for decoding the payload DOM.
pub const TLV_ZDOC_STRUCTURE: u16 = 0x0108;

/// Structured key-value metadata map: sorted UTF-8 key-value pairs.
pub const TLV_ZDOC_METADATA_KV: u16 = 0x0109;

/// Encrypted metadata: nonce(24B) \| XChaCha20-Poly1305(ciphertext+tag, AAD=header).
pub const TLV_ZDOC_ENCRYPTED_METADATA: u16 = 0x010A;

/// --- TLV Types for the Footer Section (after payload) ---

/// Object index table: sequence of object_index records.
pub const TLV_ZDOC_OBJECT_INDEX: u16 = 0x0200;

/// Per-object BLAKE3 hashes for verification.
pub const TLV_ZDOC_OBJECT_BLAKE3: u16 = 0x0201;

/// Whole-archive BLAKE3 over `header || metadata || payload`.
pub const TLV_ARCHIVE_BLAKE3: u16 = 0x0202;

/// --- Object Type Identifiers ---

pub const OBJECT_TYPE_SECTION: u8 = 1;
pub const OBJECT_TYPE_PARAGRAPH: u8 = 2;
pub const OBJECT_TYPE_TEXT_RUN: u8 = 3;
pub const OBJECT_TYPE_TABLE: u8 = 4;
pub const OBJECT_TYPE_TABLE_ROW: u8 = 5;
pub const OBJECT_TYPE_TABLE_CELL: u8 = 6;
pub const OBJECT_TYPE_IMAGE: u8 = 7;
pub const OBJECT_TYPE_ATTACHMENT: u8 = 8;
pub const OBJECT_TYPE_HYPERLINK: u8 = 9;
pub const OBJECT_TYPE_FOOTNOTE: u8 = 10;
pub const OBJECT_TYPE_STYLE: u8 = 11;
pub const OBJECT_TYPE_CODE_BLOCK: u8 = 12;
pub const OBJECT_TYPE_MATH_BLOCK: u8 = 13;
pub const OBJECT_TYPE_LIST: u8 = 14;
pub const OBJECT_TYPE_LIST_ITEM: u8 = 15;
pub const OBJECT_TYPE_HEADER_FOOTER: u8 = 16;

/// --- Text Direction Identifiers ---

pub const TEXT_DIRECTION_LTR: u8 = 0;
pub const TEXT_DIRECTION_RTL: u8 = 1;
pub const TEXT_DIRECTION_AUTO: u8 = 2;

/// --- Style Type Identifiers ---

pub const STYLE_TYPE_PARAGRAPH: u8 = 1;
pub const STYLE_TYPE_CHARACTER: u8 = 2;
pub const STYLE_TYPE_TABLE: u8 = 3;
pub const STYLE_TYPE_LIST: u8 = 4;

/// --- Resource Limits ---

/// Maximum nesting depth for sections, lists, tables.
pub const MAX_NESTING_DEPTH: usize = 64;

/// Maximum page count.
pub const MAX_PAGE_COUNT: u32 = 100_000;

/// Maximum objects per document.
pub const MAX_OBJECTS: u64 = 1_000_000;

/// Maximum text run length in bytes.
pub const MAX_TEXT_RUN_LEN: usize = 10 * 1024 * 1024; // 10 MiB

/// Maximum table rows.
pub const MAX_TABLE_ROWS: u32 = 10_000;

/// Maximum table columns.
pub const MAX_TABLE_COLS: u32 = 10_000;

/// Maximum attachment size in bytes.
pub const MAX_ATTACHMENT_SIZE: u64 = 1024 * 1024 * 1024; // 1 GiB

/// Object index entry wire format (all LE):
///   object_id: u32 | object_type: u8 | stored_offset: u64 |
///   stored_len: u32 | uncompressed_len: u32 | blake3_hash: [u8; 32]
pub const OBJECT_INDEX_ENTRY_LEN: usize = 4 + 1 + 8 + 4 + 4 + 32; // 53 bytes
