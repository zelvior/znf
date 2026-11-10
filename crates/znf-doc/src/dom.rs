//! Document Object Model (DOM) for ZDOC.
//!
//! Defines the in-memory representation of a ZDOC document: sections, paragraphs,
//! text runs, tables, styles, images, attachments, hyperlinks, footnotes, and more.
//! The DOM is independent of rendering and serialization.

use crate::error::ZdocError;
use crate::format::{
    MAX_NESTING_DEPTH, MAX_PAGE_COUNT, MAX_TABLE_COLS, MAX_TABLE_ROWS, MAX_TEXT_RUN_LEN,
    OBJECT_TYPE_ATTACHMENT, OBJECT_TYPE_CODE_BLOCK, OBJECT_TYPE_FOOTNOTE, OBJECT_TYPE_HYPERLINK,
    OBJECT_TYPE_IMAGE, OBJECT_TYPE_LIST, OBJECT_TYPE_LIST_ITEM, OBJECT_TYPE_MATH_BLOCK,
    OBJECT_TYPE_PARAGRAPH, OBJECT_TYPE_SECTION, OBJECT_TYPE_STYLE, OBJECT_TYPE_TABLE,
    OBJECT_TYPE_TABLE_CELL, OBJECT_TYPE_TABLE_ROW, OBJECT_TYPE_TEXT_RUN, TEXT_DIRECTION_AUTO,
    TEXT_DIRECTION_LTR, TEXT_DIRECTION_RTL,
};
use std::collections::BTreeMap;
use znf_integrity::{Hash, HASH_LEN};

/// Text direction for a block of content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TextDirection {
    /// Left-to-right.
    Ltr = 0,
    /// Right-to-left.
    Rtl = 1,
    /// Automatically determined from content.
    Auto = 2,
}

impl TextDirection {
    #[must_use]
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            TEXT_DIRECTION_LTR => Some(TextDirection::Ltr),
            TEXT_DIRECTION_RTL => Some(TextDirection::Rtl),
            TEXT_DIRECTION_AUTO => Some(TextDirection::Auto),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Style type identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StyleType {
    Paragraph = 1,
    Character = 2,
    Table = 3,
    List = 4,
}

impl StyleType {
    #[must_use]
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(StyleType::Paragraph),
            2 => Some(StyleType::Character),
            3 => Some(StyleType::Table),
            4 => Some(StyleType::List),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }
}

/// A style reference: either a named style or inline properties.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StyleRef {
    /// Reference to a named style by ID.
    Named(String),
    /// Inline style properties (key-value map).
    Inline(BTreeMap<String, String>),
    /// No style.
    None,
}

impl Default for StyleRef {
    fn default() -> Self {
        StyleRef::None
    }
}

/// A named style definition.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Style {
    /// Unique style identifier.
    pub id: String,
    /// Style type.
    pub style_type: StyleType,
    /// Parent style ID for inheritance (None = root).
    pub parent: Option<String>,
    /// Style properties (key-value map).
    pub properties: BTreeMap<String, String>,
}

/// A text run: a span of text with a single style.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TextRun {
    /// Unique object ID within the document.
    pub id: u32,
    /// UTF-8 text content (preserved exactly, no normalization).
    pub text: String,
    /// Style applied to this run.
    pub style: StyleRef,
}

/// A paragraph: a block of one or more text runs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Paragraph {
    /// Unique object ID within the document.
    pub id: u32,
    /// Text runs in reading order.
    pub runs: Vec<TextRun>,
    /// Paragraph style.
    pub style: StyleRef,
    /// Text direction.
    pub direction: TextDirection,
    /// Whether this is a heading (and heading level, 1-6; None = not a heading).
    pub heading_level: Option<u8>,
    /// Whether this starts a new list item.
    pub list_item: bool,
}

/// A table cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TableCell {
    /// Unique object ID within the document.
    pub id: u32,
    /// Block-level content within the cell.
    pub content: Vec<BlockContent>,
    /// Cell style.
    pub style: StyleRef,
}

/// A table row.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TableRow {
    /// Unique object ID within the document.
    pub id: u32,
    /// Cells in this row.
    pub cells: Vec<TableCell>,
    /// Row style.
    pub style: StyleRef,
}

/// A table with merged cell support.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Table {
    /// Unique object ID within the document.
    pub id: u32,
    /// Rows in the table.
    pub rows: Vec<TableRow>,
    /// Number of columns (derived from max cells in any row).
    pub col_count: u32,
    /// Table style.
    pub style: StyleRef,
    /// Merged cell regions: (start_row, start_col, rowspan, colspan).
    pub merged_cells: Vec<(u32, u32, u32, u32)>,
}

/// Block-level content that can appear in a paragraph, cell, or section.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BlockContent {
    /// A paragraph.
    Paragraph(Paragraph),
    /// A table.
    Table(Table),
    /// A code block.
    CodeBlock(CodeBlock),
    /// A math block.
    MathBlock(MathBlock),
    /// A list.
    List(List),
    /// A header/footer block.
    HeaderFooter(HeaderFooter),
    /// An embedded image (block-level).
    Image(Image),
}

/// A code block.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CodeBlock {
    /// Unique object ID within the document.
    pub id: u32,
    /// Programming language identifier (e.g. "rust", "python").
    pub language: String,
    /// Code content (preserved exactly).
    pub content: String,
}

/// A math block.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MathBlock {
    /// Unique object ID within the document.
    pub id: u32,
    /// Math notation (e.g. LaTeX, MathML).
    pub notation: String,
    /// Math content (preserved exactly).
    pub content: String,
}

/// A list with nested items.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct List {
    /// Unique object ID within the document.
    pub id: u32,
    /// List items.
    pub items: Vec<ListItem>,
    /// List style.
    pub style: StyleRef,
    /// Whether this is an ordered list.
    pub ordered: bool,
    /// Start number for ordered lists.
    pub start: u32,
}

/// A list item.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ListItem {
    /// Unique object ID within the document.
    pub id: u32,
    /// Block-level content of the item.
    pub content: Vec<BlockContent>,
    /// Nesting depth (0 = top-level).
    pub depth: u32,
}

/// A running header or footer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HeaderFooter {
    /// Unique object ID within the document.
    pub id: u32,
    /// Whether this is a header (true) or footer (false).
    pub is_header: bool,
    /// Block-level content.
    pub content: Vec<BlockContent>,
    /// Page numbers this applies to (None = all pages).
    pub pages: Option<String>,
}

/// An embedded image.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Image {
    /// Unique object ID within the document.
    pub id: u32,
    /// Image MIME type (e.g. "image/png", "image/jpeg").
    pub mime_type: String,
    /// Alternative text for accessibility.
    pub alt_text: Option<String>,
    /// Image bytes (preserved exactly).
    pub data: Vec<u8>,
    /// Display width in points (optional).
    pub width_pt: Option<f32>,
    /// Display height in points (optional).
    pub height_pt: Option<f32>,
}

/// An embedded attachment.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Attachment {
    /// Unique object ID within the document.
    pub id: u32,
    /// Original file name.
    pub file_name: String,
    /// MIME type.
    pub mime_type: String,
    /// Attachment bytes (preserved exactly).
    pub data: Vec<u8>,
}

/// A hyperlink.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Hyperlink {
    /// Unique object ID within the document.
    pub id: u32,
    /// Target URI.
    pub uri: String,
    /// Link description / title (accessibility).
    pub description: Option<String>,
}

/// A footnote.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Footnote {
    /// Unique object ID within the document.
    pub id: u32,
    /// Footnote content.
    pub content: Vec<BlockContent>,
}

/// A document section.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Section {
    /// Unique object ID within the document.
    pub id: u32,
    /// Block-level content in reading order.
    pub content: Vec<BlockContent>,
    /// Section style.
    pub style: StyleRef,
    /// Section heading (optional title).
    pub heading: Option<String>,
    /// Page break before this section.
    pub page_break_before: bool,
    /// Nesting depth (0 = top-level).
    pub depth: u32,
}

/// Page numbering configuration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PageNumbering {
    /// Numbering style (e.g. "arabic", "roman", "letters").
    pub style: String,
    /// Starting page number.
    pub start: u32,
    /// Whether to display page numbers.
    pub display: bool,
}

/// The complete ZDOC document object model.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Document {
    /// Unique document identifier (UUID).
    pub document_id: [u8; 16],
    /// Document title.
    pub title: Option<String>,
    /// Document subject.
    pub subject: Option<String>,
    /// Document author.
    pub author: Option<String>,
    /// Document creator (software).
    pub creator: Option<String>,
    /// Creation timestamp (RFC 3339).
    pub created: Option<String>,
    /// Last-modified timestamp (RFC 3339).
    pub modified: Option<String>,
    /// Document language (BCP-47).
    pub language: Option<String>,
    /// Top-level sections in reading order.
    pub sections: Vec<Section>,
    /// Named styles.
    pub styles: Vec<Style>,
    /// Embedded images.
    pub images: BTreeMap<u32, Image>,
    /// Embedded attachments.
    pub attachments: BTreeMap<u32, Attachment>,
    /// Hyperlinks.
    pub hyperlinks: BTreeMap<u32, Hyperlink>,
    /// Footnotes.
    pub footnotes: BTreeMap<u32, Footnote>,
    /// Code blocks.
    pub code_blocks: BTreeMap<u32, CodeBlock>,
    /// Math blocks.
    pub math_blocks: BTreeMap<u32, MathBlock>,
    /// Lists.
    pub lists: BTreeMap<u32, List>,
    /// Headers and footers.
    pub headers_footers: BTreeMap<u32, HeaderFooter>,
    /// Page numbering configuration.
    pub page_numbering: PageNumbering,
    /// Structured key-value metadata (sorted by key).
    pub metadata: BTreeMap<String, String>,
    /// Per-object BLAKE3 hashes (set after decoding for verification).
    pub object_hashes: BTreeMap<u32, Hash>,
}

impl Default for Document {
    fn default() -> Self {
        Self::new()
    }
}

impl Document {
    /// Create a new empty document.
    #[must_use]
    pub fn new() -> Self {
        Document {
            document_id: [0u8; 16],
            title: None,
            subject: None,
            author: None,
            creator: None,
            created: None,
            modified: None,
            language: None,
            sections: Vec::new(),
            styles: Vec::new(),
            images: BTreeMap::new(),
            attachments: BTreeMap::new(),
            hyperlinks: BTreeMap::new(),
            footnotes: BTreeMap::new(),
            code_blocks: BTreeMap::new(),
            math_blocks: BTreeMap::new(),
            lists: BTreeMap::new(),
            headers_footers: BTreeMap::new(),
            page_numbering: PageNumbering {
                style: "arabic".into(),
                start: 1,
                display: true,
            },
            metadata: BTreeMap::new(),
            object_hashes: BTreeMap::new(),
        }
    }

    /// Validate the document structure without modifying it.
    ///
    /// Checks for:
    /// - Duplicate identifiers
    /// - Broken references
    /// - Circular style inheritance
    /// - Excessive nesting depth
    /// - Invalid table dimensions
    /// - Exceeding page/object/text limits
    ///
    /// # Errors
    ///
    /// Returns [`ZdocError`] describing the first validation failure found.
    pub fn validate(&self) -> Result<(), ZdocError> {
        // Validate page count.
        if self.sections.len() as u32 > MAX_PAGE_COUNT {
            return Err(ZdocError::InvalidDimensions(format!(
                "page count {} exceeds max {}",
                self.sections.len(),
                MAX_PAGE_COUNT
            )));
        }

        // Validate object count.
        let object_count = self.sections.len()
            + self.styles.len()
            + self.images.len()
            + self.attachments.len()
            + self.hyperlinks.len()
            + self.footnotes.len()
            + self.code_blocks.len()
            + self.math_blocks.len()
            + self.lists.len()
            + self.headers_footers.len();
        if object_count as u64 > MAX_OBJECTS {
            return Err(ZdocError::ResourceLimitExceeded(format!(
                "object count {} exceeds max {}",
                object_count, MAX_OBJECTS
            )));
        }

        // Validate style inheritance for cycles.
        self.validate_styles()?;

        // Validate sections and their content.
        let mut seen_ids = std::collections::HashSet::new();
        for section in &self.sections {
            self.validate_section(section, 0, &mut seen_ids)?;
        }

        // Validate top-level objects have unique IDs.
        for image in self.images.values() {
            if !seen_ids.insert(image.id) {
                return Err(ZdocError::DuplicateIdentifier(format!(
                    "image {}",
                    image.id
                )));
            }
        }
        for attachment in self.attachments.values() {
            if !seen_ids.insert(attachment.id) {
                return Err(ZdocError::DuplicateIdentifier(format!(
                    "attachment {}",
                    attachment.id
                )));
            }
        }
        for hyperlink in self.hyperlinks.values() {
            if !seen_ids.insert(hyperlink.id) {
                return Err(ZdocError::DuplicateIdentifier(format!(
                    "hyperlink {}",
                    hyperlink.id
                )));
            }
        }
        for footnote in self.footnotes.values() {
            if !seen_ids.insert(footnote.id) {
                return Err(ZdocError::DuplicateIdentifier(format!(
                    "footnote {}",
                    footnote.id
                )));
            }
        }
        for code_block in self.code_blocks.values() {
            if !seen_ids.insert(code_block.id) {
                return Err(ZdocError::DuplicateIdentifier(format!(
                    "code_block {}",
                    code_block.id
                )));
            }
        }
        for math_block in self.math_blocks.values() {
            if !seen_ids.insert(math_block.id) {
                return Err(ZdocError::DuplicateIdentifier(format!(
                    "math_block {}",
                    math_block.id
                )));
            }
        }
        for list in self.lists.values() {
            if !seen_ids.insert(list.id) {
                return Err(ZdocError::DuplicateIdentifier(format!("list {}", list.id)));
            }
        }
        for hf in self.headers_footers.values() {
            if !seen_ids.insert(hf.id) {
                return Err(ZdocError::DuplicateIdentifier(format!(
                    "header_footer {}",
                    hf.id
                )));
            }
        }

        Ok(())
    }

    fn validate_styles(&self) -> Result<(), ZdocError> {
        let style_map: BTreeMap<&str, &Style> =
            self.styles.iter().map(|s| (s.id.as_str(), s)).collect();
        let mut visiting = std::collections::HashSet::new();
        let mut visited = std::collections::HashSet::new();

        for style in &self.styles {
            self.visit_style(style, &style_map, &mut visiting, &mut visited)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn visit_style(
        &self,
        style: &Style,
        style_map: &BTreeMap<&str, &Style>,
        visiting: &mut std::collections::HashSet<&str>,
        visited: &mut std::collections::HashSet<&str>,
    ) -> Result<(), ZdocError> {
        if visited.contains(style.id.as_str()) {
            return Ok(());
        }
        if visiting.contains(style.id.as_str()) {
            return Err(ZdocError::CircularRelationship(format!(
                "circular style inheritance at '{}'",
                style.id
            )));
        }
        visiting.insert(style.id.as_str());
        if let Some(parent_id) = &style.parent {
            if let Some(parent) = style_map.get(parent_id.as_str()) {
                self.visit_style(parent, style_map, visiting, visited)?;
            } else {
                return Err(ZdocError::BrokenReference(format!(
                    "style '{}' references missing parent '{}'",
                    style.id, parent_id
                )));
            }
        }
        visiting.remove(style.id.as_str());
        visited.insert(style.id.as_str());
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_section(
        &self,
        section: &Section,
        depth: u32,
        seen_ids: &mut std::collections::HashSet<u32>,
    ) -> Result<(), ZdocError> {
        if depth > MAX_NESTING_DEPTH as u32 {
            return Err(ZdocError::ResourceLimitExceeded(format!(
                "nesting depth {} exceeds max {}",
                depth, MAX_NESTING_DEPTH
            )));
        }

        if !seen_ids.insert(section.id) {
            return Err(ZdocError::DuplicateIdentifier(format!(
                "section {}",
                section.id
            )));
        }

        for block in &section.content {
            self.validate_block(block, depth + 1, seen_ids)?;
        }
        Ok(())
    }

    fn validate_block(
        &self,
        block: &BlockContent,
        depth: u32,
        seen_ids: &mut std::collections::HashSet<u32>,
    ) -> Result<(), ZdocError> {
        match block {
            BlockContent::Paragraph(p) => self.validate_paragraph(p, seen_ids),
            BlockContent::Table(t) => self.validate_table(t, depth, seen_ids),
            BlockContent::CodeBlock(c) => self.validate_code_block(c, seen_ids),
            BlockContent::MathBlock(m) => self.validate_math_block(m, seen_ids),
            BlockContent::List(l) => self.validate_list(l, depth, seen_ids),
            BlockContent::HeaderFooter(h) => self.validate_header_footer(h, seen_ids),
            BlockContent::Image(i) => self.validate_image(i, seen_ids),
        }
    }

    fn validate_paragraph(
        &self,
        p: &Paragraph,
        seen_ids: &mut std::collections::HashSet<u32>,
    ) -> Result<(), ZdocError> {
        if !seen_ids.insert(p.id) {
            return Err(ZdocError::DuplicateIdentifier(format!(
                "paragraph {}",
                p.id
            )));
        }
        // Validate heading level.
        if let Some(level) = p.heading_level {
            if level == 0 || level > 6 {
                return Err(ZdocError::InvalidDimensions(format!(
                    "invalid heading level {} (must be 1-6)",
                    level
                )));
            }
        }
        // Validate text runs.
        for run in &p.runs {
            self.validate_text_run(run, seen_ids)?;
        }
        // Validate text length.
        let total_len: usize = p.runs.iter().map(|r| r.text.len()).sum();
        if total_len > MAX_TEXT_RUN_LEN {
            return Err(ZdocError::ResourceLimitExceeded(format!(
                "paragraph {} text length {} exceeds max {}",
                p.id, total_len, MAX_TEXT_RUN_LEN
            )));
        }
        Ok(())
    }

    fn validate_text_run(
        &self,
        run: &TextRun,
        seen_ids: &mut std::collections::HashSet<u32>,
    ) -> Result<(), ZdocError> {
        if !seen_ids.insert(run.id) {
            return Err(ZdocError::DuplicateIdentifier(format!(
                "text_run {}",
                run.id
            )));
        }
        if run.text.len() > MAX_TEXT_RUN_LEN {
            return Err(ZdocError::ResourceLimitExceeded(format!(
                "text_run {} length {} exceeds max {}",
                run.id,
                run.text.len(),
                MAX_TEXT_RUN_LEN
            )));
        }
        Ok(())
    }

    fn validate_table(
        &self,
        table: &Table,
        depth: u32,
        seen_ids: &mut std::collections::HashSet<u32>,
    ) -> Result<(), ZdocError> {
        if !seen_ids.insert(table.id) {
            return Err(ZdocError::DuplicateIdentifier(format!(
                "table {}",
                table.id
            )));
        }
        if table.rows.len() as u32 > MAX_TABLE_ROWS {
            return Err(ZdocError::InvalidDimensions(format!(
                "table {} rows {} exceeds max {}",
                table.id,
                table.rows.len(),
                MAX_TABLE_ROWS
            )));
        }
        if table.col_count > MAX_TABLE_COLS {
            return Err(ZdocError::InvalidDimensions(format!(
                "table {} columns {} exceeds max {}",
                table.id, table.col_count, MAX_TABLE_COLS
            )));
        }
        for row in &table.rows {
            self.validate_table_row(row, depth, seen_ids)?;
        }
        Ok(())
    }

    fn validate_table_row(
        &self,
        row: &TableRow,
        depth: u32,
        seen_ids: &mut std::collections::HashSet<u32>,
    ) -> Result<(), ZdocError> {
        if !seen_ids.insert(row.id) {
            return Err(ZdocError::DuplicateIdentifier(format!(
                "table_row {}",
                row.id
            )));
        }
        for cell in &row.cells {
            self.validate_table_cell(cell, depth, seen_ids)?;
        }
        Ok(())
    }

    fn validate_table_cell(
        &self,
        cell: &TableCell,
        depth: u32,
        seen_ids: &mut std::collections::HashSet<u32>,
    ) -> Result<(), ZdocError> {
        if !seen_ids.insert(cell.id) {
            return Err(ZdocError::DuplicateIdentifier(format!(
                "table_cell {}",
                cell.id
            )));
        }
        for block in &cell.content {
            self.validate_block(block, depth + 1, seen_ids)?;
        }
        Ok(())
    }

    fn validate_code_block(
        &self,
        block: &CodeBlock,
        seen_ids: &mut std::collections::HashSet<u32>,
    ) -> Result<(), ZdocError> {
        if !seen_ids.insert(block.id) {
            return Err(ZdocError::DuplicateIdentifier(format!(
                "code_block {}",
                block.id
            )));
        }
        if block.content.len() > MAX_TEXT_RUN_LEN {
            return Err(ZdocError::ResourceLimitExceeded(format!(
                "code_block {} content length {} exceeds max {}",
                block.id,
                block.content.len(),
                MAX_TEXT_RUN_LEN
            )));
        }
        Ok(())
    }

    fn validate_math_block(
        &self,
        block: &MathBlock,
        seen_ids: &mut std::collections::HashSet<u32>,
    ) -> Result<(), ZdocError> {
        if !seen_ids.insert(block.id) {
            return Err(ZdocError::DuplicateIdentifier(format!(
                "math_block {}",
                block.id
            )));
        }
        Ok(())
    }

    fn validate_list(
        &self,
        list: &List,
        depth: u32,
        seen_ids: &mut std::collections::HashSet<u32>,
    ) -> Result<(), ZdocError> {
        if !seen_ids.insert(list.id) {
            return Err(ZdocError::DuplicateIdentifier(format!("list {}", list.id)));
        }
        if depth > MAX_NESTING_DEPTH as u32 {
            return Err(ZdocError::ResourceLimitExceeded(format!(
                "list nesting depth {} exceeds max {}",
                depth, MAX_NESTING_DEPTH
            )));
        }
        for item in &list.items {
            self.validate_list_item(item, depth, seen_ids)?;
        }
        Ok(())
    }

    fn validate_list_item(
        &self,
        item: &ListItem,
        depth: u32,
        seen_ids: &mut std::collections::HashSet<u32>,
    ) -> Result<(), ZdocError> {
        if !seen_ids.insert(item.id) {
            return Err(ZdocError::DuplicateIdentifier(format!(
                "list_item {}",
                item.id
            )));
        }
        if item.depth > MAX_NESTING_DEPTH as u32 {
            return Err(ZdocError::ResourceLimitExceeded(format!(
                "list_item {} depth {} exceeds max {}",
                item.id, item.depth, MAX_NESTING_DEPTH
            )));
        }
        for block in &item.content {
            self.validate_block(block, depth + 1, seen_ids)?;
        }
        Ok(())
    }

    fn validate_header_footer(
        &self,
        hf: &HeaderFooter,
        seen_ids: &mut std::collections::HashSet<u32>,
    ) -> Result<(), ZdocError> {
        if !seen_ids.insert(hf.id) {
            return Err(ZdocError::DuplicateIdentifier(format!(
                "header_footer {}",
                hf.id
            )));
        }
        for block in &hf.content {
            self.validate_block(block, 1, seen_ids)?;
        }
        Ok(())
    }

    fn validate_image(
        &self,
        image: &Image,
        seen_ids: &mut std::collections::HashSet<u32>,
    ) -> Result<(), ZdocError> {
        if !seen_ids.insert(image.id) {
            return Err(ZdocError::DuplicateIdentifier(format!(
                "image {}",
                image.id
            )));
        }
        Ok(())
    }

    /// Total number of objects in the document.
    #[must_use]
    pub fn object_count(&self) -> usize {
        self.sections.len()
            + self.styles.len()
            + self.images.len()
            + self.attachments.len()
            + self.hyperlinks.len()
            + self.footnotes.len()
            + self.code_blocks.len()
            + self.math_blocks.len()
            + self.lists.len()
            + self.headers_footers.len()
    }
}

/// Top-level block content that can appear directly in a section.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SectionContent {
    Paragraph(Paragraph),
    Table(Table),
    Image(Image),
    CodeBlock(CodeBlock),
    MathBlock(MathBlock),
    List(List),
}
