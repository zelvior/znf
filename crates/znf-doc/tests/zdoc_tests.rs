//! Comprehensive functional and security tests for ZDOC (.zdoc) v1.0.

use znf_compression::Config as CompConfig;
use znf_doc::{
    deserialize_document, serialize_document, BlockContent, CodeBlock, DecodeOptions, Document,
    Footnote, HeaderFooter, Hyperlink, Image, List, ListItem, MathBlock, PageNumbering, Paragraph,
    Section, Style, StyleRef, Table, TableCell, TableRow, TextDirection, TextRun,
};

fn make_section(id: u32, depth: u32) -> Section {
    Section {
        id,
        content: vec![BlockContent::Paragraph(Paragraph {
            id: 1,
            runs: vec![TextRun {
                id: 2,
                text: "Hello, world!".into(),
                style: StyleRef::None,
            }],
            style: StyleRef::None,
            direction: TextDirection::Ltr,
            heading_level: None,
            list_item: false,
        })],
        style: StyleRef::None,
        heading: Some("Section 1".into()),
        page_break_before: false,
        depth,
    }
}

fn roundtrip_check(doc: &Document) {
    let encoded = serialize_document(doc, &CompConfig::zstd(3), None, None).unwrap();
    let decoded = deserialize_document(&encoded.bytes, None, &DecodeOptions::default()).unwrap();
    assert_eq!(
        decoded.document.title, doc.title,
        "title mismatch after round-trip"
    );
    assert_eq!(
        decoded.document.sections.len(),
        doc.sections.len(),
        "section count mismatch"
    );
    assert!(decoded.integrity_verified, "integrity verification failed");
}

#[test]
fn empty_document_roundtrip() {
    let doc = Document::new();
    roundtrip_check(&doc);
}

#[test]
fn simple_document_roundtrip() {
    let mut doc = Document::new();
    doc.title = Some("Test Document".into());
    doc.author = Some("Test Author".into());
    doc.sections.push(make_section(10, 0));
    roundtrip_check(&doc);
}

#[test]
fn all_compression_modes() {
    let mut doc = Document::new();
    doc.sections.push(make_section(1, 0));
    for cfg in [
        CompConfig::stored(),
        CompConfig::lz4(),
        CompConfig::zstd(1),
        CompConfig::zstd(3),
        CompConfig::zstd(9),
        CompConfig::zstd(22),
    ] {
        let encoded = serialize_document(&doc, &cfg, None, None).unwrap();
        let decoded =
            deserialize_document(&encoded.bytes, None, &DecodeOptions::default()).unwrap();
        assert_eq!(decoded.document.sections.len(), 1);
        assert!(decoded.integrity_verified);
    }
}

#[test]
fn unicode_text_roundtrip() {
    let mut doc = Document::new();
    doc.sections.push(Section {
        id: 1,
        content: vec![BlockContent::Paragraph(Paragraph {
            id: 2,
            runs: vec![
                TextRun {
                    id: 3,
                    text: "Hello, 世界! 🎉".into(),
                    style: StyleRef::None,
                },
                TextRun {
                    id: 4,
                    text: "العربية和English mixed script".into(),
                    style: StyleRef::None,
                },
                TextRun {
                    id: 5,
                    text: "ZWJ: \u{200D} family \u{200D} test".into(),
                    style: StyleRef::None,
                },
                TextRun {
                    id: 6,
                    text: "RTL: שלום עולם".into(),
                    style: StyleRef::None,
                },
            ],
            style: StyleRef::None,
            direction: TextDirection::Auto,
            heading_level: None,
            list_item: false,
        })],
        style: StyleRef::None,
        heading: None,
        page_break_before: false,
        depth: 0,
    });
    roundtrip_check(&doc);
}

#[test]
fn empty_text_nodes() {
    let mut doc = Document::new();
    doc.sections.push(Section {
        id: 1,
        content: vec![BlockContent::Paragraph(Paragraph {
            id: 2,
            runs: vec![TextRun {
                id: 3,
                text: "".into(),
                style: StyleRef::None,
            }],
            style: StyleRef::None,
            direction: TextDirection::Ltr,
            heading_level: None,
            list_item: false,
        })],
        style: StyleRef::None,
        heading: None,
        page_break_before: false,
        depth: 0,
    });
    roundtrip_check(&doc);
}

#[test]
fn metadata_roundtrip() {
    let mut doc = Document::new();
    doc.title = Some("My Doc".into());
    doc.subject = Some("A subject".into());
    doc.author = Some("Author Name".into());
    doc.creator = Some("ZNF Tool".into());
    doc.language = Some("en-US".into());
    doc.metadata
        .insert("custom-key".into(), "custom-value".into());
    roundtrip_check(&doc);
}

#[test]
fn table_roundtrip() {
    let mut doc = Document::new();
    doc.sections.push(Section {
        id: 1,
        content: vec![BlockContent::Table(Table {
            id: 10,
            rows: vec![TableRow {
                id: 11,
                cells: vec![TableCell {
                    id: 12,
                    content: vec![BlockContent::Paragraph(Paragraph {
                        id: 13,
                        runs: vec![TextRun {
                            id: 14,
                            text: "Cell 1".into(),
                            style: StyleRef::None,
                        }],
                        style: StyleRef::None,
                        direction: TextDirection::Ltr,
                        heading_level: None,
                        list_item: false,
                    })],
                    style: StyleRef::None,
                }],
            }],
            col_count: 1,
            style: StyleRef::None,
            merged_cells: vec![],
        })],
        style: StyleRef::None,
        heading: None,
        page_break_before: false,
        depth: 0,
    });
    roundtrip_check(&doc);
}

#[test]
fn image_roundtrip() {
    let mut doc = Document::new();
    doc.images.insert(
        100,
        Image {
            id: 100,
            mime_type: "image/png".into(),
            alt_text: Some("A test image".into()),
            data: vec![1, 2, 3, 4, 5],
            width_pt: Some(100.0),
            height_pt: Some(50.0),
        },
    );
    roundtrip_check(&doc);
}

#[test]
fn attachment_roundtrip() {
    let mut doc = Document::new();
    doc.attachments.insert(
        200,
        Attachment {
            id: 200,
            file_name: "data.csv".into(),
            mime_type: "text/csv".into(),
            data: b"a,b,c\n1,2,3".to_vec(),
        },
    );
    roundtrip_check(&doc);
}

#[test]
fn hyperlink_roundtrip() {
    let mut doc = Document::new();
    doc.hyperlinks.insert(
        300,
        Hyperlink {
            id: 300,
            uri: "https://example.com".into(),
            description: Some("Example link".into()),
        },
    );
    roundtrip_check(&doc);
}

#[test]
fn footnote_roundtrip() {
    let mut doc = Document::new();
    doc.footnotes.insert(
        400,
        Footnote {
            id: 400,
            content: vec![BlockContent::Paragraph(Paragraph {
                id: 401,
                runs: vec![TextRun {
                    id: 402,
                    text: "Footnote text".into(),
                    style: StyleRef::None,
                }],
                style: StyleRef::None,
                direction: TextDirection::Ltr,
                heading_level: None,
                list_item: false,
            })],
        },
    );
    roundtrip_check(&doc);
}

#[test]
fn code_block_roundtrip() {
    let mut doc = Document::new();
    doc.code_blocks.insert(
        500,
        CodeBlock {
            id: 500,
            language: "rust".into(),
            content: "fn main() {}\n".into(),
        },
    );
    roundtrip_check(&doc);
}

#[test]
fn math_block_roundtrip() {
    let mut doc = Document::new();
    doc.math_blocks.insert(
        600,
        MathBlock {
            id: 600,
            notation: "latex".into(),
            content: "E = mc^2".into(),
        },
    );
    roundtrip_check(&doc);
}

#[test]
fn list_roundtrip() {
    let mut doc = Document::new();
    doc.lists.insert(
        700,
        List {
            id: 700,
            items: vec![ListItem {
                id: 701,
                depth: 0,
                content: vec![BlockContent::Paragraph(Paragraph {
                    id: 702,
                    runs: vec![TextRun {
                        id: 703,
                        text: "Item 1".into(),
                        style: StyleRef::None,
                    }],
                    style: StyleRef::None,
                    direction: TextDirection::Ltr,
                    heading_level: None,
                    list_item: true,
                })],
            }],
            style: StyleRef::None,
            ordered: true,
            start: 1,
        },
    );
    roundtrip_check(&doc);
}

#[test]
fn style_inheritance_roundtrip() {
    let mut doc = Document::new();
    doc.styles.push(Style {
        id: "heading1".into(),
        style_type: znf_doc::dom::StyleType::Paragraph,
        parent: None,
        properties: std::collections::BTreeMap::from([("font-size".into(), "18pt".into())]),
    });
    doc.styles.push(Style {
        id: "heading1-red".into(),
        style_type: znf_doc::dom::StyleType::Paragraph,
        parent: Some("heading1".into()),
        properties: std::collections::BTreeMap::from([("color".into(), "red".into())]),
    });
    roundtrip_check(&doc);
}

#[test]
fn invalid_utf8_rejected() {
    // This tests that deserialize rejects invalid UTF-8 in text runs.
    // We construct a document with valid text, then corrupt the serialized bytes.
    let mut doc = Document::new();
    doc.sections.push(make_section(1, 0));
    let encoded = serialize_document(&doc, &CompConfig::stored(), None, None).unwrap();
    let mut corrupted = encoded.bytes.clone();
    // Flip a byte in a text run area to create invalid UTF-8
    // Find a safe offset in the payload to corrupt
    if corrupted.len() > 100 {
        corrupted[100] = 0xFF;
        corrupted[101] = 0xFF;
    }
    let err = deserialize_document(&corrupted, None, &DecodeOptions::default()).unwrap_err();
    // Should be a corruption or malformed error, not a panic
    assert!(
        err.is_corruption() || matches!(err, znf_doc::ZdocError::MalformedStructure(_)),
        "expected corruption/malformed error, got {err:?}"
    );
}

#[test]
fn truncated_document_rejected() {
    let doc = Document::new();
    let encoded = serialize_document(&doc, &CompConfig::stored(), None, None).unwrap();
    let truncated = &encoded.bytes[..encoded.bytes.len() / 2];
    let err = deserialize_document(truncated, None, &DecodeOptions::default()).unwrap_err();
    assert!(
        matches!(err, znf_doc::ZdocError::Core(_))
            || matches!(err, znf_doc::ZdocError::MalformedStructure(_)),
        "expected core/malformed error, got {err:?}"
    );
}

use znf_doc::dom::Attachment;
