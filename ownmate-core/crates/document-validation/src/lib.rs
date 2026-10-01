use asset_manifest::{AssetManifestV1, AssetType};
use document_model::{
    DocumentMark, DocumentNode, LEGACY_DOCUMENT_SCHEMA_VERSION, MAX_LIST_DEPTH,
    MAX_VISUAL_MEDIA_GROUP_ITEMS, MIN_LEGACY_DOCUMENT_SCHEMA_VERSION, NativeBlockV3,
    NativeInlineV3, NativeMarkV3, NativeVisualMediaV3, OwnMateDocumentV1, OwnMateDocumentV3,
};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DocumentValidationError {
    #[error("unsupported document schema version")]
    SchemaVersion,
    #[error("root must be doc")]
    Root,
    #[error("blank node id")]
    BlankNodeId,
    #[error("duplicate node id: {0}")]
    DuplicateNodeId(String),
    #[error("invalid heading level")]
    HeadingLevel,
    #[error("ordered-list start must be positive")]
    OrderedListStart,
    #[error("reminder reference must point to a non-blank reminder id")]
    BlankReminderReference,
    #[error("media group must contain 2..20 visual-media items")]
    MediaGroupSize,
    #[error("atomic block presentation must use a canonical non-default size and dock")]
    BlockPresentation,
    #[error("invalid node child combination")]
    ChildCombination,
    #[error("list nesting exceeds maximum")]
    ListDepth,
    #[error("invalid link")]
    Link,
    #[error("invalid text color")]
    TextColor,
    #[error("duplicate native inline mark kind")]
    DuplicateNativeMark,
    #[error("missing asset reference: {0}")]
    MissingAsset(String),
    #[error("asset type does not match native block: {0}")]
    AssetTypeMismatch(String),
}

pub fn validate_document(
    document: &OwnMateDocumentV1,
    assets: &[AssetManifestV1],
) -> Result<(), DocumentValidationError> {
    if !(MIN_LEGACY_DOCUMENT_SCHEMA_VERSION..=LEGACY_DOCUMENT_SCHEMA_VERSION)
        .contains(&document.document_schema_version)
    {
        return Err(DocumentValidationError::SchemaVersion);
    }
    if !matches!(document.root, DocumentNode::Doc { .. }) {
        return Err(DocumentValidationError::Root);
    }
    let asset_ids: HashSet<&str> = assets.iter().map(|asset| asset.asset_id.as_str()).collect();
    let mut node_ids = HashSet::new();
    validate_node(&document.root, None, 0, &asset_ids, &mut node_ids)
}

pub fn validate_native_document_v3(
    document: &OwnMateDocumentV3,
    assets: &[AssetManifestV1],
) -> Result<(), DocumentValidationError> {
    validate_native_document_structure_v3(document)?;
    let assets_by_id: HashMap<&str, &AssetManifestV1> = assets
        .iter()
        .map(|asset| (asset.asset_id.as_str(), asset))
        .collect();
    for block in &document.blocks {
        for (asset_id, expected_type) in native_block_assets(block) {
            let asset = assets_by_id
                .get(asset_id)
                .ok_or_else(|| DocumentValidationError::MissingAsset(asset_id.into()))?;
            if asset.asset_type != expected_type {
                return Err(DocumentValidationError::AssetTypeMismatch(asset_id.into()));
            }
        }
    }
    Ok(())
}

fn native_block_assets(block: &NativeBlockV3) -> Vec<(&str, AssetType)> {
    match block {
        NativeBlockV3::Image { asset_id, .. } | NativeBlockV3::Drawing { asset_id, .. } => {
            vec![(asset_id, AssetType::Image)]
        }
        NativeBlockV3::MediaGroup { items, .. } => items
            .iter()
            .map(|item| match item {
                NativeVisualMediaV3::Image { asset_id, .. } => {
                    (asset_id.as_str(), AssetType::Image)
                }
                NativeVisualMediaV3::Video { asset_id, .. } => {
                    (asset_id.as_str(), AssetType::Video)
                }
            })
            .collect(),
        NativeBlockV3::Attachment { asset_id, kind, .. } => vec![(
            asset_id,
            match kind {
                document_model::NativeAttachmentKindV3::Video => AssetType::Video,
                document_model::NativeAttachmentKindV3::Audio => AssetType::Audio,
                document_model::NativeAttachmentKindV3::File => AssetType::Attachment,
            },
        )],
        _ => Vec::new(),
    }
}

/// Validates editor-owned structure without resolving Journal asset manifests.
/// Persistence must still call `validate_native_document_v3` with real assets.
pub fn validate_native_document_structure_v3(
    document: &OwnMateDocumentV3,
) -> Result<(), DocumentValidationError> {
    if document.document_schema_version != 3 {
        return Err(DocumentValidationError::SchemaVersion);
    }
    if document.blocks.is_empty() {
        return Err(DocumentValidationError::ChildCombination);
    }
    let mut stable_ids = HashSet::<&str>::new();
    for block in &document.blocks {
        validate_native_id(block.id(), &mut stable_ids)?;
        if let Some(presentation) = block.presentation()
            && (!presentation.is_canonical() || presentation.is_default())
        {
            return Err(DocumentValidationError::BlockPresentation);
        }
        if matches!(block, NativeBlockV3::OrderedList { start: 0, .. }) {
            return Err(DocumentValidationError::OrderedListStart);
        }
        match block {
            NativeBlockV3::Paragraph { content, .. }
            | NativeBlockV3::Blockquote { content, .. }
            | NativeBlockV3::CodeBlock { content, .. } => validate_native_inline(content)?,
            NativeBlockV3::Heading { level, content, .. } => {
                if !matches!(level, 1..=6) {
                    return Err(DocumentValidationError::HeadingLevel);
                }
                validate_native_inline(content)?;
            }
            NativeBlockV3::BulletedList { items, .. }
            | NativeBlockV3::OrderedList { items, .. } => {
                if items.is_empty() {
                    return Err(DocumentValidationError::ChildCombination);
                }
                for item in items {
                    validate_native_id(&item.id, &mut stable_ids)?;
                    validate_native_inline(&item.content)?;
                }
            }
            NativeBlockV3::Image { .. }
            | NativeBlockV3::Drawing { .. }
            | NativeBlockV3::Attachment { .. }
            | NativeBlockV3::ContextReference { .. } => {}
            NativeBlockV3::MediaGroup { items, .. } => {
                if !(2..=MAX_VISUAL_MEDIA_GROUP_ITEMS).contains(&items.len()) {
                    return Err(DocumentValidationError::MediaGroupSize);
                }
                for item in items {
                    validate_native_id(item.id(), &mut stable_ids)?;
                }
            }
            NativeBlockV3::ReminderReference { reminder_id, .. } => {
                if reminder_id.trim().is_empty() {
                    return Err(DocumentValidationError::BlankReminderReference);
                }
            }
        }
    }
    Ok(())
}

fn validate_native_id<'a>(
    id: &'a str,
    stable_ids: &mut HashSet<&'a str>,
) -> Result<(), DocumentValidationError> {
    if id.trim().is_empty() {
        return Err(DocumentValidationError::BlankNodeId);
    }
    if !stable_ids.insert(id) {
        return Err(DocumentValidationError::DuplicateNodeId(id.into()));
    }
    Ok(())
}

fn validate_native_inline(content: &[NativeInlineV3]) -> Result<(), DocumentValidationError> {
    for inline in content {
        let mut mark_kinds = HashSet::new();
        for mark in &inline.marks {
            let kind = match mark {
                NativeMarkV3::Bold => 1,
                NativeMarkV3::Italic => 2,
                NativeMarkV3::Underline => 3,
                NativeMarkV3::Strikethrough => 4,
                NativeMarkV3::ForegroundColor { rgb } => {
                    if !is_canonical_native_text_color(rgb) {
                        return Err(DocumentValidationError::TextColor);
                    }
                    5
                }
            };
            if !mark_kinds.insert(kind) {
                return Err(DocumentValidationError::DuplicateNativeMark);
            }
        }
    }
    Ok(())
}

fn is_canonical_native_text_color(value: &str) -> bool {
    is_safe_text_color(value)
        && value.as_bytes()[1..]
            .iter()
            .all(|byte| !byte.is_ascii_lowercase())
}

fn validate_node<'a>(
    node: &'a DocumentNode,
    parent: Option<&DocumentNode>,
    list_depth: u8,
    asset_ids: &HashSet<&'a str>,
    node_ids: &mut HashSet<&'a str>,
) -> Result<(), DocumentValidationError> {
    if let Some(id) = node.node_id() {
        if id.trim().is_empty() {
            return Err(DocumentValidationError::BlankNodeId);
        }
        if !node_ids.insert(id) {
            return Err(DocumentValidationError::DuplicateNodeId(id.into()));
        }
    }
    if matches!(node, DocumentNode::Heading { level, .. } if !matches!(level, 1..=6)) {
        return Err(DocumentValidationError::HeadingLevel);
    }
    if let Some(asset_id) = node.referenced_asset_id()
        && !asset_ids.contains(asset_id)
    {
        return Err(DocumentValidationError::MissingAsset(asset_id.into()));
    }
    if let DocumentNode::Text { marks, .. } = node {
        for mark in marks {
            if matches!(mark, DocumentMark::Link { href } if !(href.starts_with("https://") || href.starts_with("http://")))
            {
                return Err(DocumentValidationError::Link);
            }
            if matches!(mark, DocumentMark::TextColor { color } if !is_safe_text_color(color)) {
                return Err(DocumentValidationError::TextColor);
            }
        }
    }
    validate_parent_child(parent, node)?;
    let next_depth = list_depth
        + u8::from(matches!(
            node,
            DocumentNode::BulletList { .. }
                | DocumentNode::OrderedList { .. }
                | DocumentNode::TaskList { .. }
        ));
    if next_depth > MAX_LIST_DEPTH {
        return Err(DocumentValidationError::ListDepth);
    }
    for child in node.children() {
        validate_node(child, Some(node), next_depth, asset_ids, node_ids)?;
    }
    Ok(())
}

fn is_safe_text_color(value: &str) -> bool {
    value.len() == 7
        && value.starts_with('#')
        && value.as_bytes()[1..].iter().all(u8::is_ascii_hexdigit)
}

fn validate_parent_child(
    parent: Option<&DocumentNode>,
    child: &DocumentNode,
) -> Result<(), DocumentValidationError> {
    let valid = match parent {
        None => matches!(child, DocumentNode::Doc { .. }),
        Some(DocumentNode::Doc { .. }) | Some(DocumentNode::Blockquote { .. }) => !matches!(
            child,
            DocumentNode::Text { .. }
                | DocumentNode::ListItem { .. }
                | DocumentNode::TaskItem { .. }
        ),
        Some(DocumentNode::Paragraph { .. })
        | Some(DocumentNode::Heading { .. })
        | Some(DocumentNode::CodeBlock { .. }) => {
            matches!(child, DocumentNode::Text { .. })
        }
        Some(DocumentNode::BulletList { .. }) | Some(DocumentNode::OrderedList { .. }) => {
            matches!(child, DocumentNode::ListItem { .. })
        }
        Some(DocumentNode::TaskList { .. }) => matches!(child, DocumentNode::TaskItem { .. }),
        Some(DocumentNode::ListItem { .. }) | Some(DocumentNode::TaskItem { .. }) => matches!(
            child,
            DocumentNode::Paragraph { .. }
                | DocumentNode::BulletList { .. }
                | DocumentNode::OrderedList { .. }
                | DocumentNode::TaskList { .. }
        ),
        Some(_) => false,
    };
    if valid {
        Ok(())
    } else {
        Err(DocumentValidationError::ChildCombination)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asset_manifest::{AssetLocalState, AssetManifestV1, AssetRemoteState, AssetType};
    use document_model::{
        DocumentNode, NativeAttachmentKindV3, NativeBlockV3, NativeInlineV3, NativeListItemV3,
        NativeListMarkerV3, NativeMarkV3, NativeVisualMediaV3, OwnMateDocumentV3,
    };

    #[test]
    fn legacy_and_native_validators_keep_disjoint_schema_ranges() {
        for version in 0..=4 {
            let mut legacy = OwnMateDocumentV1::empty("root");
            legacy.document_schema_version = version;
            assert_eq!(
                validate_document(&legacy, &[]).is_ok(),
                matches!(version, 1 | 2)
            );

            let mut native = OwnMateDocumentV3::empty("body");
            native.document_schema_version = version;
            assert_eq!(
                validate_native_document_v3(&native, &[]).is_ok(),
                version == 3
            );
        }
    }

    #[test]
    fn duplicate_node_ids_are_rejected() {
        let document = OwnMateDocumentV1 {
            document_schema_version: 1,
            root: DocumentNode::Doc {
                node_id: "root".into(),
                content: vec![
                    DocumentNode::Paragraph {
                        node_id: "same".into(),
                        text_align: None,
                        content: vec![],
                    },
                    DocumentNode::Paragraph {
                        node_id: "same".into(),
                        text_align: None,
                        content: vec![],
                    },
                ],
            },
        };
        assert!(matches!(
            validate_document(&document, &[]),
            Err(DocumentValidationError::DuplicateNodeId(_))
        ));
    }

    #[test]
    fn illegal_list_child_is_rejected() {
        let document = OwnMateDocumentV1 {
            document_schema_version: 1,
            root: DocumentNode::Doc {
                node_id: "root".into(),
                content: vec![DocumentNode::BulletList {
                    node_id: "list".into(),
                    content: vec![DocumentNode::Paragraph {
                        node_id: "p".into(),
                        text_align: None,
                        content: vec![],
                    }],
                }],
            },
        };
        assert_eq!(
            validate_document(&document, &[]),
            Err(DocumentValidationError::ChildCombination)
        );
    }

    #[test]
    fn text_color_accepts_hex_and_rejects_css_injection() {
        let valid = OwnMateDocumentV1 {
            document_schema_version: 1,
            root: DocumentNode::Doc {
                node_id: "root".into(),
                content: vec![DocumentNode::Paragraph {
                    node_id: "p".into(),
                    text_align: None,
                    content: vec![DocumentNode::Text {
                        text: "safe".into(),
                        marks: vec![DocumentMark::TextColor {
                            color: "#336699".into(),
                        }],
                    }],
                }],
            },
        };
        assert_eq!(validate_document(&valid, &[]), Ok(()));
        let mut invalid = valid;
        if let DocumentNode::Doc { content, .. } = &mut invalid.root
            && let DocumentNode::Paragraph { content, .. } = &mut content[0]
            && let DocumentNode::Text { marks, .. } = &mut content[0]
        {
            marks[0] = DocumentMark::TextColor {
                color: "red;display:none".into(),
            };
        }
        assert_eq!(
            validate_document(&invalid, &[]),
            Err(DocumentValidationError::TextColor)
        );
    }

    #[test]
    fn native_v3_rejects_duplicate_nested_ids_and_unsafe_color() {
        let duplicate = OwnMateDocumentV3 {
            document_schema_version: 3,
            blocks: vec![
                NativeBlockV3::Paragraph {
                    id: "same".into(),
                    content: vec![],
                },
                NativeBlockV3::BulletedList {
                    id: "list".into(),
                    items: vec![NativeListItemV3 {
                        id: "same".into(),
                        content: vec![],
                    }],
                    marker: NativeListMarkerV3::Bullet,
                },
            ],
        };
        assert!(matches!(
            validate_native_document_v3(&duplicate, &[]),
            Err(DocumentValidationError::DuplicateNodeId(_))
        ));

        let unsafe_color = OwnMateDocumentV3 {
            document_schema_version: 3,
            blocks: vec![NativeBlockV3::Paragraph {
                id: "p".into(),
                content: vec![NativeInlineV3 {
                    text: "safe text".into(),
                    marks: vec![NativeMarkV3::ForegroundColor {
                        rgb: "red;url(evil)".into(),
                    }],
                }],
            }],
        };
        assert_eq!(
            validate_native_document_v3(&unsafe_color, &[]),
            Err(DocumentValidationError::TextColor)
        );

        let lowercase_color = OwnMateDocumentV3 {
            document_schema_version: 3,
            blocks: vec![NativeBlockV3::Paragraph {
                id: "lowercase".into(),
                content: vec![NativeInlineV3 {
                    text: "text".into(),
                    marks: vec![NativeMarkV3::ForegroundColor {
                        rgb: "#aabbcc".into(),
                    }],
                }],
            }],
        };
        assert_eq!(
            validate_native_document_v3(&lowercase_color, &[]),
            Err(DocumentValidationError::TextColor)
        );

        let duplicate_mark = OwnMateDocumentV3 {
            document_schema_version: 3,
            blocks: vec![NativeBlockV3::Paragraph {
                id: "duplicate-mark".into(),
                content: vec![NativeInlineV3 {
                    text: "text".into(),
                    marks: vec![NativeMarkV3::Bold, NativeMarkV3::Bold],
                }],
            }],
        };
        assert_eq!(
            validate_native_document_v3(&duplicate_mark, &[]),
            Err(DocumentValidationError::DuplicateNativeMark)
        );

        let zero_based_ordered_list = OwnMateDocumentV3 {
            document_schema_version: 3,
            blocks: vec![NativeBlockV3::OrderedList {
                id: "ordered".into(),
                start: 0,
                items: vec![NativeListItemV3 {
                    id: "item".into(),
                    content: vec![],
                }],
            }],
        };
        assert_eq!(
            validate_native_document_v3(&zero_based_ordered_list, &[]),
            Err(DocumentValidationError::OrderedListStart)
        );
    }

    #[test]
    fn native_v3_requires_block_and_manifest_asset_types_to_match() {
        let cases = [
            (
                NativeBlockV3::Image {
                    id: "image".into(),
                    asset_id: "asset".into(),
                    alt: String::new(),
                    presentation: None,
                },
                AssetType::Image,
            ),
            (
                NativeBlockV3::Drawing {
                    id: "drawing".into(),
                    asset_id: "asset".into(),
                    presentation: None,
                },
                AssetType::Image,
            ),
            (
                NativeBlockV3::Attachment {
                    id: "audio".into(),
                    asset_id: "asset".into(),
                    kind: NativeAttachmentKindV3::Audio,
                    label: String::new(),
                    presentation: None,
                },
                AssetType::Audio,
            ),
            (
                NativeBlockV3::Attachment {
                    id: "video".into(),
                    asset_id: "asset".into(),
                    kind: NativeAttachmentKindV3::Video,
                    label: String::new(),
                    presentation: None,
                },
                AssetType::Video,
            ),
            (
                NativeBlockV3::Attachment {
                    id: "file".into(),
                    asset_id: "asset".into(),
                    kind: NativeAttachmentKindV3::File,
                    label: String::new(),
                    presentation: None,
                },
                AssetType::Attachment,
            ),
        ];

        for (block, expected_type) in cases {
            let document = OwnMateDocumentV3 {
                document_schema_version: 3,
                blocks: vec![block],
            };
            assert_eq!(
                validate_native_document_v3(&document, &[native_asset(expected_type.clone())]),
                Ok(())
            );
            assert_eq!(
                validate_native_document_v3(&document, &[native_asset(wrong_type(&expected_type))]),
                Err(DocumentValidationError::AssetTypeMismatch("asset".into()))
            );
        }
    }

    #[test]
    fn native_v3_media_group_validates_size_nested_ids_and_asset_types() {
        let group = NativeBlockV3::MediaGroup {
            id: "group".into(),
            items: vec![
                NativeVisualMediaV3::Image {
                    id: "image".into(),
                    asset_id: "asset-image".into(),
                    alt: String::new(),
                },
                NativeVisualMediaV3::Video {
                    id: "video".into(),
                    asset_id: "asset-video".into(),
                    label: String::new(),
                },
            ],
            presentation: None,
        };
        let document = OwnMateDocumentV3 {
            document_schema_version: 3,
            blocks: vec![group],
        };
        let mut image = native_asset(AssetType::Image);
        image.asset_id = "asset-image".into();
        let mut video = native_asset(AssetType::Video);
        video.asset_id = "asset-video".into();

        assert_eq!(
            validate_native_document_v3(&document, &[image, video]),
            Ok(())
        );

        let too_small = OwnMateDocumentV3 {
            document_schema_version: 3,
            blocks: vec![NativeBlockV3::MediaGroup {
                id: "group".into(),
                items: vec![],
                presentation: None,
            }],
        };
        assert_eq!(
            validate_native_document_structure_v3(&too_small),
            Err(DocumentValidationError::MediaGroupSize),
        );
    }

    fn wrong_type(expected: &AssetType) -> AssetType {
        if *expected == AssetType::Image {
            AssetType::Audio
        } else {
            AssetType::Image
        }
    }

    fn native_asset(asset_type: AssetType) -> AssetManifestV1 {
        AssetManifestV1 {
            asset_id: "asset".into(),
            asset_type,
            mime_type: "application/octet-stream".into(),
            byte_size: 1,
            checksum: "a".repeat(64),
            created_at: "2026-08-13T00:00:00Z".into(),
            width: None,
            height: None,
            duration_ms: None,
            original_filename: None,
            local_state: AssetLocalState::Pending,
            remote_state: AssetRemoteState::LocalOnly,
            cloud_encryption_metadata: None,
        }
    }
}
