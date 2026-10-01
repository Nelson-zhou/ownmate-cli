use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Legacy tree-document fixture range; never the native editor's current schema.
pub const MIN_LEGACY_DOCUMENT_SCHEMA_VERSION: u32 = 1;
pub const LEGACY_DOCUMENT_SCHEMA_VERSION: u32 = 2;
pub const MAX_LIST_DEPTH: u8 = 3;
pub const MAX_VISUAL_MEDIA_GROUP_ITEMS: usize = 20;
pub const NATIVE_BLOCK_WIDTH_ANCHORS_PERMILLE: [u16; 4] = [330, 500, 670, 1000];
pub const NATIVE_BLOCK_HEIGHT_ANCHORS_PERMILLE: [u16; 4] = [330, 500, 670, 1000];
pub const MIN_NATIVE_BLOCK_WIDTH_PERMILLE: u16 = NATIVE_BLOCK_WIDTH_ANCHORS_PERMILLE[0];
pub const MAX_NATIVE_BLOCK_WIDTH_PERMILLE: u16 = 1000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnMateDocumentV1 {
    pub document_schema_version: u32,
    #[serde(flatten)]
    pub root: DocumentNode,
}

impl OwnMateDocumentV1 {
    pub fn empty(node_id: impl Into<String>) -> Self {
        Self {
            document_schema_version: LEGACY_DOCUMENT_SCHEMA_VERSION,
            root: DocumentNode::Doc {
                node_id: node_id.into(),
                content: vec![],
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum DocumentNode {
    Doc {
        node_id: String,
        content: Vec<DocumentNode>,
    },
    Paragraph {
        node_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        text_align: Option<TextAlign>,
        #[serde(default)]
        content: Vec<DocumentNode>,
    },
    Heading {
        node_id: String,
        level: u8,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        text_align: Option<TextAlign>,
        #[serde(default)]
        content: Vec<DocumentNode>,
    },
    Blockquote {
        node_id: String,
        #[serde(default)]
        content: Vec<DocumentNode>,
    },
    CodeBlock {
        node_id: String,
        #[serde(default)]
        language: String,
        #[serde(default)]
        content: Vec<DocumentNode>,
    },
    BulletList {
        node_id: String,
        #[serde(default)]
        content: Vec<DocumentNode>,
    },
    OrderedList {
        node_id: String,
        #[serde(default = "default_ordered_start")]
        start: u32,
        #[serde(default)]
        content: Vec<DocumentNode>,
    },
    ListItem {
        node_id: String,
        #[serde(default)]
        content: Vec<DocumentNode>,
    },
    TaskList {
        node_id: String,
        #[serde(default)]
        content: Vec<DocumentNode>,
    },
    TaskItem {
        node_id: String,
        #[serde(default)]
        checked: bool,
        #[serde(default)]
        content: Vec<DocumentNode>,
    },
    Divider {
        node_id: String,
    },
    Image {
        node_id: String,
        asset_id: String,
        #[serde(default)]
        alt: String,
    },
    Audio {
        node_id: String,
        asset_id: String,
    },
    Video {
        node_id: String,
        asset_id: String,
    },
    Attachment {
        node_id: String,
        asset_id: String,
        #[serde(default)]
        label: String,
    },
    MemoryReference {
        node_id: String,
        target_entry_id: String,
        #[serde(default)]
        label: String,
    },
    UnsupportedBlock {
        node_id: String,
        original_type: String,
        payload: Value,
    },
    Text {
        text: String,
        #[serde(default)]
        marks: Vec<DocumentMark>,
    },
}

fn default_ordered_start() -> u32 {
    1
}

impl DocumentNode {
    pub fn node_id(&self) -> Option<&str> {
        match self {
            Self::Text { .. } => None,
            Self::Doc { node_id, .. }
            | Self::Paragraph { node_id, .. }
            | Self::Heading { node_id, .. }
            | Self::Blockquote { node_id, .. }
            | Self::CodeBlock { node_id, .. }
            | Self::BulletList { node_id, .. }
            | Self::OrderedList { node_id, .. }
            | Self::ListItem { node_id, .. }
            | Self::TaskList { node_id, .. }
            | Self::TaskItem { node_id, .. }
            | Self::Divider { node_id }
            | Self::Image { node_id, .. }
            | Self::Audio { node_id, .. }
            | Self::Video { node_id, .. }
            | Self::Attachment { node_id, .. }
            | Self::MemoryReference { node_id, .. }
            | Self::UnsupportedBlock { node_id, .. } => Some(node_id),
        }
    }

    pub fn children(&self) -> &[DocumentNode] {
        match self {
            Self::Doc { content, .. }
            | Self::Paragraph { content, .. }
            | Self::Heading { content, .. }
            | Self::Blockquote { content, .. }
            | Self::CodeBlock { content, .. }
            | Self::BulletList { content, .. }
            | Self::OrderedList { content, .. }
            | Self::ListItem { content, .. }
            | Self::TaskList { content, .. }
            | Self::TaskItem { content, .. } => content,
            _ => &[],
        }
    }

    pub fn referenced_asset_id(&self) -> Option<&str> {
        match self {
            Self::Image { asset_id, .. }
            | Self::Audio { asset_id, .. }
            | Self::Video { asset_id, .. }
            | Self::Attachment { asset_id, .. } => Some(asset_id),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum DocumentMark {
    Bold,
    Italic,
    Underline,
    Strike,
    Highlight,
    TextColor { color: String },
    Link { href: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TextAlign {
    Left,
    Center,
    Right,
    Justify,
}

/// Cross-platform body document used by the native editor contract.
/// Title belongs to the Journal envelope and is intentionally absent here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OwnMateDocumentV3 {
    pub document_schema_version: u32,
    pub blocks: Vec<NativeBlockV3>,
}

impl OwnMateDocumentV3 {
    pub fn empty(block_id: impl Into<String>) -> Self {
        Self {
            document_schema_version: 3,
            blocks: vec![NativeBlockV3::Paragraph {
                id: block_id.into(),
                content: vec![],
            }],
        }
    }
}

/// Stable, document-owned presentation hints for an atomic editor block.
///
/// Width and optional visual height are integer ratios of the body width, so the canonical
/// document remains independent of Android pixels and density. The object is intentionally sparse:
/// absent height preserves content-derived layout without putting mutable Entity state into Document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeBlockPresentationV1 {
    pub width_permille: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height_permille: Option<u16>,
    #[serde(default, skip_serializing_if = "NativeBlockDockV1::is_none")]
    pub dock: NativeBlockDockV1,
}

impl Default for NativeBlockPresentationV1 {
    fn default() -> Self {
        Self {
            width_permille: MAX_NATIVE_BLOCK_WIDTH_PERMILLE,
            height_permille: None,
            dock: NativeBlockDockV1::None,
        }
    }
}

impl NativeBlockPresentationV1 {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    pub fn is_canonical(&self) -> bool {
        NATIVE_BLOCK_WIDTH_ANCHORS_PERMILLE.contains(&self.width_permille)
            && self
                .height_permille
                .is_none_or(|height| NATIVE_BLOCK_HEIGHT_ANCHORS_PERMILLE.contains(&height))
            && (self.width_permille < MAX_NATIVE_BLOCK_WIDTH_PERMILLE || self.dock.is_none())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NativeBlockDockV1 {
    #[default]
    None,
    Start,
    End,
}

impl NativeBlockDockV1 {
    pub fn is_none(&self) -> bool {
        *self == Self::None
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum NativeBlockV3 {
    Paragraph {
        id: String,
        #[serde(default)]
        content: Vec<NativeInlineV3>,
    },
    Heading {
        id: String,
        level: u8,
        #[serde(default)]
        content: Vec<NativeInlineV3>,
    },
    BulletedList {
        id: String,
        items: Vec<NativeListItemV3>,
        #[serde(default, skip_serializing_if = "NativeListMarkerV3::is_bullet")]
        marker: NativeListMarkerV3,
    },
    OrderedList {
        id: String,
        #[serde(default = "default_ordered_start")]
        start: u32,
        items: Vec<NativeListItemV3>,
    },
    Blockquote {
        id: String,
        #[serde(default)]
        content: Vec<NativeInlineV3>,
    },
    CodeBlock {
        id: String,
        #[serde(default)]
        language: String,
        #[serde(default)]
        content: Vec<NativeInlineV3>,
    },
    Image {
        id: String,
        asset_id: String,
        #[serde(default)]
        alt: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        presentation: Option<NativeBlockPresentationV1>,
    },
    Drawing {
        id: String,
        asset_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        presentation: Option<NativeBlockPresentationV1>,
    },
    MediaGroup {
        id: String,
        items: Vec<NativeVisualMediaV3>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        presentation: Option<NativeBlockPresentationV1>,
    },
    Attachment {
        id: String,
        asset_id: String,
        kind: NativeAttachmentKindV3,
        #[serde(default)]
        label: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        presentation: Option<NativeBlockPresentationV1>,
    },
    ContextReference {
        id: String,
        kind: NativeContextKindV3,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        presentation: Option<NativeBlockPresentationV1>,
    },
    ReminderReference {
        id: String,
        reminder_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        presentation: Option<NativeBlockPresentationV1>,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NativeListMarkerV3 {
    #[default]
    Bullet,
    Dash,
}

impl NativeListMarkerV3 {
    fn is_bullet(&self) -> bool {
        *self == Self::Bullet
    }
}

impl NativeBlockV3 {
    pub fn id(&self) -> &str {
        match self {
            Self::Paragraph { id, .. }
            | Self::Heading { id, .. }
            | Self::BulletedList { id, .. }
            | Self::OrderedList { id, .. }
            | Self::Blockquote { id, .. }
            | Self::CodeBlock { id, .. }
            | Self::Image { id, .. }
            | Self::Drawing { id, .. }
            | Self::MediaGroup { id, .. }
            | Self::Attachment { id, .. }
            | Self::ContextReference { id, .. }
            | Self::ReminderReference { id, .. } => id,
        }
    }

    pub fn referenced_asset_id(&self) -> Option<&str> {
        match self {
            Self::Image { asset_id, .. }
            | Self::Drawing { asset_id, .. }
            | Self::Attachment { asset_id, .. } => Some(asset_id),
            _ => None,
        }
    }

    pub fn presentation(&self) -> Option<&NativeBlockPresentationV1> {
        match self {
            Self::Image { presentation, .. }
            | Self::Drawing { presentation, .. }
            | Self::MediaGroup { presentation, .. }
            | Self::Attachment { presentation, .. }
            | Self::ContextReference { presentation, .. }
            | Self::ReminderReference { presentation, .. } => presentation.as_ref(),
            Self::Paragraph { .. }
            | Self::Heading { .. }
            | Self::BulletedList { .. }
            | Self::OrderedList { .. }
            | Self::Blockquote { .. }
            | Self::CodeBlock { .. } => None,
        }
    }

    pub fn set_presentation(&mut self, presentation: Option<NativeBlockPresentationV1>) -> bool {
        let target = match self {
            Self::Image { presentation, .. }
            | Self::Drawing { presentation, .. }
            | Self::MediaGroup { presentation, .. }
            | Self::Attachment { presentation, .. }
            | Self::ContextReference { presentation, .. }
            | Self::ReminderReference { presentation, .. } => presentation,
            Self::Paragraph { .. }
            | Self::Heading { .. }
            | Self::BulletedList { .. }
            | Self::OrderedList { .. }
            | Self::Blockquote { .. }
            | Self::CodeBlock { .. } => return false,
        };
        *target = presentation.filter(|value| !value.is_default());
        true
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum NativeVisualMediaV3 {
    Image {
        id: String,
        asset_id: String,
        #[serde(default)]
        alt: String,
    },
    Video {
        id: String,
        asset_id: String,
        #[serde(default)]
        label: String,
    },
}

impl NativeVisualMediaV3 {
    pub fn id(&self) -> &str {
        match self {
            Self::Image { id, .. } | Self::Video { id, .. } => id,
        }
    }

    pub fn asset_id(&self) -> &str {
        match self {
            Self::Image { asset_id, .. } | Self::Video { asset_id, .. } => asset_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeListItemV3 {
    pub id: String,
    #[serde(default)]
    pub content: Vec<NativeInlineV3>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeInlineV3 {
    pub text: String,
    #[serde(default)]
    pub marks: Vec<NativeMarkV3>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum NativeMarkV3 {
    Bold,
    Italic,
    Underline,
    Strikethrough,
    ForegroundColor { rgb: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NativeAttachmentKindV3 {
    Video,
    Audio,
    File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NativeContextKindV3 {
    Location,
    Mood,
    Prompt,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_legacy_document_keeps_its_schema_and_stable_root_id() {
        let document = OwnMateDocumentV1::empty("root");
        assert_eq!(document.document_schema_version, 2);
        assert_eq!(document.root.node_id(), Some("root"));
    }

    #[test]
    fn native_document_never_uses_the_legacy_fixture_schema() {
        let document = OwnMateDocumentV3::empty("body");
        assert_eq!(document.document_schema_version, 3);
        assert!(document.document_schema_version > LEGACY_DOCUMENT_SCHEMA_VERSION);
    }

    #[test]
    fn marks_round_trip_without_platform_types() {
        let mark = DocumentMark::Link {
            href: "https://ownmate.app".into(),
        };
        let json = serde_json::to_string(&mark).unwrap();
        assert_eq!(serde_json::from_str::<DocumentMark>(&json).unwrap(), mark);
    }

    #[test]
    fn formatting_extensions_round_trip_and_remain_optional() {
        let json = r##"{"documentSchemaVersion":2,"type":"doc","nodeId":"root","content":[{"type":"paragraph","nodeId":"body","textAlign":"center","content":[{"type":"text","text":"hello","marks":[{"type":"textColor","color":"#336699"}]}]}]}"##;
        let document: OwnMateDocumentV1 = serde_json::from_str(json).unwrap();
        assert_eq!(
            serde_json::from_str::<OwnMateDocumentV1>(&serde_json::to_string(&document).unwrap())
                .unwrap(),
            document
        );
    }

    #[test]
    fn asset_nodes_reject_platform_and_storage_fields() {
        let json = r#"{"documentSchemaVersion":1,"type":"doc","nodeId":"root","content":[{"type":"image","nodeId":"image","assetId":"asset","storageKey":"image/asset.jpg"}]}"#;
        assert!(serde_json::from_str::<OwnMateDocumentV1>(json).is_err());
    }

    #[test]
    fn native_document_v3_round_trips_required_cross_platform_vocabulary() {
        let json = r##"{"documentSchemaVersion":3,"blocks":[{"type":"paragraph","id":"p","content":[{"text":"你好🙂","marks":[{"type":"bold"},{"type":"foregroundColor","rgb":"#336699"}]}]},{"type":"heading","id":"h","level":2,"content":[]},{"type":"bulletedList","id":"ul","items":[{"id":"uli","content":[{"text":"项目","marks":[]}]}]},{"type":"orderedList","id":"ol","start":3,"items":[{"id":"oli","content":[]}]},{"type":"blockquote","id":"q","content":[]},{"type":"image","id":"image","assetId":"asset-image","alt":"图片"},{"type":"drawing","id":"drawing","assetId":"asset-drawing"},{"type":"mediaGroup","id":"group","items":[{"type":"image","id":"group-image","assetId":"asset-group-image","alt":""},{"type":"video","id":"group-video","assetId":"asset-group-video","label":"片段"}]},{"type":"attachment","id":"audio","assetId":"asset-audio","kind":"audio","label":"录音"},{"type":"contextReference","id":"mood","kind":"mood"},{"type":"reminderReference","id":"reminder-block","reminderId":"reminder-1"}]}"##;
        let document: OwnMateDocumentV3 = serde_json::from_str(json).unwrap();
        assert_eq!(document.document_schema_version, 3);
        assert_eq!(document.blocks.len(), 11);
        assert_eq!(
            serde_json::from_str::<OwnMateDocumentV3>(&serde_json::to_string(&document).unwrap())
                .unwrap(),
            document
        );
    }

    #[test]
    fn native_document_v3_rejects_platform_fields() {
        let json = r#"{"documentSchemaVersion":3,"blocks":[{"type":"image","id":"image","assetId":"asset","contentUri":"content://private"}]}"#;
        assert!(serde_json::from_str::<OwnMateDocumentV3>(json).is_err());
    }

    #[test]
    fn sparse_atomic_presentation_round_trips_semantic_visual_height() {
        let json = r#"{"documentSchemaVersion":3,"blocks":[{"type":"image","id":"image","assetId":"asset","presentation":{"widthPermille":670,"heightPermille":330,"dock":"end"}}]}"#;
        let document: OwnMateDocumentV3 = serde_json::from_str(json).unwrap();
        let encoded = serde_json::to_string(&document).unwrap();

        assert!(encoded.contains("\"heightPermille\":330"));
        assert_eq!(
            serde_json::from_str::<OwnMateDocumentV3>(&encoded).unwrap(),
            document
        );
    }

    #[test]
    fn native_list_marker_defaults_to_omitted_bullet_and_round_trips_dash() {
        let bullet: OwnMateDocumentV3 = serde_json::from_str(
            r#"{"documentSchemaVersion":3,"blocks":[{"type":"bulletedList","id":"bullet","items":[]}]}"#,
        )
        .unwrap();
        let bullet_json = serde_json::to_value(&bullet).unwrap();
        assert!(bullet_json["blocks"][0].get("marker").is_none());

        let dash: OwnMateDocumentV3 = serde_json::from_str(
            r#"{"documentSchemaVersion":3,"blocks":[{"type":"bulletedList","id":"dash","items":[],"marker":"dash"}]}"#,
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(&dash).unwrap()["blocks"][0]["marker"],
            "dash"
        );
    }

    #[test]
    fn shared_native_editor_fixture_is_accepted() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../contracts/editor-native/v1/document-v3.json"
        ))
        .unwrap();
        let document: OwnMateDocumentV3 =
            serde_json::from_value(fixture.get("input").unwrap().clone()).unwrap();
        assert_eq!(document.document_schema_version, 3);
        assert_eq!(document.blocks[0].id(), "paragraph-1");
    }
}
