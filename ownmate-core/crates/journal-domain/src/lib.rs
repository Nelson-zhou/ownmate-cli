use asset_manifest::{AssetManifestError, AssetManifestV1, validate_assets};
use canonical_json::{CanonicalJsonError, canonicalize, sha256_hex};
use document_model::{OwnMateDocumentV1, OwnMateDocumentV3};
use document_validation::{
    DocumentValidationError, validate_document, validate_native_document_v3,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MIN_JOURNAL_SCHEMA_VERSION: u32 = 2;
pub const MAX_LEGACY_JOURNAL_SCHEMA_VERSION: u32 = 4;
pub const NATIVE_JOURNAL_SCHEMA_VERSION: u32 = 5;
pub const JOURNAL_SCHEMA_VERSION: u32 = NATIVE_JOURNAL_SCHEMA_VERSION;
pub const MAX_JOURNAL_TITLE_UTF16: u32 = 1024;
pub const MAX_JOURNAL_CONTAINER_ID_BYTES: usize = 128;
pub const MAX_WEB_PREVIEW_COUNT: usize = 64;
pub const MAX_WEB_PREVIEW_URL_BYTES: usize = 2_048;
pub const MAX_WEB_PREVIEW_TITLE_UTF16: usize = 512;
pub const MAX_WEB_PREVIEW_DESCRIPTION_UTF16: usize = 2_048;
pub const MAX_WEB_PREVIEW_SITE_NAME_UTF16: usize = 120;
pub const MAX_WEB_PREVIEW_CAPTURED_AT_BYTES: usize = 64;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnMateJournalV1 {
    pub journal_schema_version: u32,
    pub entry_id: String,
    pub journal_date: String,
    pub occurred_at: String,
    pub created_at: String,
    pub updated_at: String,
    pub timezone: String,
    pub revision: u64,
    pub document: OwnMateDocumentV1,
    pub context: JournalContextV1,
    pub assets: Vec<AssetManifestV1>,
    pub source: JournalSourceV1,
}

/// Canonical Journal envelope for the native cross-platform editor.
///
/// The title is deliberately independent from the body Document. Keeping a
/// separate type makes an invalid schema-5/legacy-Document combination
/// unrepresentable after deserialization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OwnMateJournalV5 {
    pub journal_schema_version: u32,
    pub entry_id: String,
    /// Journal Container belongs to the Journal envelope, never the body Document.
    /// Old schema-5 payloads remain valid and are assigned to the stable default by Room/import.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
    pub journal_date: String,
    pub occurred_at: String,
    pub created_at: String,
    pub updated_at: String,
    pub timezone: String,
    pub revision: u64,
    pub title: String,
    /// Missing means enabled. Omit true to preserve existing canonical hashes.
    #[serde(
        default = "default_title_enabled",
        skip_serializing_if = "is_title_enabled"
    )]
    pub title_enabled: bool,
    pub document: OwnMateDocumentV3,
    pub context: JournalContextV1,
    pub assets: Vec<AssetManifestV1>,
    pub source: JournalSourceV1,
    /// Historical presentation metadata for permanent HTTP(S) URLs in Document.
    /// Empty keeps pre-feature Journal v5 hashes byte-for-byte stable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub web_previews: Vec<WebPreviewSnapshotV1>,
}

fn default_title_enabled() -> bool {
    true
}
fn is_title_enabled(value: &bool) -> bool {
    *value
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WebPreviewSnapshotV1 {
    pub url: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site_name: Option<String>,
    pub captured_at: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JournalContextV1 {
    pub location: Option<LocationContextV1>,
    pub weather: Option<WeatherContextV1>,
    pub mood: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_of_mind: Option<StateOfMindV1>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub provenance: ContextProvenanceV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StateOfMindV1 {
    pub version: u32,
    pub entry_type: StateOfMindEntryTypeV1,
    pub score: i32,
    #[serde(default)]
    pub descriptors: Vec<String>,
    #[serde(default)]
    pub factors: Vec<String>,
    pub additional_context: Option<String>,
    pub logged_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StateOfMindEntryTypeV1 {
    Emotion,
    Mood,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocationContextV1 {
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub name: Option<String>,
    pub address: Option<String>,
    pub city: Option<String>,
    pub district: Option<String>,
    pub province: Option<String>,
    pub country: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WeatherContextV1 {
    pub summary: String,
    pub temperature_celsius: Option<f32>,
    pub code: Option<String>,
    pub feels_like_celsius: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<WeatherDetailsSnapshotV1>,
}

/// Optional weather snapshot; old records stay unchanged until explicit weather acquisition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WeatherDetailsSnapshotV1 {
    pub humidity: Option<f64>,
    pub wind_dir: Option<String>,
    pub wind_scale: Option<String>,
    pub wind_scale_is_beaufort: bool,
    pub daily_summary: bool,
    pub observed_at: Option<String>,
    pub min_temperature_celsius: Option<f64>,
    pub max_temperature_celsius: Option<f64>,
    pub wind_speed_kmh: Option<f64>,
    pub pressure_hpa: Option<f64>,
    pub visibility_km: Option<f64>,
    pub precipitation_mm: Option<f64>,
    pub cloud_cover_percent: Option<f64>,
    pub dew_point_celsius: Option<f64>,
    pub sunrise: Option<String>,
    pub sunset: Option<String>,
    pub moonrise: Option<String>,
    pub moonset: Option<String>,
    pub moon_phase: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextProvenanceV1 {
    pub occurred_at: Option<FieldProvenanceV1>,
    pub location: Option<FieldProvenanceV1>,
    pub weather: Option<FieldProvenanceV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldProvenanceV1 {
    pub source: ProvenanceSourceV1,
    pub asset_id: Option<String>,
    #[serde(default)]
    pub source_asset_removed: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceSourceV1 {
    Manual,
    DeviceLocation,
    MediaMetadata,
    WeatherProvider,
    Import,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum JournalSourceV1 {
    OwnMate,
    External {
        provider: String,
        external_id: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidatedJournal {
    pub canonical_json: String,
    pub content_hash: String,
    pub revision: u64,
}

#[derive(Debug, Error)]
pub enum JournalError {
    #[error("unsupported journal schema version")]
    SchemaVersion,
    #[error("entry id is blank")]
    EntryId,
    #[error("journal container id is invalid")]
    ContainerId,
    #[error("revision must be positive")]
    Revision,
    #[error("journal title exceeds its UTF-16 limit")]
    TitleTooLong,
    #[error("disabled title must be empty")]
    DisabledTitleNotEmpty,
    #[error("invalid web preview snapshot")]
    WebPreview,
    #[error("invalid state of mind")]
    StateOfMind,
    #[error("invalid weather snapshot")]
    WeatherSnapshot,
    #[error(transparent)]
    Asset(#[from] AssetManifestError),
    #[error(transparent)]
    Document(#[from] DocumentValidationError),
    #[error(transparent)]
    Canonical(#[from] CanonicalJsonError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JournalVersionProbe {
    journal_schema_version: u32,
}

pub fn validate_canonicalize_hash_json(input: &str) -> Result<ValidatedJournal, JournalError> {
    let version = serde_json::from_str::<JournalVersionProbe>(input)?.journal_schema_version;
    match version {
        MIN_JOURNAL_SCHEMA_VERSION..=MAX_LEGACY_JOURNAL_SCHEMA_VERSION => {
            let journal: OwnMateJournalV1 = serde_json::from_str(input)?;
            validate_journal(&journal)?;
            canonicalize_validated(&journal, journal.revision)
        }
        NATIVE_JOURNAL_SCHEMA_VERSION => {
            let journal: OwnMateJournalV5 = serde_json::from_str(input)?;
            validate_native_journal(&journal)?;
            canonicalize_validated(&journal, journal.revision)
        }
        _ => Err(JournalError::SchemaVersion),
    }
}

fn canonicalize_validated<T: Serialize>(
    journal: &T,
    revision: u64,
) -> Result<ValidatedJournal, JournalError> {
    let canonical_json = canonicalize(journal)?;
    Ok(ValidatedJournal {
        content_hash: sha256_hex(&canonical_json),
        canonical_json,
        revision,
    })
}

/// Transitional validator for journal schemas 2-4 while the active WebView
/// editor remains in place. This path is deleted with that runtime; schema 5
/// never deserializes through the legacy type.
pub fn validate_journal(journal: &OwnMateJournalV1) -> Result<(), JournalError> {
    if !(MIN_JOURNAL_SCHEMA_VERSION..=MAX_LEGACY_JOURNAL_SCHEMA_VERSION)
        .contains(&journal.journal_schema_version)
    {
        return Err(JournalError::SchemaVersion);
    }
    if journal.journal_schema_version == MIN_JOURNAL_SCHEMA_VERSION
        && journal.document.document_schema_version > 1
    {
        return Err(JournalError::SchemaVersion);
    }
    validate_common(
        journal.journal_schema_version,
        &journal.entry_id,
        journal.revision,
        &journal.context,
    )?;
    validate_assets(&journal.assets)?;
    validate_document(&journal.document, &journal.assets)?;
    Ok(())
}

pub fn validate_native_journal(journal: &OwnMateJournalV5) -> Result<(), JournalError> {
    if journal.journal_schema_version != NATIVE_JOURNAL_SCHEMA_VERSION {
        return Err(JournalError::SchemaVersion);
    }
    validate_common(
        journal.journal_schema_version,
        &journal.entry_id,
        journal.revision,
        &journal.context,
    )?;
    if journal.container_id.as_deref().is_some_and(|value| {
        value.trim().is_empty()
            || value.len() > MAX_JOURNAL_CONTAINER_ID_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    }) {
        return Err(JournalError::ContainerId);
    }
    if journal
        .title
        .encode_utf16()
        .take(MAX_JOURNAL_TITLE_UTF16 as usize + 1)
        .count()
        > MAX_JOURNAL_TITLE_UTF16 as usize
    {
        return Err(JournalError::TitleTooLong);
    }
    if !journal.title_enabled && !journal.title.is_empty() {
        return Err(JournalError::DisabledTitleNotEmpty);
    }
    validate_web_previews(&journal.web_previews)?;
    validate_assets(&journal.assets)?;
    validate_native_document_v3(&journal.document, &journal.assets)?;
    Ok(())
}

fn validate_web_previews(previews: &[WebPreviewSnapshotV1]) -> Result<(), JournalError> {
    if previews.len() > MAX_WEB_PREVIEW_COUNT {
        return Err(JournalError::WebPreview);
    }
    if previews.windows(2).any(|pair| {
        pair[0]
            .url
            .encode_utf16()
            .cmp(pair[1].url.encode_utf16())
            .is_ge()
    }) {
        return Err(JournalError::WebPreview);
    }
    let mut urls = std::collections::HashSet::with_capacity(previews.len());
    for preview in previews {
        let valid_optional = |value: Option<&str>, max_utf16: usize| {
            value.is_none_or(|text| {
                !text.trim().is_empty()
                    && !text.chars().any(char::is_control)
                    && text.encode_utf16().take(max_utf16 + 1).count() <= max_utf16
            })
        };
        if !valid_web_preview_url(&preview.url)
            || !urls.insert(preview.url.as_str())
            || preview.title.trim().is_empty()
            || preview.title.chars().any(char::is_control)
            || preview
                .title
                .encode_utf16()
                .take(MAX_WEB_PREVIEW_TITLE_UTF16 + 1)
                .count()
                > MAX_WEB_PREVIEW_TITLE_UTF16
            || !valid_optional(
                preview.description.as_deref(),
                MAX_WEB_PREVIEW_DESCRIPTION_UTF16,
            )
            || !valid_optional(
                preview.site_name.as_deref(),
                MAX_WEB_PREVIEW_SITE_NAME_UTF16,
            )
            || preview.captured_at.trim().is_empty()
            || preview.captured_at.len() > MAX_WEB_PREVIEW_CAPTURED_AT_BYTES
        {
            return Err(JournalError::WebPreview);
        }
    }
    Ok(())
}

fn valid_web_preview_url(value: &str) -> bool {
    if value.len() < 8
        || value.len() > MAX_WEB_PREVIEW_URL_BYTES
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return false;
    }
    let remainder = if value
        .get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
    {
        &value[8..]
    } else if value
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"))
    {
        &value[7..]
    } else {
        return false;
    };
    let authority = remainder.split(['/', '?', '#']).next().unwrap_or_default();
    !authority.is_empty() && !authority.contains('@') && !authority.contains('\\')
}

fn validate_common(
    journal_schema_version: u32,
    entry_id: &str,
    revision: u64,
    context: &JournalContextV1,
) -> Result<(), JournalError> {
    if entry_id.trim().is_empty() {
        return Err(JournalError::EntryId);
    }
    if revision == 0 {
        return Err(JournalError::Revision);
    }
    if let Some(state) = &context.state_of_mind {
        if journal_schema_version < 4 {
            return Err(JournalError::SchemaVersion);
        }
        validate_state_of_mind(state)?;
    }
    if let Some(details) = context
        .weather
        .as_ref()
        .and_then(|weather| weather.details.as_ref())
    {
        let percentage =
            |value: Option<f64>| value.is_none_or(|v| v.is_finite() && (0.0..=100.0).contains(&v));
        let positive = |value: Option<f64>| value.is_none_or(|v| v.is_finite() && v >= 0.0);
        let text = [
            &details.wind_dir,
            &details.wind_scale,
            &details.observed_at,
            &details.sunrise,
            &details.sunset,
            &details.moonrise,
            &details.moonset,
            &details.moon_phase,
        ];
        if !percentage(details.humidity)
            || !percentage(details.cloud_cover_percent)
            || !positive(details.wind_speed_kmh)
            || !positive(details.visibility_km)
            || !positive(details.precipitation_mm)
            || details
                .pressure_hpa
                .is_some_and(|v| !v.is_finite() || v <= 0.0)
            || text
                .iter()
                .any(|v| v.as_ref().is_some_and(|s| s.len() > 256))
            || [
                details.min_temperature_celsius,
                details.max_temperature_celsius,
                details.dew_point_celsius,
            ]
            .iter()
            .flatten()
            .any(|v| !v.is_finite())
        {
            return Err(JournalError::WeatherSnapshot);
        }
    }
    Ok(())
}

fn validate_state_of_mind(state: &StateOfMindV1) -> Result<(), JournalError> {
    let valid_text =
        |value: &str, max: usize| !value.trim().is_empty() && value.chars().count() <= max;
    if state.version != 1
        || !(-3..=3).contains(&state.score)
        || state.descriptors.len() > 12
        || state.factors.len() > 12
        || state.descriptors.iter().any(|value| !valid_text(value, 32))
        || state.factors.iter().any(|value| !valid_text(value, 32))
        || state
            .additional_context
            .as_deref()
            .is_some_and(|value| !valid_text(value, 500))
        || !valid_text(&state.logged_at, 64)
    {
        return Err(JournalError::StateOfMind);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn native_journal_fixture() -> (serde_json::Value, OwnMateJournalV5) {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../contracts/editor-native/v1/journal-v5.json"
        ))
        .expect("valid shared native Journal fixture");
        let journal = serde_json::from_value(fixture["accepted"]["input"].clone())
            .expect("accepted fixture must decode as Journal v5");
        (fixture, journal)
    }

    #[test]
    fn title_visibility_survives_transport_without_changing_old_hashes() {
        let (fixture, _) = native_journal_fixture();
        let mut input = fixture["accepted"]["input"].clone();
        let before = validate_canonicalize_hash_json(&input.to_string()).unwrap();
        input["titleEnabled"] = serde_json::json!(true);
        assert_eq!(
            before.content_hash,
            validate_canonicalize_hash_json(&input.to_string())
                .unwrap()
                .content_hash
        );
        input["title"] = fixture["titleVisibility"]["removed"]["title"].clone();
        input["titleEnabled"] = fixture["titleVisibility"]["removed"]["titleEnabled"].clone();
        let hidden = validate_canonicalize_hash_json(&input.to_string()).unwrap();
        let roundtrip = validate_canonicalize_hash_json(&hidden.canonical_json).unwrap();
        assert_eq!(hidden.content_hash, roundtrip.content_hash);
        let decoded: OwnMateJournalV5 = serde_json::from_str(&roundtrip.canonical_json).unwrap();
        assert!(!decoded.title_enabled);
        input["titleEnabled"] = serde_json::json!(true);
        assert_ne!(
            hidden.content_hash,
            validate_canonicalize_hash_json(&input.to_string())
                .unwrap()
                .content_hash
        );
        input["titleEnabled"] = serde_json::json!("false");
        assert!(validate_canonicalize_hash_json(&input.to_string()).is_err());
        input["titleEnabled"] = serde_json::json!(false);
        input["title"] = serde_json::json!("must not silently hide content");
        assert!(validate_canonicalize_hash_json(&input.to_string()).is_err());
    }

    #[test]
    fn weather_snapshot_survives_canonical_transport_and_changes_hash() {
        let (fixture, _) = native_journal_fixture();
        let mut input = fixture["accepted"]["input"].clone();
        input["context"]["weather"] = fixture["weatherSnapshot"].clone();
        let first = validate_canonicalize_hash_json(&input.to_string()).unwrap();
        let second = validate_canonicalize_hash_json(&first.canonical_json).unwrap();
        assert_eq!(first.content_hash, second.content_hash);
        let canonical: serde_json::Value = serde_json::from_str(&second.canonical_json).unwrap();
        assert_eq!(canonical["context"]["weather"], fixture["weatherSnapshot"]);
        input["context"]["weather"]["details"]["humidity"] = serde_json::json!(66.0);
        assert_ne!(
            first.content_hash,
            validate_canonicalize_hash_json(&input.to_string())
                .unwrap()
                .content_hash
        );
        input["context"]["weather"]["details"]["humidity"] = serde_json::json!(101.0);
        assert!(matches!(
            validate_canonicalize_hash_json(&input.to_string()),
            Err(JournalError::WeatherSnapshot)
        ));
    }

    #[test]
    fn shared_native_journal_keeps_title_outside_document_and_hashes_stably() {
        let (fixture, journal) = native_journal_fixture();
        assert_eq!(fixture["limits"]["maxTitleUtf16"], MAX_JOURNAL_TITLE_UTF16);
        assert_eq!(
            fixture["limits"]["maxWebPreviewCount"],
            MAX_WEB_PREVIEW_COUNT
        );
        assert_eq!(
            fixture["limits"]["maxWebPreviewUrlBytes"],
            MAX_WEB_PREVIEW_URL_BYTES
        );
        assert_eq!(
            fixture["limits"]["maxWebPreviewTitleUtf16"],
            MAX_WEB_PREVIEW_TITLE_UTF16
        );
        assert_eq!(
            fixture["limits"]["maxWebPreviewDescriptionUtf16"],
            MAX_WEB_PREVIEW_DESCRIPTION_UTF16
        );
        assert_eq!(
            fixture["limits"]["maxWebPreviewSiteNameUtf16"],
            MAX_WEB_PREVIEW_SITE_NAME_UTF16
        );
        assert_eq!(
            fixture["limits"]["maxWebPreviewCapturedAtBytes"],
            MAX_WEB_PREVIEW_CAPTURED_AT_BYTES
        );
        assert_eq!(fixture["ordering"]["webPreviews"], "exactUrlUtf16Ascending");
        assert_eq!(
            journal.container_id.as_deref(),
            Some("ownmate-personal-default-v1")
        );
        assert_eq!(journal.title, "独立标题");
        assert_eq!(journal.document.document_schema_version, 3);
        assert_eq!(journal.web_previews.len(), 1);
        assert_eq!(journal.web_previews[0].title, "抓取时标题");

        let first = validate_canonicalize_hash_json(
            &serde_json::to_string_pretty(&fixture["accepted"]["input"]).unwrap(),
        )
        .unwrap();
        let second = validate_canonicalize_hash_json(&first.canonical_json).unwrap();
        let canonical: serde_json::Value = serde_json::from_str(&first.canonical_json).unwrap();

        assert_eq!(first.content_hash, second.content_hash);
        assert_eq!(
            first.content_hash,
            fixture["accepted"]["expected"]["contentHash"]
        );
        assert_eq!(first.revision, fixture["accepted"]["expected"]["revision"]);
        assert_eq!(canonical["title"], "独立标题");
        assert_eq!(
            canonical["document"]["blocks"][0]["content"][0]["text"],
            "正文第一段 🙂"
        );
        assert!(canonical["document"].get("title").is_none());
        assert_eq!(canonical["webPreviews"][0]["siteName"], "Example");
    }

    #[test]
    fn native_journal_requires_a_title_and_document_v3() {
        let (fixture, _) = native_journal_fixture();
        for case in fixture["rejections"].as_array().unwrap() {
            assert_eq!(case["expectedError"], "journalShape");
            assert!(
                validate_canonicalize_hash_json(&case["input"].to_string()).is_err(),
                "{}",
                case["name"]
            );
        }
    }

    #[test]
    fn native_journal_title_limit_counts_utf16_code_units() {
        let (_, mut journal) = native_journal_fixture();
        journal.title.clear();
        validate_native_journal(&journal).unwrap();

        journal.title = "🙂".repeat((MAX_JOURNAL_TITLE_UTF16 / 2) as usize);
        validate_native_journal(&journal).unwrap();

        journal.title.push('a');
        assert!(matches!(
            validate_native_journal(&journal),
            Err(JournalError::TitleTooLong)
        ));
    }

    #[test]
    fn native_journal_web_preview_is_optional_bounded_and_canonical() {
        let (fixture, _) = native_journal_fixture();
        let mut input = fixture["accepted"]["input"].clone();
        input["webPreviews"] = serde_json::json!([{
            "url": "https://example.com/moment?entry=private",
            "title": "抓取时标题",
            "description": "抓取时摘要",
            "siteName": "Example",
            "capturedAt": "2026-08-31T02:03:04Z"
        }]);

        let first = validate_canonicalize_hash_json(&input.to_string()).unwrap();
        let second = validate_canonicalize_hash_json(&first.canonical_json).unwrap();
        let canonical: serde_json::Value = serde_json::from_str(&first.canonical_json).unwrap();

        assert_eq!(first.content_hash, second.content_hash);
        assert_eq!(canonical["webPreviews"][0]["title"], "抓取时标题");
        assert_eq!(
            canonical["document"]["blocks"][0]["content"][0]["text"],
            "正文第一段 🙂"
        );
        assert!(canonical["context"].get("webPreviews").is_none());

        input["webPreviews"] = serde_json::json!([
            {
                "url": "https://example.com/same",
                "title": "一",
                "capturedAt": "2026-08-31T02:03:04Z"
            },
            {
                "url": "https://example.com/same",
                "title": "二",
                "capturedAt": "2026-08-31T02:04:04Z"
            }
        ]);
        assert!(matches!(
            validate_canonicalize_hash_json(&input.to_string()),
            Err(JournalError::WebPreview)
        ));

        input["webPreviews"] = serde_json::json!([
            {
                "url": "https://example.com/z",
                "title": "后",
                "capturedAt": "2026-08-31T02:03:04Z"
            },
            {
                "url": "https://example.com/a",
                "title": "前",
                "capturedAt": "2026-08-31T02:04:04Z"
            }
        ]);
        assert!(matches!(
            validate_canonicalize_hash_json(&input.to_string()),
            Err(JournalError::WebPreview)
        ));

        input["webPreviews"] = serde_json::json!([
            {
                "url": "https://example.com/\u{10000}",
                "title": "UTF-16 前项",
                "capturedAt": "2026-08-31T02:03:04Z"
            },
            {
                "url": "https://example.com/\u{e000}",
                "title": "UTF-16 后项",
                "capturedAt": "2026-08-31T02:04:04Z"
            }
        ]);
        validate_canonicalize_hash_json(&input.to_string()).unwrap();
    }

    #[test]
    fn validated_journal_produces_stable_hash() {
        let journal = OwnMateJournalV1 {
            journal_schema_version: MAX_LEGACY_JOURNAL_SCHEMA_VERSION,
            entry_id: "entry".into(),
            journal_date: "2026-07-17".into(),
            occurred_at: "2026-07-17T08:00:00Z".into(),
            created_at: "2026-07-17T00:00:00Z".into(),
            updated_at: "2026-07-17T00:00:00Z".into(),
            timezone: "Asia/Shanghai".into(),
            revision: 1,
            document: OwnMateDocumentV1::empty("root"),
            context: JournalContextV1::default(),
            assets: vec![],
            source: JournalSourceV1::OwnMate,
        };
        let input = serde_json::to_string_pretty(&journal).unwrap();
        let first = validate_canonicalize_hash_json(&input).unwrap();
        let second = validate_canonicalize_hash_json(&first.canonical_json).unwrap();
        assert_eq!(first.content_hash, second.content_hash);
    }

    #[test]
    fn accepts_android_bridge_shape() {
        let input = r#"{"journalSchemaVersion":2,"entryId":"new","journalDate":"2026-07-17","occurredAt":"2026-07-17T15:36:43+08:00","createdAt":"2026-07-17T07:36:43Z","updatedAt":"2026-07-17T07:36:47Z","timezone":"Asia/Shanghai","revision":1,"document":{"documentSchemaVersion":1,"type":"doc","nodeId":"root","content":[{"type":"paragraph","nodeId":"p1","content":[]}]},"context":{"location":null,"weather":null,"mood":null,"tags":[],"provenance":{"occurredAt":{"source":"manual"},"location":null,"weather":null}},"assets":[],"source":{"type":"ownMate"}}"#;
        validate_canonicalize_hash_json(input).unwrap();
    }

    #[test]
    fn accepts_location_without_name_and_preserves_time_semantics() {
        let input = r#"{"journalSchemaVersion":2,"entryId":"location-without-name","journalDate":"2026-07-15","occurredAt":"2026-07-15T10:32:00+08:00","createdAt":"2026-07-17T14:06:00Z","updatedAt":"2026-07-17T14:07:00Z","timezone":"Asia/Shanghai","revision":2,"document":{"documentSchemaVersion":1,"type":"doc","nodeId":"root","content":[]},"context":{"location":{"latitude":30.5928,"longitude":114.3055,"address":"武汉市江汉区"},"weather":null,"mood":null,"tags":[],"provenance":{"occurredAt":{"source":"media_metadata","assetId":"asset-a"},"location":{"source":"media_metadata","assetId":"asset-a"},"weather":null}},"assets":[],"source":{"type":"ownMate"}}"#;
        let validated = validate_canonicalize_hash_json(input).unwrap();
        let canonical: serde_json::Value = serde_json::from_str(&validated.canonical_json).unwrap();
        assert_eq!(canonical["occurredAt"], "2026-07-15T10:32:00+08:00");
        assert_eq!(canonical["createdAt"], "2026-07-17T14:06:00Z");
        assert!(canonical["context"]["location"]["name"].is_null());
    }

    #[test]
    fn accepts_coordinate_only_and_no_location_contexts() {
        for location in [r#"{"latitude":30.5928,"longitude":114.3055}"#, "null"] {
            let input = format!(
                r#"{{"journalSchemaVersion":2,"entryId":"location-shape","journalDate":"2026-07-17","occurredAt":"2026-07-17T22:06:00+08:00","createdAt":"2026-07-17T14:06:00Z","updatedAt":"2026-07-17T14:06:00Z","timezone":"Asia/Shanghai","revision":1,"document":{{"documentSchemaVersion":1,"type":"doc","nodeId":"root","content":[]}},"context":{{"location":{location},"weather":null,"mood":null,"tags":[],"provenance":{{"occurredAt":{{"source":"manual"}},"location":null,"weather":null}}}},"assets":[],"source":{{"type":"ownMate"}}}}"#,
            );
            validate_canonicalize_hash_json(&input).unwrap();
        }
    }

    #[test]
    fn accepts_journal_with_remote_only_asset() {
        // 回归用例：媒体同步后原件仅在云端（localState=remoteOnly）的日记必须能保存。
        let input = format!(
            r#"{{"journalSchemaVersion":2,"entryId":"remote-only","journalDate":"2026-07-31","occurredAt":"2026-07-31T10:52:45+08:00","createdAt":"2026-07-31T02:52:45Z","updatedAt":"2026-07-31T02:53:00Z","timezone":"Asia/Shanghai","revision":3,"document":{{"documentSchemaVersion":1,"type":"doc","nodeId":"root","content":[]}},"context":{{"location":null,"weather":null,"mood":null,"tags":[],"provenance":{{"occurredAt":{{"source":"manual"}},"location":null,"weather":null}}}},"assets":[{{"assetId":"asset-a","assetType":"image","mimeType":"image/jpeg","byteSize":56924,"checksum":"{}","createdAt":"2026-07-31T02:52:45Z","width":100,"height":100,"durationMs":null,"originalFilename":null,"localState":"remoteOnly","remoteState":"uploaded","cloudEncryptionMetadata":null}}],"source":{{"type":"ownMate"}}}}"#,
            "a".repeat(64)
        );
        let validated = validate_canonicalize_hash_json(&input).unwrap();
        let canonical: serde_json::Value = serde_json::from_str(&validated.canonical_json).unwrap();
        assert_eq!(canonical["assets"][0]["localState"], "remoteOnly");
    }

    #[test]
    fn state_of_mind_round_trips_in_schema_four() {
        let input = r#"{"journalSchemaVersion":4,"entryId":"mood","journalDate":"2026-08-08","occurredAt":"2026-08-08T08:00:00+08:00","createdAt":"2026-08-08T00:00:00Z","updatedAt":"2026-08-08T00:01:00Z","timezone":"Asia/Shanghai","revision":2,"document":{"documentSchemaVersion":2,"type":"doc","nodeId":"root","content":[]},"context":{"location":null,"weather":null,"mood":"愉快","stateOfMind":{"version":1,"entryType":"emotion","score":2,"descriptors":["轻松","感恩"],"factors":["家人"],"additionalContext":"一起吃了晚饭","loggedAt":"2026-08-08T00:01:00Z"},"tags":[],"provenance":{}},"assets":[],"source":{"type":"ownMate"}}"#;
        let validated = validate_canonicalize_hash_json(input).unwrap();
        let canonical: serde_json::Value = serde_json::from_str(&validated.canonical_json).unwrap();
        assert_eq!(canonical["context"]["stateOfMind"]["score"], 2);
        assert_eq!(
            canonical["context"]["stateOfMind"]["descriptors"][1],
            "感恩"
        );
    }

    #[test]
    fn older_schema_rejects_structured_state_of_mind() {
        let input = r#"{"journalSchemaVersion":3,"entryId":"mood","journalDate":"2026-08-08","occurredAt":"2026-08-08T08:00:00+08:00","createdAt":"2026-08-08T00:00:00Z","updatedAt":"2026-08-08T00:01:00Z","timezone":"Asia/Shanghai","revision":2,"document":{"documentSchemaVersion":2,"type":"doc","nodeId":"root","content":[]},"context":{"location":null,"weather":null,"mood":"愉快","stateOfMind":{"version":1,"entryType":"emotion","score":2,"descriptors":[],"factors":[],"additionalContext":null,"loggedAt":"2026-08-08T00:01:00Z"},"tags":[],"provenance":{}},"assets":[],"source":{"type":"ownMate"}}"#;
        assert!(matches!(
            validate_canonicalize_hash_json(input),
            Err(JournalError::SchemaVersion)
        ));
    }

    #[test]
    fn rejects_invalid_state_of_mind() {
        let input = r#"{"journalSchemaVersion":4,"entryId":"mood","journalDate":"2026-08-08","occurredAt":"2026-08-08T08:00:00+08:00","createdAt":"2026-08-08T00:00:00Z","updatedAt":"2026-08-08T00:01:00Z","timezone":"Asia/Shanghai","revision":2,"document":{"documentSchemaVersion":2,"type":"doc","nodeId":"root","content":[]},"context":{"location":null,"weather":null,"mood":"愉快","stateOfMind":{"version":1,"entryType":"emotion","score":4,"descriptors":[],"factors":[],"additionalContext":null,"loggedAt":"2026-08-08T00:01:00Z"},"tags":[],"provenance":{}},"assets":[],"source":{"type":"ownMate"}}"#;
        assert!(matches!(
            validate_canonicalize_hash_json(input),
            Err(JournalError::StateOfMind)
        ));
    }

    #[test]
    fn rejects_unsupported_or_oversized_state_of_mind_fields() {
        let input = r#"{"journalSchemaVersion":4,"entryId":"mood","journalDate":"2026-08-08","occurredAt":"2026-08-08T08:00:00+08:00","createdAt":"2026-08-08T00:00:00Z","updatedAt":"2026-08-08T00:01:00Z","timezone":"Asia/Shanghai","revision":2,"document":{"documentSchemaVersion":2,"type":"doc","nodeId":"root","content":[]},"context":{"location":null,"weather":null,"mood":"愉快","stateOfMind":{"version":1,"entryType":"emotion","score":2,"descriptors":[],"factors":[],"additionalContext":null,"loggedAt":"2026-08-08T00:01:00Z"},"tags":[],"provenance":{}},"assets":[],"source":{"type":"ownMate"}}"#;
        let base: serde_json::Value = serde_json::from_str(input).unwrap();
        for mutate in ["version", "descriptors", "loggedAt"] {
            let mut candidate = base.clone();
            let state = candidate["context"]["stateOfMind"].as_object_mut().unwrap();
            match mutate {
                "version" => state.insert("version".into(), 2.into()),
                "descriptors" => state.insert(
                    "descriptors".into(),
                    serde_json::Value::Array((0..13).map(|i| format!("word-{i}").into()).collect()),
                ),
                _ => state.insert("loggedAt".into(), "".into()),
            };
            assert!(matches!(
                validate_canonicalize_hash_json(&candidate.to_string()),
                Err(JournalError::StateOfMind)
            ));
        }
    }

    #[test]
    fn schema_three_without_state_keeps_a_stable_canonical_hash() {
        let input = r#"{"journalSchemaVersion":3,"entryId":"legacy","journalDate":"2026-08-08","occurredAt":"2026-08-08T08:00:00+08:00","createdAt":"2026-08-08T00:00:00Z","updatedAt":"2026-08-08T00:01:00Z","timezone":"Asia/Shanghai","revision":2,"document":{"documentSchemaVersion":2,"type":"doc","nodeId":"root","content":[]},"context":{"location":null,"weather":null,"mood":"平静","tags":[],"provenance":{}},"assets":[],"source":{"type":"ownMate"}}"#;
        let first = validate_canonicalize_hash_json(input).unwrap();
        let second = validate_canonicalize_hash_json(&first.canonical_json).unwrap();
        assert_eq!(first.content_hash, second.content_hash);
        assert!(!first.canonical_json.contains("stateOfMind"));
    }
}
