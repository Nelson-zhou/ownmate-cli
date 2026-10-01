use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssetManifestV1 {
    pub asset_id: String,
    pub asset_type: AssetType,
    pub mime_type: String,
    pub byte_size: u64,
    pub checksum: String,
    pub created_at: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub duration_ms: Option<u64>,
    pub original_filename: Option<String>,
    pub local_state: AssetLocalState,
    pub remote_state: AssetRemoteState,
    pub cloud_encryption_metadata: Option<CloudEncryptionMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AssetType {
    Image,
    Audio,
    Video,
    Attachment,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AssetLocalState {
    Pending,
    Available,
    Missing,
    /// 原件仅在云端（pull 不自动下载原件 / 一键释放本机空间），点开时按需回拉。
    RemoteOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AssetRemoteState {
    LocalOnly,
    Pending,
    Uploaded,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudEncryptionMetadata {
    pub algorithm: String,
    pub key_id: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AssetManifestError {
    #[error("asset id is blank")]
    BlankId,
    #[error("duplicate asset id: {0}")]
    DuplicateId(String),
    #[error("checksum must be a lowercase SHA-256 hex string")]
    InvalidChecksum,
    #[error("platform URI or absolute path is forbidden")]
    PlatformPath,
}

pub fn validate_assets(assets: &[AssetManifestV1]) -> Result<(), AssetManifestError> {
    let mut ids = HashSet::new();
    for asset in assets {
        if asset.asset_id.trim().is_empty() {
            return Err(AssetManifestError::BlankId);
        }
        if !ids.insert(asset.asset_id.clone()) {
            return Err(AssetManifestError::DuplicateId(asset.asset_id.clone()));
        }
        if asset.checksum.len() != 64
            || !asset
                .checksum
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(AssetManifestError::InvalidChecksum);
        }
        for value in [
            Some(asset.asset_id.as_str()),
            asset.original_filename.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if value.starts_with("content://")
                || value.starts_with("file://")
                || value.starts_with('/')
            {
                return Err(AssetManifestError::PlatformPath);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asset(id: &str) -> AssetManifestV1 {
        AssetManifestV1 {
            asset_id: id.into(),
            asset_type: AssetType::Image,
            mime_type: "image/jpeg".into(),
            byte_size: 1,
            checksum: "a".repeat(64),
            created_at: "2026-07-17T00:00:00Z".into(),
            width: Some(1),
            height: Some(1),
            duration_ms: None,
            original_filename: None,
            local_state: AssetLocalState::Available,
            remote_state: AssetRemoteState::LocalOnly,
            cloud_encryption_metadata: None,
        }
    }

    #[test]
    fn rejects_duplicates() {
        assert!(matches!(
            validate_assets(&[asset("a"), asset("a")]),
            Err(AssetManifestError::DuplicateId(_))
        ));
    }
    #[test]
    fn rejects_platform_paths() {
        assert_eq!(
            validate_assets(&[asset("content://photo")]),
            Err(AssetManifestError::PlatformPath)
        );
    }

    #[test]
    fn rejects_android_storage_key_in_manifest() {
        let json = format!(
            r#"{{"assetId":"a","storageKey":"image/a.jpg","assetType":"image","mimeType":"image/jpeg","byteSize":1,"checksum":"{}","createdAt":"now","width":null,"height":null,"durationMs":null,"originalFilename":null,"localState":"available","remoteState":"localOnly","cloudEncryptionMetadata":null}}"#,
            "a".repeat(64)
        );
        assert!(serde_json::from_str::<AssetManifestV1>(&json).is_err());
    }

    #[test]
    fn accepts_remote_only_local_state() {
        let json = format!(
            r#"{{"assetId":"a","assetType":"image","mimeType":"image/jpeg","byteSize":1,"checksum":"{}","createdAt":"now","width":null,"height":null,"durationMs":null,"originalFilename":null,"localState":"remoteOnly","remoteState":"uploaded","cloudEncryptionMetadata":null}}"#,
            "a".repeat(64)
        );
        let manifest: AssetManifestV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest.local_state, AssetLocalState::RemoteOnly);
        // 序列化往返保持 camelCase 拼写，canonical JSON 不会漂移。
        let reserialized = serde_json::to_string(&manifest).unwrap();
        assert!(reserialized.contains(r#""localState":"remoteOnly""#));
        assert!(validate_assets(&[manifest]).is_ok());
    }
}
