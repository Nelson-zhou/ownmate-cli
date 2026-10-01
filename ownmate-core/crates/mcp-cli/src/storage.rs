use crate::{McpError, Result};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const KEYRING_SERVICE: &str = "space.ownmate.mcp-cli";
const KEYRING_ACCOUNT: &str = "default-external-client-v1";

#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSession {
    pub protocol_version: u32,
    pub base_url: String,
    pub grant_id: String,
    pub trust_mode: String,
    pub access_token: String,
    pub access_expires_at: u64,
    pub refresh_token: Option<String>,
    pub grant_expires_at: Option<u64>,
    pub dek_key_id: String,
    pub dek_base64: String,
}

impl ExternalSession {
    pub fn is_trusted(&self) -> bool {
        self.trust_mode == "trusted" && self.refresh_token.is_some()
    }
}

pub fn save_trusted(session: &ExternalSession) -> Result<()> {
    if !session.is_trusted() {
        return Err(McpError::Invalid("临时会话不得写入系统凭据库".into()));
    }
    let serialized = Zeroizing::new(serde_json::to_string(session)?);
    entry()?
        .set_password(&serialized)
        .map_err(|error| McpError::Credential(error.to_string()))
}

pub fn load_trusted() -> Result<ExternalSession> {
    let serialized = Zeroizing::new(
        entry()?
            .get_password()
            .map_err(|error| McpError::Credential(error.to_string()))?,
    );
    let session: ExternalSession = serde_json::from_str(&serialized)?;
    if !session.is_trusted() || session.protocol_version != 1 {
        return Err(McpError::Invalid("系统凭据库中的外部客户端凭据无效".into()));
    }
    Ok(session)
}

pub fn delete_trusted() -> Result<()> {
    entry()?
        .delete_credential()
        .map_err(|error| McpError::Credential(error.to_string()))
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
fn entry() -> Result<keyring::Entry> {
    keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)
        .map_err(|error| McpError::Credential(error.to_string()))
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
fn entry() -> Result<UnsupportedEntry> {
    Err(McpError::Credential(
        "当前平台没有受支持的系统凭据库".into(),
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
struct UnsupportedEntry;
