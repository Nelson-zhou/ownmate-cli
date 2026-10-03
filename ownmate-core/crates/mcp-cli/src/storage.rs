use crate::protocol::{ReminderCommandEnvelope, ReminderWriteContext};
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
    #[serde(default)]
    pub keyspace_id: Option<String>,
    #[serde(default)]
    pub keyspace_generation: Option<u64>,
    #[serde(default = "legacy_scopes")]
    pub scopes: Vec<String>,
    #[serde(default)]
    #[zeroize(skip)]
    pub write_context: Option<ReminderWriteContext>,
    #[serde(skip)]
    #[zeroize(skip)]
    pub temporary_commands: Vec<ReminderCommandEnvelope>,
}

impl ExternalSession {
    pub fn keyspace(&self) -> Option<(&str, u64)> {
        self.keyspace_id.as_deref().zip(self.keyspace_generation)
    }
    pub fn require_scope(&self, scope: &str) -> Result<()> {
        validate_scopes(&self.scopes)?;
        if !self.scopes.iter().any(|allowed| allowed == scope) {
            return Err(McpError::Invalid(if scope == "reminders:write" {
                "手机未授权修改提醒事项".into()
            } else {
                "手机未授权读取此类内容".into()
            }));
        }
        Ok(())
    }
    pub fn is_trusted(&self) -> bool {
        self.trust_mode == "trusted" && self.refresh_token.is_some()
    }
}

pub fn legacy_scopes() -> Vec<String> {
    vec!["journals:read".into()]
}

pub fn validate_scopes(scopes: &[String]) -> Result<()> {
    let allowed = [
        "journals:read",
        "fragments:read",
        "reminders:read",
        "reminders:write",
    ];
    let unique: std::collections::HashSet<_> = scopes.iter().collect();
    if scopes.is_empty()
        || scopes.len() > allowed.len()
        || unique.len() != scopes.len()
        || scopes
            .iter()
            .any(|scope| !allowed.contains(&scope.as_str()))
    {
        return Err(McpError::Invalid("外部访问权限无效".into()));
    }
    Ok(())
}

pub fn save_trusted(session: &ExternalSession) -> Result<()> {
    validate_scopes(&session.scopes)?;
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
    validate_scopes(&session.scopes)?;
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

#[cfg(test)]
mod scope_tests {
    use super::*;

    #[test]
    fn missing_legacy_scope_field_never_expands_permission() {
        let value = serde_json::json!({
            "protocolVersion": 1, "baseUrl": "https://example.invalid",
            "grantId": "fixture", "trustMode": "temporary", "accessToken": "",
            "accessExpiresAt": 0, "refreshToken": null, "grantExpiresAt": 0,
            "dekKeyId": "fixture", "dekBase64": ""
        });
        let session: ExternalSession = serde_json::from_value(value.clone()).unwrap();
        assert!(session.require_scope("journals:read").is_ok());
        assert!(session.require_scope("fragments:read").is_err());
        assert!(session.require_scope("reminders:read").is_err());
        let mut malformed = value;
        malformed["scopes"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<ExternalSession>(malformed).is_err());
    }

    #[test]
    fn empty_duplicate_and_unknown_scopes_fail_closed() {
        for scopes in [
            vec![],
            vec!["unknown:read".into()],
            vec!["reminders:read".into(), "reminders:read".into()],
        ] {
            assert!(validate_scopes(&scopes).is_err());
        }
        assert!(validate_scopes(&["fragments:read".into(), "reminders:read".into()]).is_ok());
    }
}
