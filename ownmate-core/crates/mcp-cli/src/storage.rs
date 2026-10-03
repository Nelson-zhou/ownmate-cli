use crate::protocol::{ReminderCommandEnvelope, ReminderWriteContext};
use crate::{McpError, Result};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const KEYRING_SERVICE: &str = "space.ownmate.mcp-cli";
pub(crate) const LEGACY_ACCOUNT: &str = "default-external-client-v1";

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
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

impl std::fmt::Debug for ExternalSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalSession")
            .field("protocol_version", &self.protocol_version)
            .field("trust_mode", &self.trust_mode)
            .finish_non_exhaustive()
    }
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

pub(crate) fn validate_trusted(session: &ExternalSession) -> Result<()> {
    validate_scopes(&session.scopes)?;
    if !session.is_trusted()
        || session.protocol_version != 1
        || session.grant_id.is_empty()
        || session.access_token.is_empty()
        || session.refresh_token.as_deref().is_none_or(str::is_empty)
        || session.dek_key_id.is_empty()
        || session.dek_base64.is_empty()
    {
        return Err(McpError::Invalid("可信外部客户端凭据无效".into()));
    }
    crate::api::ExternalApiClient::new(&session.base_url)?;
    crate::reminders::decode_dek(session)?;
    if session.scopes.iter().any(|s| s == "reminders:write") {
        crate::reminders::validate_write_context(session)?;
    }
    Ok(())
}

pub(crate) trait CredentialStore {
    fn set(&self, account: &str, value: &str) -> Result<()>;
    fn get(&self, account: &str) -> Result<Option<Zeroizing<String>>>;
    fn delete(&self, account: &str) -> Result<()>;
}

pub(crate) struct NativeCredentials;

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
impl CredentialStore for NativeCredentials {
    fn set(&self, account: &str, value: &str) -> Result<()> {
        entry(account)?
            .set_password(value)
            .map_err(credential_error)
    }
    fn get(&self, account: &str) -> Result<Option<Zeroizing<String>>> {
        match entry(account)?.get_password() {
            Ok(value) => Ok(Some(Zeroizing::new(value))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(credential_error(error)),
        }
    }
    fn delete(&self, account: &str) -> Result<()> {
        match entry(account)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(credential_error(error)),
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
impl CredentialStore for NativeCredentials {
    fn set(&self, _: &str, _: &str) -> Result<()> {
        Err(unavailable())
    }
    fn get(&self, _: &str) -> Result<Option<Zeroizing<String>>> {
        Err(unavailable())
    }
    fn delete(&self, _: &str) -> Result<()> {
        Err(unavailable())
    }
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
fn credential_error(error: keyring::Error) -> McpError {
    // Provider error strings can contain item attributes, platform details or blobs.
    // Emit only a fixed category, including for ambiguous/encoding errors.
    McpError::Credential(
        match error {
            keyring::Error::NoStorageAccess(_) => "访问被系统拒绝；请在本机用户会话检查系统凭据库",
            keyring::Error::NoEntry => "未找到可信连接；请先配对",
            _ => "原生凭据操作失败；请在本机用户会话检查系统凭据库",
        }
        .into(),
    )
}

pub(crate) fn unavailable() -> McpError {
    McpError::Credential("未找到可用的可信连接；请先配对".into())
}

pub(crate) fn account_for(base_url: &str, grant_id: &str) -> String {
    format!(
        "grant-v1-{:x}",
        Sha256::digest(format!("{base_url}\n{grant_id}").as_bytes())
    )
}

pub(crate) fn read_session(store: &impl CredentialStore, account: &str) -> Result<ExternalSession> {
    let serialized = store.get(account)?.ok_or_else(unavailable)?;
    let session: ExternalSession = serde_json::from_str(&serialized)
        .map_err(|_| McpError::Credential("系统凭据库中的连接格式无效".into()))?;
    validate_trusted(&session)?;
    Ok(session)
}

pub(crate) fn save_verified(store: &impl CredentialStore, session: &ExternalSession) -> Result<()> {
    validate_trusted(session)?;
    let serialized = Zeroizing::new(serde_json::to_string(session)?);
    let account = account_for(&session.base_url, &session.grant_id);
    store.set(&account, &serialized)?;
    let readback = read_session(store, &account)?;
    let verified = Zeroizing::new(serde_json::to_string(&readback)?);
    if !constant_equal(serialized.as_bytes(), verified.as_bytes()) {
        return Err(McpError::Credential(
            "可信凭据读回校验失败；新连接尚未生效".into(),
        ));
    }
    Ok(())
}

pub fn load_trusted() -> Result<ExternalSession> {
    crate::profiles::load_trusted()
}

pub fn delete_trusted() -> Result<()> {
    crate::profiles::disconnect()
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
fn entry(account: &str) -> Result<keyring::Entry> {
    keyring::Entry::new(KEYRING_SERVICE, account).map_err(credential_error)
}

fn constant_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let difference = left
        .iter()
        .zip(right)
        .fold(0_u8, |acc, (a, b)| acc | std::hint::black_box(a ^ b));
    std::hint::black_box(difference) == 0
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialProbeReport {
    pub available: bool,
    pub cleanup_verified: bool,
    pub synthetic_only: bool,
    pub formal_save_guaranteed: bool,
}

pub fn credential_probe() -> CredentialProbeReport {
    probe_with(&NativeCredentials)
}

pub(crate) fn probe_with(store: &impl CredentialStore) -> CredentialProbeReport {
    let mut random = [0_u8; 32];
    OsRng.fill_bytes(&mut random);
    let account = format!("probe-v1-{:x}", Sha256::digest(random));
    OsRng.fill_bytes(&mut random);
    let value = Zeroizing::new(format!(
        "ownmate-synthetic-probe-{:x}",
        Sha256::digest(random)
    ));
    random.zeroize();
    let verified = (|| -> Result<bool> {
        store.set(&account, &value)?;
        Ok(store
            .get(&account)?
            .is_some_and(|v| constant_equal(v.as_bytes(), value.as_bytes())))
    })()
    .unwrap_or(false);
    // Delete even when set reports failure: native APIs may have partially completed.
    let cleanup_verified =
        store.delete(&account).is_ok() && matches!(store.get(&account), Ok(None));
    CredentialProbeReport {
        available: verified && cleanup_verified,
        cleanup_verified,
        synthetic_only: true,
        formal_save_guaranteed: false,
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;

    #[derive(Default)]
    pub struct MockCredentials {
        pub entries: RefCell<BTreeMap<String, String>>,
        pub calls: RefCell<Vec<String>>,
        pub deny_formal: Cell<bool>,
        pub deny_reads: Cell<bool>,
        pub mismatch: Cell<bool>,
        pub deny_delete: Cell<bool>,
        pub fail_probe_after_write: Cell<bool>,
        pub readback_patch: RefCell<Option<(&'static str, serde_json::Value)>>,
    }
    impl CredentialStore for MockCredentials {
        fn set(&self, account: &str, value: &str) -> Result<()> {
            self.calls.borrow_mut().push(format!("set:{account}"));
            if self.deny_formal.get() && !account.starts_with("probe-v1-") {
                return Err(McpError::Credential("synthetic denied".into()));
            }
            self.entries
                .borrow_mut()
                .insert(account.into(), value.into());
            if self.fail_probe_after_write.get() && account.starts_with("probe-v1-") {
                return Err(McpError::Credential(
                    "synthetic partial write failure".into(),
                ));
            }
            Ok(())
        }
        fn get(&self, account: &str) -> Result<Option<Zeroizing<String>>> {
            self.calls.borrow_mut().push(format!("get:{account}"));
            if self.deny_reads.get() {
                return Err(McpError::Credential("synthetic locked".into()));
            }
            let mut value = self.entries.borrow().get(account).cloned();
            if self.mismatch.get() && account.starts_with("grant-v1-") {
                let mut v: serde_json::Value =
                    serde_json::from_str(value.as_deref().unwrap()).unwrap();
                v["refreshToken"] = serde_json::json!("SYNTHETIC_DIFFERENT_REFRESH");
                value = Some(v.to_string());
            }
            if account.starts_with("grant-v1-")
                && let Some((field, patch)) = &*self.readback_patch.borrow()
            {
                let mut v: serde_json::Value =
                    serde_json::from_str(value.as_deref().unwrap()).unwrap();
                v[*field] = patch.clone();
                value = Some(v.to_string());
            }
            Ok(value.map(Zeroizing::new))
        }
        fn delete(&self, account: &str) -> Result<()> {
            self.calls.borrow_mut().push(format!("delete:{account}"));
            if self.deny_delete.get() {
                return Err(McpError::Credential("synthetic cleanup denied".into()));
            }
            self.entries.borrow_mut().remove(account);
            Ok(())
        }
    }

    pub fn trusted() -> ExternalSession {
        let mut session = crate::reminders::fixture_session();
        session.trust_mode = "trusted".into();
        session.refresh_token = Some("SYNTHETIC_REFRESH_NOT_LIVE".into());
        session.grant_expires_at = None;
        session
    }
}

#[cfg(test)]
mod credential_tests {
    use super::fixtures::*;
    use super::*;

    #[test]
    fn probe_is_isolated_and_cleans_up_on_success_or_read_failure() {
        let store = MockCredentials::default();
        store
            .entries
            .borrow_mut()
            .insert(LEGACY_ACCOUNT.into(), "SYNTHETIC_OLD_ITEM".into());
        let report = probe_with(&store);
        assert!(report.available && report.cleanup_verified && report.synthetic_only);
        assert!(!report.formal_save_guaranteed);
        assert_eq!(store.entries.borrow().len(), 1);
        assert!(
            store
                .calls
                .borrow()
                .iter()
                .all(|call| !call.contains(LEGACY_ACCOUNT))
        );
        store.calls.borrow_mut().clear();
        store.deny_reads.set(true);
        let report = probe_with(&store);
        assert!(!report.available);
        assert_eq!(store.entries.borrow().len(), 1);
        assert!(
            store
                .calls
                .borrow()
                .iter()
                .any(|call| call.starts_with("delete:probe-v1-"))
        );
    }

    #[test]
    fn probe_cleanup_denial_is_reported_without_item_values() {
        let store = MockCredentials::default();
        store.deny_delete.set(true);
        let report = probe_with(&store);
        assert!(!report.available && !report.cleanup_verified);
        let output = serde_json::to_string(&report).unwrap();
        assert!(!output.contains("probe-v1-") && !output.contains("synthetic-probe-"));
    }

    #[test]
    fn partial_probe_set_failure_still_deletes_the_isolated_item() {
        let store = MockCredentials::default();
        store.fail_probe_after_write.set(true);
        let report = probe_with(&store);
        assert!(!report.available && report.cleanup_verified);
        assert!(store.entries.borrow().is_empty());
    }

    #[test]
    fn successful_probe_does_not_guarantee_formal_save_and_never_replaces_legacy() {
        let store = MockCredentials::default();
        assert!(probe_with(&store).available);
        store
            .entries
            .borrow_mut()
            .insert(LEGACY_ACCOUNT.into(), "SYNTHETIC_OLD_ITEM".into());
        store.deny_formal.set(true);
        assert!(save_verified(&store, &trusted()).is_err());
        assert_eq!(
            store.entries.borrow().get(LEGACY_ACCOUNT).unwrap(),
            "SYNTHETIC_OLD_ITEM"
        );
    }

    #[test]
    fn readback_verifies_credentials_and_complete_immutable_session() {
        let store = MockCredentials::default();
        let session = trusted();
        save_verified(&store, &session).unwrap();
        store.mismatch.set(true);
        let error = save_verified(&store, &session).unwrap_err().to_string();
        assert!(!error.contains("SYNTHETIC_"));
        assert!(error.contains("读回校验失败"));
        let printed = format!("{session:?}");
        assert!(!printed.contains("SYNTHETIC_") && !printed.contains(&session.dek_base64));
        store.mismatch.set(false);
        for (field, value) in [
            ("grantId", serde_json::json!("SYNTHETIC_OTHER_GRANT")),
            (
                "baseUrl",
                serde_json::json!("https://synthetic.example.invalid"),
            ),
            ("accessToken", serde_json::json!("SYNTHETIC_OTHER_ACCESS")),
            ("accessExpiresAt", serde_json::json!(1)),
            ("refreshToken", serde_json::json!("SYNTHETIC_OTHER_REFRESH")),
            ("grantExpiresAt", serde_json::json!(1)),
            ("dekKeyId", serde_json::json!("SYNTHETIC_OTHER_KEY_ID")),
            (
                "dekBase64",
                serde_json::json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
            ),
            ("keyspaceId", serde_json::json!("SYNTHETIC_OTHER_SPACE")),
            ("keyspaceGeneration", serde_json::json!(4)),
            ("scopes", serde_json::json!(["journals:read"])),
            ("writeContext", serde_json::Value::Null),
        ] {
            *store.readback_patch.borrow_mut() = Some((field, value));
            assert!(save_verified(&store, &session).is_err(), "field {field}");
        }
    }

    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    #[test]
    fn native_error_details_are_never_displayed() {
        let error = credential_error(keyring::Error::Invalid(
            "PRIVATE_ATTRIBUTE".into(),
            "PRIVATE_CONTENT".into(),
        ));
        assert!(!error.to_string().contains("PRIVATE_"));
        let error = credential_error(keyring::Error::NoStorageAccess(Box::new(
            std::io::Error::other("PRIVATE_KEYCHAIN_PATH"),
        )));
        assert!(!error.to_string().contains("PRIVATE_"));
    }
}

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
