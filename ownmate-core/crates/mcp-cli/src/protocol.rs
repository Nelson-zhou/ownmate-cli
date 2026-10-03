use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiEnvelope<T> {
    pub ok: bool,
    pub data: Option<T>,
    pub message: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePairingRequest<'a> {
    pub client_name: &'a str,
    pub platform: &'a str,
    pub client_public_key: &'a str,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePairingResponse {
    pub protocol_version: u32,
    pub pairing_id: String,
    pub pairing_secret: String,
    pub verification_code: String,
    pub client_fingerprint: String,
    pub expires_at: u64,
    pub qr_payload: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExchangePairingRequest<'a> {
    pub pairing_id: &'a str,
    pub pairing_secret: &'a str,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExchangePairingResponse {
    pub protocol_version: u32,
    pub status: String,
    pub grant_id: Option<String>,
    pub client_name: Option<String>,
    pub trust_mode: Option<String>,
    pub scope: Option<String>,
    #[serde(default = "crate::storage::legacy_scopes")]
    pub scopes: Vec<String>,
    pub access_token: Option<String>,
    pub access_expires_at: Option<u64>,
    pub refresh_token: Option<String>,
    pub grant_expires_at: Option<u64>,
    pub key_envelope: Option<ExternalKeyEnvelope>,
    #[serde(default)]
    pub write_context: Option<ReminderWriteContext>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalKeyEnvelope {
    pub version: u32,
    pub keyspace_id: String,
    pub keyspace_generation: u64,
    pub algorithm: String,
    pub hkdf_info: String,
    pub salt: String,
    pub wrapped_dek: String,
    pub source_device_id: String,
    pub source_public_key: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WrappedDekField {
    pub version: u32,
    #[serde(rename = "type")]
    pub envelope_type: String,
    pub purpose: String,
    pub key_id: String,
    pub keyspace_id: String,
    pub keyspace_generation: u64,
    pub source_device_id: String,
    pub destination_device_id: String,
    pub source_key_fingerprint: String,
    pub destination_key_fingerprint: String,
    pub trust_mode: String,
    pub expires_at: u64,
    pub ciphertext: String,
    pub nonce: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshRequest<'a> {
    pub refresh_token: &'a str,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshResponse {
    pub protocol_version: u32,
    pub access_token: String,
    pub access_expires_at: u64,
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    #[serde(default)]
    pub write_context: Option<ReminderWriteContext>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReminderWriteContext {
    #[serde(default)]
    pub capability_version: u32,
    pub keyspace_id: String,
    pub keyspace_generation: u64,
    pub target_device_id: String,
    pub actions: Vec<String>,
    pub policy: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReminderCommandEnvelope {
    pub protocol_version: u32,
    pub request_id: String,
    pub operation: String,
    pub grant_id: String,
    pub keyspace_id: String,
    pub keyspace_generation: u64,
    pub target_device_id: String,
    pub target_reminder_id: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub key_id: String,
    pub algorithm: String,
    pub encryption_version: u32,
    pub nonce: String,
    pub ciphertext: String,
}

// Decode into this projection rather than forwarding arbitrary server fields to a write-only
// caller. A receipt carries no reminder title, notes, history or current conflicting version.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReminderCommandReceipt {
    pub protocol_version: u32,
    pub command_id: String,
    pub request_id: String,
    pub target_reminder_id: String,
    pub operation: String,
    pub status: String,
    pub expires_at: u64,
    pub operation_status: Option<String>,
    pub result_version: Option<String>,
    pub applied_at: Option<u64>,
    pub rejection_code: Option<String>,
    pub notification_status: String,
    pub sync_visibility: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpaqueJournal {
    pub entry_id: String,
    pub key_id: String,
    pub ciphertext: String,
    pub nonce: String,
    pub algorithm: String,
    pub encryption_version: u32,
    pub revision: u64,
    pub journal_schema_version: u32,
    pub server_updated_at: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JournalPage {
    pub protocol_version: u32,
    pub items: Vec<OpaqueJournal>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JournalItemResponse {
    pub protocol_version: u32,
    pub item: OpaqueJournal,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncJournalPayload {
    pub payload_version: u32,
    pub record_state: Option<String>,
    pub canonical_journal_json: String,
    pub title: String,
    pub plain_text: String,
    pub lifecycle: JournalLifecycle,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JournalLifecycle {
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct McpJournalV1 {
    pub version: u32,
    pub entry_id: String,
    pub occurred_at: String,
    pub timezone: String,
    pub title: String,
    pub text: String,
    pub tags: Vec<String>,
    pub mood: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_of_mind: Option<McpStateOfMindV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct McpStateOfMindV1 {
    pub entry_type: String,
    pub score: i32,
    pub descriptors: Vec<String>,
    pub factors: Vec<String>,
    pub additional_context: Option<String>,
    pub logged_at: String,
}

#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: Option<String>,
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}
