use crate::protocol::{
    ApiEnvelope, ClientReadyRequest, ClientReadyResponse, CreatePairingRequest,
    CreatePairingResponse, ExchangePairingRequest, ExchangePairingResponse, JournalItemResponse,
    JournalPage, OpaqueJournal, RefreshRequest, RefreshResponse, ReminderCommandEnvelope,
    ReminderCommandReceipt,
};
use crate::storage::ExternalSession;
use crate::{McpError, Result};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadResource {
    Journal,
    Fragment,
    Reminder,
    ReminderCompletion,
}

impl ReadResource {
    pub fn scope(self) -> &'static str {
        match self {
            Self::Journal => "journals:read",
            Self::Fragment => "fragments:read",
            Self::Reminder | Self::ReminderCompletion => "reminders:read",
        }
    }

    pub fn path(self) -> &'static str {
        match self {
            Self::Journal => "journals",
            Self::Fragment => "fragments",
            Self::Reminder => "reminders",
            Self::ReminderCompletion => "reminder-completions",
        }
    }
}

pub struct ExternalApiClient {
    base_url: String,
    agent: ureq::Agent,
}

impl ExternalApiClient {
    pub fn submit_reminder_command(
        &self,
        session: &mut ExternalSession,
        command: &ReminderCommandEnvelope,
    ) -> Result<ReminderCommandReceipt> {
        session.require_scope("reminders:write")?;
        self.ensure_access(session)?;
        let first = self.authorized_post(
            "/external-access/v1/reminder-commands",
            &session.access_token,
            command,
        )?;
        if first.0 != 401 {
            return decode_response(first);
        }
        self.refresh(session)?;
        session.require_scope("reminders:write")?;
        decode_response(self.authorized_post(
            "/external-access/v1/reminder-commands",
            &session.access_token,
            command,
        )?)
    }

    pub fn reminder_request_status(
        &self,
        session: &mut ExternalSession,
        request_id: &str,
    ) -> Result<ReminderCommandReceipt> {
        session.require_scope("reminders:write")?;
        self.get_authorized(
            session,
            &format!(
                "/external-access/v1/reminder-commands/{}",
                percent_encode(request_id)
            ),
        )
    }
    pub fn new(base_url: &str) -> Result<Self> {
        let normalized = base_url.trim().trim_end_matches('/').to_string();
        let local = normalized.starts_with("http://127.0.0.1:")
            || normalized.starts_with("http://localhost:");
        if normalized.is_empty() || (!normalized.starts_with("https://") && !local) {
            return Err(McpError::Invalid(
                "API 地址必须使用 HTTPS（本机开发地址除外）".into(),
            ));
        }
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(20)))
            .http_status_as_error(false)
            .build();
        Ok(Self {
            base_url: normalized,
            agent: config.into(),
        })
    }

    pub fn create_pairing(
        &self,
        client_name: &str,
        public_key: &str,
        supported_trust_modes: &[String],
    ) -> Result<CreatePairingResponse> {
        self.post_public(
            "/external-access/v1/pairings",
            &CreatePairingRequest {
                client_name,
                platform: std::env::consts::OS,
                client_public_key: public_key,
                client_ready_version: 1,
                supported_trust_modes,
            },
        )
        .map_err(connection_error)
    }

    pub fn client_ready(&self, session: &mut ExternalSession, deadline: u64) -> Result<()> {
        let request = ClientReadyRequest {
            protocol_version: 1,
            client_ready_version: 1,
        };
        let first = self
            .authorized_post(
                "/external-access/v1/client/ready",
                &session.access_token,
                &request,
            )
            .map_err(connection_error)?;
        let result = if first.0 == 401 && session.is_trusted() {
            // A prior ready may have succeeded with its reply lost. Only an ACTIVE
            // grant can refresh server-side; awaiting/expired grants remain closed.
            // This also handles another process rotating the short access-token hash.
            self.refresh(session).map_err(connection_error)?;
            self.authorized_post(
                "/external-access/v1/client/ready",
                &session.access_token,
                &request,
            )
            .map_err(connection_error)?
        } else {
            first
        };
        let response: ClientReadyResponse = decode_response(result).map_err(connection_error)?;
        validate_client_ready(&response, session, deadline)
    }

    pub fn exchange_pairing(
        &self,
        pairing_id: &str,
        pairing_secret: &str,
    ) -> Result<ExchangePairingResponse> {
        self.post_public(
            "/external-access/v1/pairings/exchange",
            &ExchangePairingRequest {
                pairing_id,
                pairing_secret,
            },
        )
        .map_err(connection_error)
    }

    pub fn list_journals(&self, session: &mut ExternalSession) -> Result<Vec<OpaqueJournal>> {
        self.list_resources(session, ReadResource::Journal)
    }

    pub fn list_resources(
        &self,
        session: &mut ExternalSession,
        kind: ReadResource,
    ) -> Result<Vec<OpaqueJournal>> {
        session.require_scope(kind.scope())?;
        let mut cursor: Option<String> = None;
        let mut items = Vec::new();
        let mut seen_cursors = std::collections::HashSet::new();
        let mut seen_ids = std::collections::HashSet::new();
        loop {
            let path = match &cursor {
                Some(value) => format!(
                    "/external-access/v1/{}?limit=200&cursor={}",
                    kind.path(),
                    percent_encode(value),
                ),
                None => format!("/external-access/v1/{}?limit=200", kind.path()),
            };
            let page: JournalPage = self.get_authorized(session, &path)?;
            if page.protocol_version != 1 {
                return Err(McpError::Invalid("只读日记协议版本不兼容".into()));
            }
            for item in page.items {
                validate_list_identity(&item.entry_id, &mut seen_ids)?;
                items.push(item);
            }
            if !page.has_more {
                return Ok(items);
            }
            let next = page
                .next_cursor
                .ok_or_else(|| McpError::Invalid("只读日记游标没有前进".into()))?;
            validate_next_cursor(&next, &mut seen_cursors)?;
            cursor = Some(next);
        }
    }

    pub fn get_journal(
        &self,
        session: &mut ExternalSession,
        entry_id: &str,
    ) -> Result<OpaqueJournal> {
        self.get_resource(session, ReadResource::Journal, entry_id)
    }

    pub fn get_resource(
        &self,
        session: &mut ExternalSession,
        kind: ReadResource,
        entry_id: &str,
    ) -> Result<OpaqueJournal> {
        session.require_scope(kind.scope())?;
        if entry_id.is_empty()
            || entry_id.len() > 160
            || entry_id.chars().any(|c| c == '/' || c.is_control())
        {
            return Err(McpError::Invalid("entryId 无效".into()));
        }
        let response: JournalItemResponse = self.get_authorized(
            session,
            &format!(
                "/external-access/v1/{}/{}",
                kind.path(),
                percent_encode(entry_id)
            ),
        )?;
        if response.protocol_version != 1 {
            return Err(McpError::Invalid("只读日记协议版本不兼容".into()));
        }
        if response.item.entry_id != entry_id {
            return Err(McpError::Invalid("只读资源响应身份不匹配".into()));
        }
        Ok(response.item)
    }

    fn get_authorized<T: DeserializeOwned>(
        &self,
        session: &mut ExternalSession,
        path: &str,
    ) -> Result<T> {
        self.ensure_access(session)?;
        let first = self.authorized_get(path, &session.access_token)?;
        if first.0 != 401 {
            return decode_response(first);
        }
        self.refresh(session)?;
        let retry = self.authorized_get(path, &session.access_token)?;
        decode_response(retry)
    }

    fn ensure_access(&self, session: &mut ExternalSession) -> Result<()> {
        if session
            .grant_expires_at
            .is_some_and(|expiry| expiry <= now_millis())
        {
            return Err(McpError::Api("临时授权已到期，请重新扫码".into()));
        }
        if session.access_expires_at > now_millis().saturating_add(30_000) {
            return Ok(());
        }
        self.refresh(session)
    }

    fn refresh(&self, session: &mut ExternalSession) -> Result<()> {
        let refresh_token = session
            .refresh_token
            .as_deref()
            .ok_or_else(|| McpError::Api("30 分钟临时授权已到期，请重新扫码".into()))?;
        let refreshed: RefreshResponse = self.post_public(
            "/external-access/v1/token/refresh",
            &RefreshRequest { refresh_token },
        )?;
        if refreshed.protocol_version != 1 {
            return Err(McpError::Invalid("外部访问令牌协议版本不兼容".into()));
        }
        if let Some(scopes) = &refreshed.scopes {
            crate::storage::validate_scopes(scopes)?;
            let old: std::collections::HashSet<_> = session.scopes.iter().collect();
            let new: std::collections::HashSet<_> = scopes.iter().collect();
            if old != new {
                return Err(McpError::Invalid("刷新令牌不得改变原授权范围".into()));
            }
        }
        if let Some(context) = &refreshed.write_context {
            if session.write_context.as_ref() != Some(context) {
                return Err(McpError::Invalid("刷新令牌不得改变原写授权身份".into()));
            }
        } else if session.scopes.iter().any(|s| s == "reminders:write") {
            return Err(McpError::Invalid("刷新响应缺少原写授权身份".into()));
        }
        session.access_token = refreshed.access_token;
        session.access_expires_at = refreshed.access_expires_at;
        // Refresh token is stable. Ephemeral access tokens stay in each process, avoiding
        // Keychain prompts and concurrent CLI/MCP writers overwriting a verified grant.
        Ok(())
    }

    fn post_public<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> Result<T> {
        let mut response = self
            .agent
            .post(format!("{}{}", self.base_url, path))
            .header("Accept", "application/json")
            .send_json(body)
            .map_err(|error| McpError::Network(error.to_string()))?;
        let status = response.status().as_u16();
        let retry_after = retry_after_header(&response);
        let text = response
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE_BYTES)
            .read_to_string()
            .map_err(|error| McpError::Network(error.to_string()))?;
        decode_response((status, text, retry_after))
    }

    fn authorized_get(&self, path: &str, access_token: &str) -> Result<(u16, String, Option<u64>)> {
        let mut response = self
            .agent
            .get(format!("{}{}", self.base_url, path))
            .header("Accept", "application/json")
            .header("Authorization", format!("Bearer {access_token}"))
            .call()
            .map_err(|error| McpError::Network(error.to_string()))?;
        let status = response.status().as_u16();
        let retry_after = retry_after_header(&response);
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE_BYTES)
            .read_to_string()
            .map_err(|error| McpError::Network(error.to_string()))?;
        Ok((status, body, retry_after))
    }

    fn authorized_post<B: Serialize>(
        &self,
        path: &str,
        access_token: &str,
        body: &B,
    ) -> Result<(u16, String, Option<u64>)> {
        let mut response = self
            .agent
            .post(format!("{}{}", self.base_url, path))
            .header("Accept", "application/json")
            .header("Authorization", format!("Bearer {access_token}"))
            .send_json(body)
            .map_err(|error| McpError::Network(error.to_string()))?;
        let status = response.status().as_u16();
        let retry_after = retry_after_header(&response);
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE_BYTES)
            .read_to_string()
            .map_err(|error| McpError::Network(error.to_string()))?;
        Ok((status, body, retry_after))
    }
}

pub(crate) fn validate_client_ready(
    response: &ClientReadyResponse,
    session: &ExternalSession,
    deadline: u64,
) -> Result<()> {
    if response.protocol_version != 1
        || response.client_ready_version != 1
        || response.grant_id != session.grant_id
        || response.status != "active"
        || response.client_ready_expires_at != deadline
        || response.client_ready_at == 0
        || response.client_ready_at >= deadline
    {
        return Err(McpError::Invalid(
            "客户端 ready 确认响应无效；新连接尚未生效".into(),
        ));
    }
    Ok(())
}

fn connection_error(error: McpError) -> McpError {
    match error {
        McpError::Json(_) => McpError::Invalid("连接协议响应格式无效".into()),
        McpError::Network(_) => McpError::Network("连接请求未完成；未输出请求或凭据内容".into()),
        McpError::ApiResponse { status, code, .. } => McpError::ApiResponse {
            status,
            code,
            message: "客户端连接请求未获批准".into(),
        },
        McpError::Api(_) => McpError::Api("客户端连接请求未获批准".into()),
        other => other,
    }
}

fn retry_after_header(response: &ureq::http::Response<ureq::Body>) -> Option<u64> {
    response
        .headers()
        .get("Retry-After")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
}

fn decode_response<T: DeserializeOwned>(
    (status, body, retry_after): (u16, String, Option<u64>),
) -> Result<T> {
    if status == 429 {
        let value: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
        return Err(McpError::RateLimited {
            retry_after_seconds: retry_after
                .or_else(|| value["retryAfter"].as_u64())
                .or_else(|| value["data"]["retryAfter"].as_u64())
                .or_else(|| value["retryAfterSeconds"].as_u64())
                .or_else(|| value["data"]["retryAfterSeconds"].as_u64())
                .unwrap_or(60)
                .max(1),
        });
    }
    decode_envelope(status, &body)
}

fn validate_list_identity(id: &str, seen: &mut std::collections::HashSet<String>) -> Result<()> {
    if id.is_empty()
        || id.len() > 160
        || id.chars().any(|c| c == '/' || c.is_control())
        || !seen.insert(id.to_owned())
    {
        return Err(McpError::Invalid(
            "只读列表资源身份无效或重复，请重新读取".into(),
        ));
    }
    Ok(())
}

fn validate_next_cursor(next: &str, seen: &mut std::collections::HashSet<String>) -> Result<()> {
    if next.is_empty() || next.len() > 1024 || !seen.insert(next.to_owned()) {
        return Err(McpError::Invalid("只读记录分页游标无效或循环".into()));
    }
    Ok(())
}

fn decode_envelope<T: DeserializeOwned>(status: u16, body: &str) -> Result<T> {
    if !(200..300).contains(&status) {
        let value: serde_json::Value = serde_json::from_str(body)?;
        let code = value["data"]["code"]
            .as_str()
            .filter(|s| s.len() <= 80 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
            .unwrap_or("API_REJECTED");
        return Err(McpError::ApiResponse {
            status,
            code: code.into(),
            message: value["message"].as_str().unwrap_or("请求未获批准").into(),
        });
    }
    let envelope: ApiEnvelope<T> = serde_json::from_str(body)?;
    if !(200..300).contains(&status) || !envelope.ok {
        return Err(McpError::Api(
            envelope.message.unwrap_or_else(|| format!("HTTP {status}")),
        ));
    }
    envelope
        .data
        .ok_or_else(|| McpError::Invalid("OwnMate API 响应缺少 data".into()))
}

pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_ready_server(
        refresh_allowed: bool,
    ) -> (ExternalApiClient, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = std::thread::spawn(move || {
            for index in 0..if refresh_allowed { 3 } else { 2 } {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut bytes = Vec::new();
                let offset = loop {
                    let mut chunk = [0; 1024];
                    let count = stream.read(&mut chunk).unwrap();
                    assert!(count > 0);
                    bytes.extend_from_slice(&chunk[..count]);
                    if let Some(offset) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                        let header = String::from_utf8_lossy(&bytes[..offset]);
                        let size = header
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .and_then(|v| v.trim().parse::<usize>().ok())
                            })
                            .unwrap();
                        if bytes.len() >= offset + 4 + size {
                            break offset;
                        }
                    }
                };
                let header = String::from_utf8_lossy(&bytes[..offset]);
                let request: serde_json::Value =
                    serde_json::from_slice(&bytes[offset + 4..]).unwrap();
                let (status, response) = if index == 1 {
                    assert!(header.starts_with("POST /external-access/v1/token/refresh "));
                    assert_eq!(
                        request,
                        serde_json::json!({"refreshToken":"SYNTHETIC_REFRESH_NOT_LIVE"})
                    );
                    if refresh_allowed {
                        (
                            200,
                            serde_json::json!({"ok":true,"data":{"protocolVersion":1,
                        "accessToken":"SYNTHETIC_REFRESHED_ACCESS","accessExpiresAt":u64::MAX,"scopes":["journals:read"]}}),
                        )
                    } else {
                        (
                            401,
                            serde_json::json!({"ok":false,"message":"PRIVATE_AWAITING_DETAILS","data":{"code":"EXTERNAL_CLIENT_NOT_READY"}}),
                        )
                    }
                } else {
                    assert!(header.starts_with("POST /external-access/v1/client/ready "));
                    assert_eq!(
                        request,
                        serde_json::json!({"protocolVersion":1,"clientReadyVersion":1})
                    );
                    if index == 0 {
                        (
                            401,
                            serde_json::json!({"ok":false,"message":"PRIVATE_TOKEN_DETAILS","data":{"code":"EXTERNAL_ACCESS_EXPIRED"}}),
                        )
                    } else {
                        assert!(header.contains("Bearer SYNTHETIC_REFRESHED_ACCESS"));
                        (
                            200,
                            serde_json::json!({"ok":true,"data":{"protocolVersion":1,"clientReadyVersion":1,
                            "grantId":"fixture_grant","status":"active","clientReadyExpiresAt":100,"clientReadyAt":50}}),
                        )
                    }
                };
                let body = response.to_string();
                write!(stream, "HTTP/1.1 {status} Synthetic\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        (ExternalApiClient::new(&base).unwrap(), task)
    }

    #[test]
    fn ready_lost_reply_recovers_expired_or_rotated_access_with_active_only_memory_refresh() {
        let (api, task) = fake_ready_server(true);
        let mut session = crate::storage::fixtures::trusted();
        session.scopes = vec!["journals:read".into()];
        session.write_context = None;
        api.client_ready(&mut session, 100).unwrap();
        assert_eq!(session.access_token, "SYNTHETIC_REFRESHED_ACCESS");
        assert_eq!(
            session.refresh_token.as_deref(),
            Some("SYNTHETIC_REFRESH_NOT_LIVE")
        );
        task.join().unwrap();
    }

    #[test]
    fn ready_401_cannot_refresh_or_activate_an_awaiting_grant() {
        let (api, task) = fake_ready_server(false);
        let mut session = crate::storage::fixtures::trusted();
        let original = serde_json::to_string(&session).unwrap();
        let error = api.client_ready(&mut session, 100).unwrap_err();
        assert!(!error.to_string().contains("PRIVATE_"));
        assert_eq!(serde_json::to_string(&session).unwrap(), original);
        task.join().unwrap();
    }

    #[test]
    fn ready_validates_identity_and_original_deadline_even_for_idempotent_late_reply() {
        assert_eq!(
            serde_json::to_value(ClientReadyRequest {
                protocol_version: 1,
                client_ready_version: 1
            })
            .unwrap(),
            serde_json::json!({"protocolVersion":1,"clientReadyVersion":1})
        );
        let session = crate::storage::fixtures::trusted();
        let mut response = ClientReadyResponse {
            protocol_version: 1,
            client_ready_version: 1,
            grant_id: session.grant_id.clone(),
            status: "active".into(),
            client_ready_expires_at: 100,
            client_ready_at: 50,
        };
        assert!(validate_client_ready(&response, &session, 100).is_ok());
        response.client_ready_expires_at = 200;
        assert!(validate_client_ready(&response, &session, 100).is_err());
        response.client_ready_expires_at = 100;
        response.client_ready_at = 101;
        assert!(validate_client_ready(&response, &session, 100).is_err());
        response.client_ready_at = 50;
        response.grant_id = "other_synthetic_grant".into();
        assert!(validate_client_ready(&response, &session, 100).is_err());
    }

    #[test]
    fn connection_errors_do_not_echo_response_private_values() {
        let error = connection_error(McpError::ApiResponse {
            status: 400,
            code: "BAD_READY".into(),
            message: "PRIVATE_TOKEN_VALUE".into(),
        });
        assert!(!error.to_string().contains("PRIVATE_"));
        let malformed =
            serde_json::from_str::<ClientReadyResponse>(r#"{"protocolVersion":"PRIVATE_VALUE"}"#)
                .unwrap_err();
        assert!(
            !connection_error(McpError::Json(malformed))
                .to_string()
                .contains("PRIVATE_")
        );
    }

    #[test]
    fn refresh_uses_stable_refresh_token_without_writing_keychain_or_expanding_scope() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let scopes = vec!["journals:read".to_string()];
        let task = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut bytes = Vec::new();
            loop {
                let mut chunk = [0; 1024];
                let count = stream.read(&mut chunk).unwrap();
                bytes.extend_from_slice(&chunk[..count]);
                if let Some(offset) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                    let header = String::from_utf8_lossy(&bytes[..offset]);
                    let size = header
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .and_then(|v| v.trim().parse::<usize>().ok())
                        })
                        .unwrap();
                    if bytes.len() >= offset + 4 + size {
                        break;
                    }
                }
            }
            let offset = bytes.windows(4).position(|v| v == b"\r\n\r\n").unwrap();
            assert!(
                String::from_utf8_lossy(&bytes[..offset])
                    .starts_with("POST /external-access/v1/token/refresh ")
            );
            let request: serde_json::Value = serde_json::from_slice(&bytes[offset + 4..]).unwrap();
            assert_eq!(
                request,
                serde_json::json!({"refreshToken":"SYNTHETIC_REFRESH_NOT_LIVE"})
            );
            let body = serde_json::json!({"ok":true,"data":{"protocolVersion":1,"accessToken":"SYNTHETIC_NEW_ACCESS","accessExpiresAt":u64::MAX,"scopes":scopes}}).to_string();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        let mut session = crate::storage::fixtures::trusted();
        session.scopes = vec!["journals:read".into()];
        session.write_context = None;
        session.base_url = base.clone();
        session.access_expires_at = 0;
        ExternalApiClient::new(&base)
            .unwrap()
            .refresh(&mut session)
            .unwrap();
        assert_eq!(
            session.refresh_token.as_deref(),
            Some("SYNTHETIC_REFRESH_NOT_LIVE")
        );
        assert_eq!(session.access_token, "SYNTHETIC_NEW_ACCESS");
        task.join().unwrap();
        // This test requires no native entry, even when running without a desktop keyring.
    }

    #[test]
    fn pagination_rejects_duplicate_and_invalid_resource_identity() {
        let mut seen = std::collections::HashSet::new();
        assert!(validate_list_identity("record-a", &mut seen).is_ok());
        assert!(validate_list_identity("record-b", &mut seen).is_ok());
        assert!(validate_list_identity("record-a", &mut seen).is_err());
        for id in ["", "a/b", "a\n", &"a".repeat(161)] {
            assert!(validate_list_identity(id, &mut seen).is_err());
        }
    }

    #[test]
    fn non_authorized_resource_requests_fail_before_network() {
        let api = ExternalApiClient::new("http://127.0.0.1:1").unwrap();
        let mut session = ExternalSession {
            protocol_version: 1,
            base_url: "http://127.0.0.1:1".into(),
            grant_id: "fixture".into(),
            trust_mode: "temporary".into(),
            access_token: String::new(),
            access_expires_at: 0,
            refresh_token: None,
            grant_expires_at: Some(0),
            dek_key_id: "fixture".into(),
            dek_base64: String::new(),
            scopes: vec!["reminders:read".into()],
            keyspace_id: None,
            keyspace_generation: None,
            write_context: None,
            temporary_commands: Vec::new(),
        };
        for kind in [ReadResource::Journal, ReadResource::Fragment] {
            let error = api.list_resources(&mut session, kind).unwrap_err();
            assert_eq!(error.to_string(), "手机未授权读取此类内容");
        }
        assert_eq!(ReadResource::ReminderCompletion.scope(), "reminders:read");
    }

    #[test]
    fn only_https_or_loopback_http_is_accepted() {
        assert!(ExternalApiClient::new("https://api.ownmate.space").is_ok());
        assert!(ExternalApiClient::new("http://127.0.0.1:3000").is_ok());
        assert!(ExternalApiClient::new("http://example.com").is_err());
    }

    #[test]
    fn percent_encoding_never_injects_query_or_path_segments() {
        assert_eq!(percent_encode("a/b?c=d"), "a%2Fb%3Fc%3Dd");
    }

    #[test]
    fn pagination_rejects_empty_oversized_and_cyclic_cursors() {
        let mut seen = std::collections::HashSet::new();
        assert!(validate_next_cursor("", &mut seen).is_err());
        assert!(validate_next_cursor(&"x".repeat(1025), &mut seen).is_err());
        assert!(validate_next_cursor("a", &mut seen).is_ok());
        assert!(validate_next_cursor("b", &mut seen).is_ok());
        assert!(validate_next_cursor("a", &mut seen).is_err());
    }
}
