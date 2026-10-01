use crate::protocol::{
    ApiEnvelope, CreatePairingRequest, CreatePairingResponse, ExchangePairingRequest,
    ExchangePairingResponse, JournalItemResponse, JournalPage, OpaqueJournal, RefreshRequest,
    RefreshResponse,
};
use crate::storage::{ExternalSession, save_trusted};
use crate::{McpError, Result};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

pub struct ExternalApiClient {
    base_url: String,
    agent: ureq::Agent,
}

impl ExternalApiClient {
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
    ) -> Result<CreatePairingResponse> {
        self.post_public(
            "/external-access/v1/pairings",
            &CreatePairingRequest {
                client_name,
                platform: std::env::consts::OS,
                client_public_key: public_key,
            },
        )
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
    }

    pub fn list_journals(&self, session: &mut ExternalSession) -> Result<Vec<OpaqueJournal>> {
        let mut cursor: Option<String> = None;
        let mut items = Vec::new();
        loop {
            let path = match &cursor {
                Some(value) => format!(
                    "/external-access/v1/journals?limit=200&cursor={}",
                    percent_encode(value),
                ),
                None => "/external-access/v1/journals?limit=200".into(),
            };
            let page: JournalPage = self.get_authorized(session, &path)?;
            if page.protocol_version != 1 {
                return Err(McpError::Invalid("只读日记协议版本不兼容".into()));
            }
            items.extend(page.items);
            if !page.has_more {
                return Ok(items);
            }
            let next = page
                .next_cursor
                .filter(|next| Some(next) != cursor.as_ref())
                .ok_or_else(|| McpError::Invalid("只读日记游标没有前进".into()))?;
            cursor = Some(next);
        }
    }

    pub fn get_journal(
        &self,
        session: &mut ExternalSession,
        entry_id: &str,
    ) -> Result<OpaqueJournal> {
        if entry_id.is_empty()
            || entry_id.len() > 160
            || entry_id.chars().any(|c| c == '/' || c.is_control())
        {
            return Err(McpError::Invalid("entryId 无效".into()));
        }
        let response: JournalItemResponse = self.get_authorized(
            session,
            &format!("/external-access/v1/journals/{}", percent_encode(entry_id)),
        )?;
        if response.protocol_version != 1 {
            return Err(McpError::Invalid("只读日记协议版本不兼容".into()));
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
            return decode_envelope(first.0, &first.1);
        }
        self.refresh(session)?;
        let retry = self.authorized_get(path, &session.access_token)?;
        decode_envelope(retry.0, &retry.1)
    }

    fn ensure_access(&self, session: &mut ExternalSession) -> Result<()> {
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
        session.access_token = refreshed.access_token;
        session.access_expires_at = refreshed.access_expires_at;
        if session.is_trusted() {
            save_trusted(session)?;
        }
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
        let text = response
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE_BYTES)
            .read_to_string()
            .map_err(|error| McpError::Network(error.to_string()))?;
        decode_envelope(status, &text)
    }

    fn authorized_get(&self, path: &str, access_token: &str) -> Result<(u16, String)> {
        let mut response = self
            .agent
            .get(format!("{}{}", self.base_url, path))
            .header("Accept", "application/json")
            .header("Authorization", format!("Bearer {access_token}"))
            .call()
            .map_err(|error| McpError::Network(error.to_string()))?;
        let status = response.status().as_u16();
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE_BYTES)
            .read_to_string()
            .map_err(|error| McpError::Network(error.to_string()))?;
        Ok((status, body))
    }
}

fn decode_envelope<T: DeserializeOwned>(status: u16, body: &str) -> Result<T> {
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
}
