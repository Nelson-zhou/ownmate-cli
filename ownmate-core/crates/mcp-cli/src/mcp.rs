use crate::api::ExternalApiClient;
use crate::crypto::decrypt_mcp_journal;
use crate::protocol::JsonRpcRequest;
use crate::storage::ExternalSession;
use crate::{McpError, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use std::io::{BufRead, Write};
use zeroize::Zeroizing;

const MAX_REQUEST_LINE_BYTES: usize = 1024 * 1024;

pub fn serve_stdio(session: &mut ExternalSession) -> Result<()> {
    let decoded = STANDARD
        .decode(&session.dek_base64)
        .map_err(|_| McpError::Invalid("系统凭据库中的 DEK 无效".into()))?;
    if decoded.len() != 32 || STANDARD.encode(&decoded) != session.dek_base64 {
        return Err(McpError::Invalid("系统凭据库中的 DEK 无效".into()));
    }
    let dek = Zeroizing::new(decoded);
    let api = ExternalApiClient::new(&session.base_url)?;
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.len() > MAX_REQUEST_LINE_BYTES {
            write_response(
                &mut stdout,
                json_rpc_error(Value::Null, -32600, "JSON-RPC 请求超限"),
            )?;
            continue;
        }
        let request: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(request) => request,
            Err(_) => {
                write_response(
                    &mut stdout,
                    json_rpc_error(Value::Null, -32700, "JSON-RPC 解析失败"),
                )?;
                continue;
            }
        };
        if request.id.is_none() {
            // MCP notifications do not receive JSON-RPC responses.
            continue;
        }
        let id = request.id.clone().unwrap_or(Value::Null);
        let response = match dispatch(&api, session, &dek, request) {
            Ok(value) => json!({"jsonrpc":"2.0","id":id,"result":value}),
            Err(DispatchError::MethodNotFound) => json_rpc_error(id, -32601, "Method not found"),
            Err(DispatchError::InvalidParams(message)) => json_rpc_error(id, -32602, &message),
            Err(DispatchError::Internal(error)) => json_rpc_error(id, -32000, &error.to_string()),
        };
        write_response(&mut stdout, response)?;
    }
    Ok(())
}

enum DispatchError {
    MethodNotFound,
    InvalidParams(String),
    Internal(McpError),
}

impl From<McpError> for DispatchError {
    fn from(value: McpError) -> Self {
        Self::Internal(value)
    }
}

fn dispatch(
    api: &ExternalApiClient,
    session: &mut ExternalSession,
    dek: &[u8],
    request: JsonRpcRequest,
) -> std::result::Result<Value, DispatchError> {
    if request.jsonrpc.as_deref() != Some("2.0") {
        return Err(DispatchError::InvalidParams("jsonrpc 必须为 2.0".into()));
    }
    match request.method.as_str() {
        "initialize" => Ok(json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {
                "resources": {"subscribe": false, "listChanged": false}
            },
            "serverInfo": {"name": "ownmate-mcp", "version": env!("CARGO_PKG_VERSION")}
        })),
        "ping" => Ok(json!({})),
        "resources/list" => {
            let resources = api
                .list_journals(session)?
                .into_iter()
                .filter_map(|item| {
                    let journal = decrypt_mcp_journal(&item, &session.dek_key_id, dek).ok()?;
                    Some(json!({
                        "uri": resource_uri(&journal.entry_id),
                        "name": if journal.title.trim().is_empty() { journal.occurred_at.clone() } else { journal.title.clone() },
                        "description": format!("OwnMate 已保存文字日记 · {}", journal.occurred_at),
                        "mimeType": "application/json"
                    }))
                })
                .collect::<Vec<_>>();
            Ok(json!({"resources": resources}))
        }
        "resources/read" => {
            let uri = request
                .params
                .get("uri")
                .and_then(Value::as_str)
                .ok_or_else(|| DispatchError::InvalidParams("缺少 resource uri".into()))?;
            let entry_id = parse_resource_uri(uri)
                .ok_or_else(|| DispatchError::InvalidParams("OwnMate resource uri 无效".into()))?;
            let item = api.get_journal(session, &entry_id)?;
            let journal = decrypt_mcp_journal(&item, &session.dek_key_id, dek)?;
            let text = serde_json::to_string(&journal).map_err(McpError::from)?;
            Ok(json!({
                "contents": [{"uri": uri, "mimeType": "application/json", "text": text}]
            }))
        }
        // v1 intentionally exposes no tools, prompts, subscriptions, or write methods.
        _ => Err(DispatchError::MethodNotFound),
    }
}

fn resource_uri(entry_id: &str) -> String {
    format!("ownmate://journal/{}", percent_encode(entry_id))
}

fn parse_resource_uri(uri: &str) -> Option<String> {
    let encoded = uri.strip_prefix("ownmate://journal/")?;
    if encoded.is_empty() || encoded.contains('/') {
        return None;
    }
    let decoded = percent_decode(encoded)?;
    if decoded.len() > 160 || decoded.chars().any(char::is_control) {
        return None;
    }
    Some(decoded)
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

fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = *bytes.get(index + 1)?;
            let low = *bytes.get(index + 2)?;
            output.push((hex(high)? << 4) | hex(low)?);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(output).ok()
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn json_rpc_error(id: Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}

fn write_response(output: &mut impl Write, value: Value) -> Result<()> {
    serde_json::to_writer(&mut *output, &value)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_uri_round_trips_without_path_injection() {
        let id = "journal id?#中文";
        assert_eq!(parse_resource_uri(&resource_uri(id)).as_deref(), Some(id));
        assert!(parse_resource_uri("ownmate://journal/a/b").is_none());
    }

    #[test]
    fn initialize_declares_resources_only() {
        let value = json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {"resources": {"subscribe": false, "listChanged": false}}
        });
        assert!(value["capabilities"].get("resources").is_some());
        assert!(value["capabilities"].get("tools").is_none());
        assert!(value["capabilities"].get("prompts").is_none());
    }

    #[test]
    fn tools_and_write_methods_are_method_not_found() {
        let api = ExternalApiClient::new("http://127.0.0.1:3000").unwrap();
        let mut session = ExternalSession {
            protocol_version: 1,
            base_url: "http://127.0.0.1:3000".into(),
            grant_id: "external_grant_fixture".into(),
            trust_mode: "temporary".into(),
            access_token: "oma_fixture".into(), // git-guard: ignore — synthetic test token, never accepted by a server
            access_expires_at: u64::MAX,
            refresh_token: None,
            grant_expires_at: Some(u64::MAX),
            dek_key_id: "ownmate_dek_v1".into(),
            dek_base64: STANDARD.encode([0_u8; 32]),
        };
        for method in [
            "tools/list",
            "tools/call",
            "resources/subscribe",
            "journals/write",
        ] {
            let result = dispatch(
                &api,
                &mut session,
                &[0_u8; 32],
                JsonRpcRequest {
                    jsonrpc: Some("2.0".into()),
                    id: Some(json!(1)),
                    method: method.into(),
                    params: Value::Null,
                },
            );
            assert!(matches!(result, Err(DispatchError::MethodNotFound)));
        }
    }
}
