use crate::api::{ExternalApiClient, ReadResource};
use crate::projection::decrypt_projection_with_keyspace;
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
    serve(
        session,
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
    )
}

fn serve(
    session: &mut ExternalSession,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<()> {
    let decoded = STANDARD
        .decode(&session.dek_base64)
        .map_err(|_| McpError::Invalid("系统凭据库中的 DEK 无效".into()))?;
    if decoded.len() != 32 || STANDARD.encode(&decoded) != session.dek_base64 {
        return Err(McpError::Invalid("系统凭据库中的 DEK 无效".into()));
    }
    let dek = Zeroizing::new(decoded);
    let api = ExternalApiClient::new(&session.base_url)?;
    for line in input.lines() {
        let line = line?;
        if line.len() > MAX_REQUEST_LINE_BYTES {
            write_response(
                output,
                json_rpc_error(Value::Null, -32600, "JSON-RPC 请求超限"),
            )?;
            continue;
        }
        let request: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(request) => request,
            Err(_) => {
                write_response(
                    output,
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
        write_response(output, response)?;
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
                "resources": {"subscribe": false, "listChanged": false},
                "tools": {"listChanged":false}
            },
            "serverInfo": {"name": "ownmate-mcp", "version": env!("CARGO_PKG_VERSION")}
        })),
        "ping" => Ok(json!({})),
        "resources/list" => {
            crate::storage::validate_scopes(&session.scopes)?;
            let mut resources = Vec::new();
            let mut counts = serde_json::Map::new();
            for kind in [
                ReadResource::Journal,
                ReadResource::Fragment,
                ReadResource::Reminder,
                ReadResource::ReminderCompletion,
            ] {
                if !session.scopes.iter().any(|scope| scope == kind.scope()) {
                    continue;
                }
                let items = api.list_resources(session, kind)?;
                counts.insert(kind.path().into(), json!(items.len()));
                for item in items {
                    let projection = decrypt_projection_with_keyspace(
                        kind,
                        &item,
                        &session.dek_key_id,
                        dek,
                        session.keyspace(),
                    )?;
                    let record = if kind == ReadResource::Journal {
                        &projection
                    } else {
                        &projection["record"]
                    };
                    let title = record["title"]
                        .as_str()
                        .filter(|s| !s.trim().is_empty())
                        .unwrap_or(&item.entry_id);
                    resources.push(json!({
                        "uri": typed_resource_uri(kind, &item.entry_id),
                        "name": title, "mimeType":"application/json",
                        "description": format!("OwnMate {} · read-only", kind.path())
                    }));
                }
            }
            Ok(json!({"resources":resources,"_meta":{"ownmate":{
                "scopes":session.scopes, "returnedCount":resources.len(), "allPagesRead":true,
                "countsByResourceType":counts,
                "coverage":"authorized cloud-visible resources, not a complete local archive",
                "unavailable":["mediaFiles","untranscribedMediaContent"],
                "analysisGuidance":"Cite URI and recorded timestamps. Separate observation from inference; missing text is not missing experience."
            }}}))
        }
        "resources/read" => {
            let uri = request
                .params
                .get("uri")
                .and_then(Value::as_str)
                .ok_or_else(|| DispatchError::InvalidParams("缺少 resource uri".into()))?;
            let (kind, entry_id) = parse_typed_uri(uri)
                .ok_or_else(|| DispatchError::InvalidParams("OwnMate resource uri 无效".into()))?;
            let item = api.get_resource(session, kind, &entry_id)?;
            let projection = decrypt_projection_with_keyspace(
                kind,
                &item,
                &session.dek_key_id,
                dek,
                session.keyspace(),
            )?;
            let text = serde_json::to_string(&projection).map_err(McpError::from)?;
            Ok(json!({
                "contents": [{"uri": uri, "mimeType": "application/json", "text": text}]
            }))
        }
        "tools/list" => Ok(json!({"tools":reminder_tools(session)?})),
        "tools/call" => {
            let params = request
                .params
                .as_object()
                .ok_or_else(|| DispatchError::InvalidParams("工具参数必须为对象".into()))?;
            if params
                .keys()
                .any(|k| !["name", "arguments", "_meta"].contains(&k.as_str()))
            {
                return Err(DispatchError::InvalidParams("未知工具调用字段".into()));
            }
            let name = params
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| DispatchError::InvalidParams("缺少工具名称".into()))?;
            let arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let output = call_reminder_tool(api, session, dek, name, arguments);
            match output {
                Ok(value) => Ok(
                    json!({"content":[{"type":"text","text":serde_json::to_string(&value).map_err(McpError::from)?}],"structuredContent":value,"isError":false}),
                ),
                Err(error) => {
                    let retry = match &error {
                        McpError::RateLimited {
                            retry_after_seconds,
                        } => Some(*retry_after_seconds),
                        _ => None,
                    };
                    Ok(
                        json!({"content":[{"type":"text","text":error.to_string()}],"isError":true,"_meta":{"ownmate":{"retryAfterSeconds":retry,"retryGuidance":"Reuse the same requestId and input; never automatically create a replacement request."}}}),
                    )
                }
            }
        }
        _ => Err(DispatchError::MethodNotFound),
    }
}

fn reminder_tools(session: &ExternalSession) -> Result<Vec<Value>> {
    crate::storage::validate_scopes(&session.scopes)?;
    let contract = crate::reminder_interface::contract()?;
    let mut tools = Vec::new();
    for (operation, name, scope, read_only) in [
        ("list", "reminders_list", "reminders:read", true),
        ("read", "reminders_read", "reminders:read", true),
        ("create", "reminders_create", "reminders:write", false),
        ("update", "reminders_update", "reminders:write", false),
        (
            "requestStatus",
            "reminders_request_status",
            "reminders:write",
            true,
        ),
    ] {
        if !session.scopes.iter().any(|s| s == scope)
            || scope == "reminders:write"
                && crate::reminders::validate_write_context(session).is_err()
        {
            continue;
        }
        let mut schema = contract["operations"][operation]["inputSchema"].clone();
        schema["$defs"] = contract["$defs"].clone();
        tools.push(json!({"name":name,"description":contract["operations"][operation]["description"],"inputSchema":schema,
            "annotations":{"readOnlyHint":read_only,"destructiveHint":false,"idempotentHint":true}}));
    }
    Ok(tools)
}

fn call_reminder_tool(
    api: &ExternalApiClient,
    session: &mut ExternalSession,
    dek: &[u8],
    name: &str,
    arguments: Value,
) -> Result<Value> {
    match name {
        "reminders_list" => crate::reminders::list(
            api,
            session,
            dek,
            crate::reminders::ReminderListQuery::parse(arguments)?,
        ),
        "reminders_read" | "reminders_request_status" => {
            let field = if name == "reminders_read" {
                "reminderId"
            } else {
                "requestId"
            };
            let obj = arguments
                .as_object()
                .ok_or_else(|| McpError::Invalid("工具参数必须为对象".into()))?;
            if obj.len() != 1 {
                return Err(McpError::Invalid("工具参数字段无效".into()));
            }
            let id = obj
                .get(field)
                .and_then(Value::as_str)
                .ok_or_else(|| McpError::Invalid("工具缺少标识".into()))?;
            if name == "reminders_read" {
                crate::reminders::read(api, session, dek, id)
            } else {
                crate::reminders::request_status(api, session, id)
            }
        }
        "reminders_create" => crate::reminders::submit(api, session, dek, "create", arguments),
        "reminders_update" => crate::reminders::submit(api, session, dek, "update", arguments),
        _ => Err(McpError::Invalid(
            "未知 OwnMate 工具；不提供完成、删除或记录正文写能力".into(),
        )),
    }
}

fn resource_uri(entry_id: &str) -> String {
    format!("ownmate://journal/{}", percent_encode(entry_id))
}

pub fn typed_resource_uri(kind: ReadResource, id: &str) -> String {
    if kind == ReadResource::Journal {
        return resource_uri(id);
    }
    format!("ownmate://{}/{}", kind.path(), percent_encode(id))
}

#[cfg(test)]
fn parse_resource_uri(uri: &str) -> Option<String> {
    let (kind, id) = parse_typed_uri(uri)?;
    (kind == ReadResource::Journal).then_some(id)
}

pub fn parse_typed_uri(uri: &str) -> Option<(ReadResource, String)> {
    let (namespace, encoded) = uri.strip_prefix("ownmate://")?.split_once('/')?;
    let kind = match namespace {
        "journal" => ReadResource::Journal,
        "fragments" => ReadResource::Fragment,
        "reminders" => ReadResource::Reminder,
        "reminder-completions" => ReadResource::ReminderCompletion,
        _ => return None,
    };
    if encoded.is_empty() || encoded.contains('/') {
        return None;
    }
    let decoded = percent_decode(encoded)?;
    if decoded.len() > 160 || decoded.contains('/') || decoded.chars().any(char::is_control) {
        return None;
    }
    Some((kind, decoded))
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
    fn stdio_consumes_only_mcp_messages_and_emits_only_json_rpc() {
        let mut session = crate::reminders::fixture_session();
        let mut input = std::io::Cursor::new(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n");
        let mut output = Vec::new();
        serve(&mut session, &mut input, &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert_eq!(text.lines().count(), 1);
        let response: Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(response["id"], 1);
        assert_eq!(response["jsonrpc"], "2.0");
        assert!(!text.contains("SYNTHETIC_") && !text.contains(&session.dek_base64));
    }

    #[test]
    fn typed_resource_uris_preserve_namespace_and_reject_path_escape() {
        for kind in [
            ReadResource::Journal,
            ReadResource::Fragment,
            ReadResource::Reminder,
            ReadResource::ReminderCompletion,
        ] {
            let uri = typed_resource_uri(kind, "fixture");
            assert_eq!(parse_typed_uri(&uri), Some((kind, "fixture".into())));
        }
        assert!(parse_typed_uri("ownmate://unknown/fixture").is_none());
        assert!(parse_typed_uri("ownmate://reminders/a%2Fb").is_none());
    }

    #[test]
    fn resource_uri_round_trips_without_path_injection() {
        let id = "journal id?#中文";
        assert_eq!(parse_resource_uri(&resource_uri(id)).as_deref(), Some(id));
        assert!(parse_resource_uri("ownmate://journal/a/b").is_none());
    }

    #[test]
    fn initialize_declares_resources_and_scoped_tools() {
        let api = ExternalApiClient::new("http://127.0.0.1:1").unwrap();
        let value = dispatch(
            &api,
            &mut crate::reminders::fixture_session(),
            &[7; 32],
            JsonRpcRequest {
                jsonrpc: Some("2.0".into()),
                id: Some(json!(1)),
                method: "initialize".into(),
                params: Value::Null,
            },
        )
        .unwrap_or_else(|_| panic!("initialize failed"));
        assert!(value["capabilities"].get("resources").is_some());
        assert!(value["capabilities"].get("tools").is_some());
        assert!(value["capabilities"].get("prompts").is_none());
    }

    #[test]
    fn arbitrary_write_methods_remain_method_not_found() {
        let api = ExternalApiClient::new("http://127.0.0.1:3000").unwrap();
        let mut session = ExternalSession {
            protocol_version: 1,
            base_url: "http://127.0.0.1:3000".into(),
            grant_id: "external_grant_fixture".into(),
            trust_mode: "temporary".into(),
            access_token: "oma_fixture".into(), // git-guard: ignore -- synthetic unit-test token, not a live credential
            access_expires_at: u64::MAX,
            refresh_token: None,
            grant_expires_at: Some(u64::MAX),
            dek_key_id: "ownmate_dek_v1".into(),
            dek_base64: STANDARD.encode([0_u8; 32]),
            scopes: crate::storage::legacy_scopes(),
            keyspace_id: None,
            keyspace_generation: None,
            write_context: None,
            temporary_commands: Vec::new(),
        };
        for method in ["resources/subscribe", "journals/write"] {
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

    #[test]
    fn tools_are_exposed_per_scope_and_each_call_checks_again() {
        let mut session = crate::reminders::fixture_session();
        let names = |session: &ExternalSession| {
            reminder_tools(session)
                .unwrap()
                .into_iter()
                .map(|tool| tool["name"].as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            names(&session),
            [
                "reminders_create",
                "reminders_update",
                "reminders_request_status"
            ]
        );
        let api = ExternalApiClient::new("http://127.0.0.1:1").unwrap();
        assert!(
            call_reminder_tool(
                &api,
                &mut session,
                &[7; 32],
                "reminders_read",
                json!({"reminderId":"fixture"})
            )
            .is_err()
        );
        assert!(
            call_reminder_tool(&api, &mut session, &[7; 32], "reminders_list", json!({})).is_err()
        );
        session.scopes = vec!["reminders:read".into()];
        assert_eq!(names(&session), ["reminders_list", "reminders_read"]);
        assert!(call_reminder_tool(&api,&mut session,&[7;32],"reminders_create",json!({"requestId":"fixture_request_001","title":"fixture title","due":{"kind":"none"},"recurrence":"NONE"})).is_err());
        session.scopes = vec!["journals:read".into(), "fragments:read".into()];
        assert!(names(&session).is_empty());
        session.scopes = vec!["reminders:write".into()];
        session.write_context = None;
        assert!(names(&session).is_empty());
    }
}
