use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ownmate_mcp::api::{ExternalApiClient, now_millis};
use ownmate_mcp::crypto::PairingIdentity;
use ownmate_mcp::mcp::serve_stdio;
use ownmate_mcp::storage::{ExternalSession, credential_probe, delete_trusted, load_trusted};
use ownmate_mcp::{DEFAULT_API_BASE_URL, McpError, Result};
use qrcode::QrCode;
use qrcode::render::unicode;
use serde_json::Value;
use std::io::Read;
use std::time::Duration;
use zeroize::Zeroizing;

fn main() {
    if let Err(error) = run() {
        eprintln!("ownmate-mcp: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("reminders") => reminder_interface_command(args.collect()),
        Some("doctor") => {
            if args.collect::<Vec<_>>() != ["--credential-probe"] {
                return Err(McpError::Invalid(
                    "doctor 仅接受 --credential-probe（只使用隔离合成条目）".into(),
                ));
            }
            let report = credential_probe();
            println!("{}", serde_json::to_string_pretty(&report)?);
            if report.available {
                Ok(())
            } else {
                Err(McpError::Credential(
                    "合成探测未通过；不保证可信凭据能够保存".into(),
                ))
            }
        }
        Some("pair") => {
            let options = PairOptions::parse(args.collect())?;
            pair_and_serve(options)
        }
        Some("mcp") => {
            if args.next().is_some() {
                return Err(McpError::Invalid("mcp 不接受额外参数".into()));
            }
            let mut session = load_trusted()?;
            serve_stdio(&mut session)
        }
        Some("disconnect") => {
            delete_trusted()?;
            eprintln!(
                "已从本机系统凭据库移除 OwnMate 外部客户端；如需立即吊销云端权限，请同时在 App 的“设备与外部访问”中撤销。"
            );
            Ok(())
        }
        Some("--version") | Some("version") => {
            println!("ownmate-mcp {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some(command @ ("list" | "query")) => {
            let query_args: Vec<_> = args.collect();
            if command == "list" && !query_args.is_empty() {
                return Err(McpError::Invalid("筛选请使用 query 命令".into()));
            }
            let query = ownmate_mcp::query::Query::parse(query_args)?;
            let mut session = load_trusted()?;
            let api = ExternalApiClient::new(&session.base_url)?;
            let key = Zeroizing::new(
                STANDARD
                    .decode(&session.dek_base64)
                    .map_err(|_| McpError::Invalid("本机连接密钥无效".into()))?,
            );
            {
                let mut records = Vec::new();
                for kind in [
                    ownmate_mcp::api::ReadResource::Journal,
                    ownmate_mcp::api::ReadResource::Fragment,
                    ownmate_mcp::api::ReadResource::Reminder,
                    ownmate_mcp::api::ReadResource::ReminderCompletion,
                ] {
                    if !session.scopes.iter().any(|scope| scope == kind.scope()) {
                        continue;
                    }
                    for item in api.list_resources(&mut session, kind)? {
                        let mut projection = ownmate_mcp::projection::decrypt_projection(
                            kind,
                            &item,
                            &session.dek_key_id,
                            &key,
                        )?;
                        projection["resourceUri"] = serde_json::json!(
                            ownmate_mcp::mcp::typed_resource_uri(kind, &item.entry_id)
                        );
                        records.push(projection);
                    }
                }
                let output = if command == "query" {
                    query.report_typed(records, &session.scopes)
                } else {
                    serde_json::to_value(records)?
                };
                println!("{}", serde_json::to_string_pretty(&output)?);
                Ok(())
            }
        }
        Some("read") => {
            let id = args
                .next()
                .ok_or_else(|| McpError::Invalid("read 需要记录 ID".into()))?;
            if args.next().is_some() {
                return Err(McpError::Invalid("read 只接受一个记录 ID".into()));
            }
            let mut session = load_trusted()?;
            let api = ExternalApiClient::new(&session.base_url)?;
            let key = Zeroizing::new(
                STANDARD
                    .decode(&session.dek_base64)
                    .map_err(|_| McpError::Invalid("本机连接密钥无效".into()))?,
            );
            let (kind, id) = if id.starts_with("ownmate://") {
                ownmate_mcp::mcp::parse_typed_uri(&id)
                    .ok_or_else(|| McpError::Invalid("资源 URI 无效".into()))?
            } else {
                (ownmate_mcp::api::ReadResource::Journal, id)
            };
            let item = api.get_resource(&mut session, kind, &id)?;
            let record = ownmate_mcp::projection::decrypt_projection(
                kind,
                &item,
                &session.dek_key_id,
                &key,
            )?;
            println!("{}", serde_json::to_string_pretty(&record)?);
            Ok(())
        }
        Some("help") | Some("--help") | Some("-h") | None => {
            print_help();
            Ok(())
        }
        Some(other) => Err(McpError::Invalid(format!("未知命令: {other}"))),
    }
}

fn reminder_interface_command(args: Vec<String>) -> Result<()> {
    match args.as_slice() {
        [command] if command == "schema" => {
            println!(
                "{}",
                serde_json::to_string_pretty(&ownmate_mcp::reminder_interface::contract()?)?
            );
            Ok(())
        }
        [command, operation, input, source]
            if command == "validate" && input == "--input" && source == "-" =>
        {
            // Local shape validation only: never load credentials or construct an API client.
            let value = read_reminder_input()?;
            let result = ownmate_mcp::reminder_interface::validate(operation, value)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
        [operation, input, source] if (operation == "create" || operation == "update") && input == "--input" && source == "-" => {
            execute_reminder_write(operation, None)
        }
        [operation, id, input, source] if operation == "update" && input == "--input" && source == "-" => {
            execute_reminder_write(operation, Some(id))
        }
        [command, id] if command == "read" || command == "request-status" => {
            let mut session = load_trusted()?;
            let api = ExternalApiClient::new(&session.base_url)?;
            let result = if command == "read" {
                let key = ownmate_mcp::reminders::decode_dek(&session)?;
                ownmate_mcp::reminders::read(&api, &mut session, &key, id)?
            } else { ownmate_mcp::reminders::request_status(&api, &mut session, id)? };
            println!("{}", serde_json::to_string_pretty(&result)?); Ok(())
        }
        [command, options @ ..] if command == "list" => {
            let query = ownmate_mcp::reminders::ReminderListQuery::cli(options.to_vec())?;
            let mut session = load_trusted()?; let api = ExternalApiClient::new(&session.base_url)?;
            let key = ownmate_mcp::reminders::decode_dek(&session)?;
            println!("{}",serde_json::to_string_pretty(&ownmate_mcp::reminders::list(&api,&mut session,&key,query)?)?); Ok(())
        }
        _ => Err(McpError::Invalid(
            "提醒命令无效；写入仅接受 create 或 update [ID] --input -，内容必须通过标准输入 JSON 提交".into(),
        )),
    }
}

fn read_reminder_input() -> Result<Value> {
    let mut bytes = Zeroizing::new(Vec::new());
    std::io::stdin()
        .lock()
        .take(512 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 512 * 1024 {
        return Err(McpError::Invalid("待办输入超过 512 KiB".into()));
    }
    serde_json::from_slice(&bytes).map_err(|_| McpError::Invalid("待办输入必须是有效 JSON".into()))
}

fn execute_reminder_write(operation: &str, id: Option<&str>) -> Result<()> {
    let value = read_reminder_input()?;
    ownmate_mcp::reminder_interface::validate(operation, value.clone())?;
    if id.is_some_and(|id| value["reminderId"] != id) {
        return Err(McpError::Invalid(
            "命令事项 ID 与输入 reminderId 不匹配".into(),
        ));
    }
    let mut session = load_trusted()?;
    let api = ExternalApiClient::new(&session.base_url)?;
    let key = ownmate_mcp::reminders::decode_dek(&session)?;
    let result = ownmate_mcp::reminders::submit(&api, &mut session, &key, operation, value)?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

struct PairOptions {
    name: String,
    base_url: String,
}

impl PairOptions {
    fn parse(args: Vec<String>) -> Result<Self> {
        let default_name = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .unwrap_or_else(|_| "Desktop".into());
        let mut options = Self {
            name: format!("{} OwnMate MCP", default_name.trim()),
            base_url: std::env::var("OWNMATE_API_BASE_URL")
                .unwrap_or_else(|_| DEFAULT_API_BASE_URL.into()),
        };
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--name" => {
                    index += 1;
                    options.name = args
                        .get(index)
                        .cloned()
                        .ok_or_else(|| McpError::Invalid("--name 缺少值".into()))?;
                }
                "--base-url" => {
                    index += 1;
                    options.base_url = args
                        .get(index)
                        .cloned()
                        .ok_or_else(|| McpError::Invalid("--base-url 缺少值".into()))?;
                }
                unknown => return Err(McpError::Invalid(format!("未知参数: {unknown}"))),
            }
            index += 1;
        }
        options.name = options.name.trim().to_string();
        if options.name.is_empty() || options.name.chars().count() > 80 {
            return Err(McpError::Invalid(
                "外部客户端名称必须为 1..80 个字符".into(),
            ));
        }
        Ok(options)
    }
}

fn pair_and_serve(options: PairOptions) -> Result<()> {
    let identity = PairingIdentity::generate()?;
    let api = ExternalApiClient::new(&options.base_url)?;
    let probe = credential_probe();
    let trusted_available = probe.available && ownmate_mcp::profiles::trusted_metadata_available();
    let supported_modes: Vec<String> = if trusted_available {
        eprintln!("原生凭据合成探测通过；正式凭据仍需保存并读回校验，探测不保证正式保存成功。");
        vec!["temporary".into(), "trusted".into()]
    } else {
        eprintln!("当前上下文无法完成可信凭据预检；本次只允许手机明确批准临时授权。");
        if !probe.cleanup_verified {
            eprintln!("隔离合成探测条目的清理未能确认；请在本机用户会话检查系统凭据库。");
        }
        vec!["temporary".into()]
    };
    let mut pairing = api.create_pairing(
        &options.name,
        identity.public_key_base64(),
        &supported_modes,
    )?;
    validate_pairing_response(&pairing, &supported_modes)?;
    let pairing_secret = Zeroizing::new(std::mem::take(&mut pairing.pairing_secret));

    eprintln!("请在 OwnMate → 设置 → 扫一扫 中扫描：");
    eprintln!("核对码：{}", pairing.verification_code);
    eprintln!("公钥指纹：{}", pairing.client_fingerprint);
    eprintln!("{}", render_qr(&pairing.qr_payload)?);
    eprintln!("请在手机核对信息并选择可用授权方式。等待批准…");

    while now_millis() < pairing.expires_at.saturating_add(10 * 60 * 1000) {
        let exchange = api.exchange_pairing(&pairing.pairing_id, &pairing_secret)?;
        if exchange.client_ready_version != Some(1)
            || exchange.supported_trust_modes.as_deref() != Some(supported_modes.as_slice())
        {
            return Err(McpError::Invalid(
                "服务端未确认客户端完成协议；新连接尚未生效".into(),
            ));
        }
        if exchange.status == "pending" {
            std::thread::sleep(Duration::from_secs(2));
            continue;
        }
        if exchange.status != "awaiting_client" && exchange.status != "active" {
            return Err(McpError::Invalid("授权响应状态无效".into()));
        }
        let deadline = exchange
            .client_ready_expires_at
            .ok_or_else(|| McpError::Invalid("授权响应缺少客户端完成期限".into()))?;
        if deadline <= now_millis()
            || deadline > now_millis().saturating_add(10 * 60 * 1000)
            || (exchange.status == "active" && exchange.client_ready_at.is_none())
        {
            return Err(McpError::Invalid("客户端完成期限无效或已到期".into()));
        }
        ownmate_mcp::storage::validate_scopes(&exchange.scopes)?;
        let declared: Vec<String> = exchange
            .scope
            .as_deref()
            .unwrap_or("")
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        ownmate_mcp::storage::validate_scopes(&declared)?;
        let declared_set: std::collections::HashSet<_> = declared.iter().collect();
        let approved_set: std::collections::HashSet<_> = exchange.scopes.iter().collect();
        if exchange.protocol_version != 1 || declared_set != approved_set {
            return Err(McpError::Invalid("外部访问授权的协议或权限不兼容".into()));
        }
        let grant_id = exchange
            .grant_id
            .ok_or_else(|| McpError::Invalid("授权响应缺少 grantId".into()))?;
        let trust_mode = exchange
            .trust_mode
            .ok_or_else(|| McpError::Invalid("授权响应缺少 trustMode".into()))?;
        if !supported_modes.contains(&trust_mode) {
            return Err(McpError::Invalid("授权响应 trustMode 无效".into()));
        }
        let envelope = exchange
            .key_envelope
            .ok_or_else(|| McpError::Invalid("授权响应缺少 keyEnvelope".into()))?;
        let (dek_key_id, dek) =
            identity.unwrap_dek(&envelope, &grant_id, &trust_mode, exchange.grant_expires_at)?;
        let mut session = ExternalSession {
            protocol_version: 1,
            base_url: options.base_url,
            grant_id,
            trust_mode: trust_mode.clone(),
            access_token: exchange
                .access_token
                .ok_or_else(|| McpError::Invalid("授权响应缺少 accessToken".into()))?,
            access_expires_at: exchange
                .access_expires_at
                .ok_or_else(|| McpError::Invalid("授权响应缺少 accessExpiresAt".into()))?,
            refresh_token: exchange.refresh_token,
            grant_expires_at: exchange.grant_expires_at,
            dek_key_id,
            dek_base64: STANDARD.encode(&dek),
            keyspace_id: Some(envelope.keyspace_id.clone()),
            keyspace_generation: Some(envelope.keyspace_generation),
            scopes: exchange.scopes,
            write_context: exchange.write_context,
            temporary_commands: Vec::new(),
        };
        if session.scopes.iter().any(|s| s == "reminders:write") {
            ownmate_mcp::reminders::validate_write_context(&session)?;
        }
        ownmate_mcp::pairing::validate_session_mode(&session, now_millis())?;
        if trust_mode == "trusted" {
            eprintln!("正在保存并读回校验可信凭据；失败时在原期限内重试同一授权，旧连接保留。");
            ownmate_mcp::pairing::retry_before_deadline(
                deadline,
                || ownmate_mcp::profiles::stage_trusted(&session, deadline),
                now_millis,
                || std::thread::sleep(Duration::from_secs(5)),
            )?;
        }
        ownmate_mcp::pairing::retry_before_deadline(
            deadline,
            || api.client_ready(&mut session, deadline),
            now_millis,
            || std::thread::sleep(Duration::from_secs(5)),
        )?;
        if trust_mode == "trusted" {
            ownmate_mcp::profiles::activate_trusted(&session, deadline)?;
            eprintln!("可信凭据已读回校验，客户端 ready 已确认；可在 App 中随时撤销。");
        } else {
            eprintln!("临时授权已确认；本进程退出或原 30 分钟期限到期后需重新扫码。");
        }
        return serve_stdio(&mut session);
    }
    Err(McpError::Api("配对已过期，请重新运行 pair".into()))
}

fn validate_pairing_response(
    pairing: &ownmate_mcp::protocol::CreatePairingResponse,
    supported_modes: &[String],
) -> Result<()> {
    if pairing.client_ready_version != Some(1)
        || pairing.supported_trust_modes.as_deref() != Some(supported_modes)
    {
        return Err(McpError::Invalid(
            "服务端不支持客户端 ready 协议；请更新服务端后重新配对（二维码尚未显示）".into(),
        ));
    }
    if pairing.protocol_version != 1
        || pairing.pairing_id.is_empty()
        || pairing.pairing_secret.is_empty()
        || pairing.verification_code.len() != 6
    {
        return Err(McpError::Invalid("配对响应无效".into()));
    }
    ownmate_mcp::pairing::validate_modes(supported_modes)?;
    let qr: Value = serde_json::from_str(&pairing.qr_payload)
        .map_err(|_| McpError::Invalid("配对二维码格式无效".into()))?;
    if qr.get("t").and_then(Value::as_str) != Some("ownmate-external")
        || qr.get("v").and_then(Value::as_u64) != Some(1)
        || qr.get("pid").and_then(Value::as_str) != Some(&pairing.pairing_id)
        || qr.get("code").and_then(Value::as_str) != Some(&pairing.verification_code)
        || qr.get("fp").and_then(Value::as_str) != Some(&pairing.client_fingerprint)
        || qr.get("exp").and_then(Value::as_u64) != Some(pairing.expires_at)
        || qr.get("clientReadyVersion").and_then(Value::as_u64) != Some(1)
        || qr.get("supportedTrustModes") != Some(&serde_json::to_value(supported_modes)?)
        || qr.get("pairingSecret").is_some()
        || qr.get("token").is_some()
        || qr.get("pk").is_some()
    {
        return Err(McpError::Invalid("配对二维码与服务端响应不一致".into()));
    }
    Ok(())
}

fn render_qr(payload: &str) -> Result<String> {
    let code = QrCode::new(payload.as_bytes())
        .map_err(|_| McpError::Invalid("配对二维码生成失败".into()))?;
    Ok(code.render::<unicode::Dense1x2>().quiet_zone(true).build())
}

fn print_help() {
    eprintln!("OwnMate CLI/MCP（按手机明确授权）");
    eprintln!("  ownmate-mcp pair [--name NAME] [--base-url URL]");
    eprintln!("  ownmate-mcp mcp");
    eprintln!("  ownmate-mcp disconnect");
    eprintln!("  ownmate-mcp doctor --credential-probe  仅探测并清理隔离合成凭据");
    eprintln!("  ownmate-mcp list                 输出授权记录的 JSON");
    eprintln!(
        "  ownmate-mcp query [--contains TEXT] [--tag TAG] [--from YYYY-MM-DD] [--through YYYY-MM-DD]"
    );
    eprintln!("  ownmate-mcp read ENTRY_ID        输出指定记录的 JSON");
    eprintln!("  ownmate-mcp reminders schema     离线输出待办字段规范、示例与权限说明");
    eprintln!("  ownmate-mcp reminders validate create|update --input -");
    eprintln!("                                  仅校验输入形状，不联网、不写入事项");
    eprintln!(
        "  ownmate-mcp reminders list [--filter all|today|overdue|range|noDate] [--status PENDING|COMPLETED] [--time-zone IANA] [--from YYYY-MM-DD --through YYYY-MM-DD]"
    );
    eprintln!("  ownmate-mcp reminders read ID");
    eprintln!("  ownmate-mcp reminders create --input -");
    eprintln!("  ownmate-mcp reminders update ID --input -");
    eprintln!("  ownmate-mcp reminders request-status REQUEST_ID");
    eprintln!("  ownmate-mcp --version");
    eprintln!("pair 会显示二维码；手机决定临时 30 分钟或信任设备，然后当前进程进入 MCP stdio。");
}

#[cfg(test)]
mod pairing_protocol_tests {
    use super::*;
    fn fixture() -> ownmate_mcp::protocol::CreatePairingResponse {
        let modes = vec!["temporary".to_string()];
        ownmate_mcp::protocol::CreatePairingResponse {
            protocol_version: 1, pairing_id: "synthetic_pairing".into(),
            pairing_secret: "SYNTHETIC_PAIRING_SECRET_NOT_LIVE".into(),
            verification_code: "123456".into(), client_fingerprint: "synthetic_fp".into(),
            expires_at: 100, client_ready_version: Some(1), supported_trust_modes: Some(modes.clone()),
            qr_payload: serde_json::json!({"t":"ownmate-external","v":1,"pid":"synthetic_pairing",
                "code":"123456","fp":"synthetic_fp","exp":100,"clientReadyVersion":1,"supportedTrustModes":modes}).to_string(),
        }
    }

    #[test]
    fn legacy_server_is_rejected_before_qr_render_and_negotiation_cannot_expand_modes() {
        let modes = vec!["temporary".into()];
        let mut pairing = fixture();
        assert!(validate_pairing_response(&pairing, &modes).is_ok());
        pairing.client_ready_version = None;
        assert!(
            validate_pairing_response(&pairing, &modes)
                .unwrap_err()
                .to_string()
                .contains("二维码尚未显示")
        );
        pairing.client_ready_version = Some(1);
        pairing
            .supported_trust_modes
            .as_mut()
            .unwrap()
            .push("trusted".into());
        assert!(validate_pairing_response(&pairing, &modes).is_err());
        let mut pairing = fixture();
        let mut qr: Value = serde_json::from_str(&pairing.qr_payload).unwrap();
        qr["supportedTrustModes"] = serde_json::json!(["temporary", "trusted"]);
        pairing.qr_payload = qr.to_string();
        assert!(validate_pairing_response(&pairing, &modes).is_err());
    }

    #[test]
    fn new_exchange_requires_explicit_scopes_without_legacy_fallback() {
        let exchange: ownmate_mcp::protocol::ExchangePairingResponse = serde_json::from_value(
            serde_json::json!({"protocolVersion":1,"status":"awaiting_client","scope":"journals:read","clientReadyVersion":1})
        ).unwrap();
        assert!(ownmate_mcp::storage::validate_scopes(&exchange.scopes).is_err());
    }

    #[test]
    fn malformed_wrapped_dek_does_not_echo_private_values() {
        let identity = PairingIdentity::generate().unwrap();
        let envelope = ownmate_mcp::protocol::ExternalKeyEnvelope {
            version: 2,
            keyspace_id: "synthetic_space".into(),
            keyspace_generation: 1,
            algorithm: "AES-256-GCM".into(),
            hkdf_info: "OwnMate ExternalAccess v2".into(),
            salt: String::new(),
            wrapped_dek: r#"{"version":"PRIVATE_SYNTHETIC_VALUE"}"#.into(),
            source_device_id: "synthetic_device".into(),
            source_public_key: String::new(),
        };
        let error = identity
            .unwrap_dek(&envelope, "synthetic_grant", "trusted", None)
            .unwrap_err();
        assert_eq!(error.to_string(), "密码学验证失败");
        assert!(!error.to_string().contains("PRIVATE_"));
    }
}
