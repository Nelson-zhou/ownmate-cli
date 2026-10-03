use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ownmate_mcp::api::{ExternalApiClient, now_millis};
use ownmate_mcp::crypto::PairingIdentity;
use ownmate_mcp::mcp::serve_stdio;
use ownmate_mcp::storage::{ExternalSession, delete_trusted, load_trusted, save_trusted};
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
    let mut pairing = api.create_pairing(&options.name, identity.public_key_base64())?;
    validate_pairing_response(&pairing)?;
    let pairing_secret = Zeroizing::new(std::mem::take(&mut pairing.pairing_secret));

    eprintln!("请在 OwnMate → 设置 → 设备与外部访问 → 扫码授权 中扫描：");
    eprintln!("核对码：{}", pairing.verification_code);
    eprintln!("公钥指纹：{}", pairing.client_fingerprint);
    eprintln!("{}", render_qr(&pairing.qr_payload)?);
    eprintln!("手机上选择“仅本次使用（30 分钟）”或“信任此设备”。等待批准…");

    while now_millis() < pairing.expires_at.saturating_add(10 * 60 * 1000) {
        let exchange = api.exchange_pairing(&pairing.pairing_id, &pairing_secret)?;
        if exchange.status == "pending" {
            std::thread::sleep(Duration::from_secs(2));
            continue;
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
        if trust_mode != "temporary" && trust_mode != "trusted" {
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
        if trust_mode == "trusted" {
            if session.refresh_token.is_none() {
                return Err(McpError::Invalid("可信授权缺少 refreshToken".into()));
            }
            save_trusted(&session)?;
            eprintln!("外部客户端凭据已写入系统凭据库；可在 App 中随时撤销。");
        } else if session.refresh_token.is_some() || session.grant_expires_at.is_none() {
            return Err(McpError::Invalid("临时授权凭据结构无效".into()));
        } else {
            eprintln!("临时授权已生效；本进程退出或 30 分钟到期后需重新扫码。");
        }
        return serve_stdio(&mut session);
    }
    Err(McpError::Api("配对已过期，请重新运行 pair".into()))
}

fn validate_pairing_response(pairing: &ownmate_mcp::protocol::CreatePairingResponse) -> Result<()> {
    if pairing.protocol_version != 1
        || pairing.pairing_id.is_empty()
        || pairing.pairing_secret.is_empty()
        || pairing.verification_code.len() != 6
    {
        return Err(McpError::Invalid("配对响应无效".into()));
    }
    let qr: Value = serde_json::from_str(&pairing.qr_payload)?;
    if qr.get("t").and_then(Value::as_str) != Some("ownmate-external")
        || qr.get("v").and_then(Value::as_u64) != Some(1)
        || qr.get("pid").and_then(Value::as_str) != Some(&pairing.pairing_id)
        || qr.get("code").and_then(Value::as_str) != Some(&pairing.verification_code)
        || qr.get("fp").and_then(Value::as_str) != Some(&pairing.client_fingerprint)
        || qr.get("exp").and_then(Value::as_u64) != Some(pairing.expires_at)
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
