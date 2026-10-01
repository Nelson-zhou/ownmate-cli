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
        Some("list") => {
            let mut session = load_trusted()?;
            let api = ExternalApiClient::new(&session.base_url)?;
            let key = Zeroizing::new(
                STANDARD
                    .decode(&session.dek_base64)
                    .map_err(|_| McpError::Invalid("本机连接密钥无效".into()))?,
            );
            let records = api
                .list_journals(&mut session)?
                .into_iter()
                .map(|item| {
                    ownmate_mcp::crypto::decrypt_mcp_journal(&item, &session.dek_key_id, &key)
                })
                .collect::<Result<Vec<_>>>()?;
            println!("{}", serde_json::to_string_pretty(&records)?);
            Ok(())
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
            let item = api.get_journal(&mut session, &id)?;
            let record =
                ownmate_mcp::crypto::decrypt_mcp_journal(&item, &session.dek_key_id, &key)?;
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
        if exchange.protocol_version != 1 || exchange.scope.as_deref() != Some("journals:read") {
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
        };
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
    eprintln!("OwnMate CLI/MCP（只读）");
    eprintln!("  ownmate-mcp pair [--name NAME] [--base-url URL]");
    eprintln!("  ownmate-mcp mcp");
    eprintln!("  ownmate-mcp disconnect");
    eprintln!("  ownmate-mcp list                 输出授权记录的 JSON");
    eprintln!("  ownmate-mcp read ENTRY_ID        输出指定记录的 JSON");
    eprintln!("  ownmate-mcp --version");
    eprintln!("pair 会显示二维码；手机决定临时 30 分钟或信任设备，然后当前进程进入 MCP stdio。");
}
