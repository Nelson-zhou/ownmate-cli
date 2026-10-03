use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ownmate_mcp::api::{ExternalApiClient, now_millis};
use ownmate_mcp::crypto::PairingIdentity;
use ownmate_mcp::mcp::serve_stdio;
use ownmate_mcp::pair_owner::{PairOwner, QrOutput, State};
use ownmate_mcp::storage::{ExternalSession, credential_probe, delete_trusted, load_trusted};
use ownmate_mcp::{DEFAULT_API_BASE_URL, McpError, Result};
use qrcode::QrCode;
use qrcode::render::unicode;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

fn main() {
    if let Err(error) = run() {
        let (reason, next) = error_action(&error);
        if std::env::args().any(|v| v == "--json") {
            eprintln!(
                "{}",
                serde_json::json!({"schemaVersion":1,"ok":false,"reason":reason,"nextAction":next})
            );
        } else {
            eprintln!("ownmate-mcp: {error}\nreason={reason} nextAction={next}");
        }
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let values: Vec<String> = std::env::args().skip(1).collect();
    if values.iter().any(|v| v == "--help" || v == "-h")
        || values.first().is_some_and(|v| v == "help")
    {
        return command_help(&values);
    }
    let mut args = values.into_iter();
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
            let values: Vec<String> = args.collect();
            if values
                .first()
                .is_some_and(|v| v == "status" || v == "replace")
            {
                return pair_control(values);
            }
            let options = PairOptions::parse(values)?;
            pair_and_serve(options)
        }
        Some("status") => {
            let values: Vec<String> = args.collect();
            if !values.is_empty() && values != ["--json"] {
                return Err(McpError::Invalid("status 仅接受 --json".into()));
            }
            let connection = ownmate_mcp::profiles::metadata_status()?;
            let pairings = ownmate_mcp::pair_owner::all_status()?;
            display_status(
                &serde_json::json!({"schemaVersion":1,"connection":connection,"pairings":pairings.sessions,
                "pairingsTruncated":pairings.truncated,"pairingsScanTruncated":pairings.scan_truncated,"pairingsLimit":128,
                "evidence":"local_metadata_only_no_credentials_or_network",
                "reason":"LOCAL_STATUS_ONLY","nextAction":if pairings.truncated { "use_pair_status_with_explicit_session_for_unlisted_runs" } else { "inspect_connection_and_pairing_reasons" }}),
                !values.is_empty(),
            )
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
    setup: bool,
    qr_output: Option<std::path::PathBuf>,
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
            setup: false,
            qr_output: None,
        };
        let mut mode_seen = false;
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
                "--setup" | "--serve" => {
                    if mode_seen {
                        return Err(McpError::Invalid("--setup 与 --serve 只能选择一个".into()));
                    }
                    mode_seen = true;
                    options.setup = args[index] == "--setup";
                }
                "--qr-output" => {
                    if options.qr_output.is_some() {
                        return Err(McpError::Invalid("--qr-output 不得重复".into()));
                    }
                    index += 1;
                    options.qr_output = Some(
                        args.get(index)
                            .ok_or_else(|| McpError::Invalid("--qr-output 缺少 SVG 路径".into()))?
                            .into(),
                    );
                }
                _ => {
                    return Err(McpError::Invalid(
                        "pair 参数无效；请运行 pair --help".into(),
                    ));
                }
            }
            index += 1;
        }
        options.name = options.name.trim().to_string();
        if options.name.is_empty() || options.name.chars().count() > 80 {
            return Err(McpError::Invalid(
                "外部客户端名称必须为 1..80 个字符".into(),
            ));
        }
        let trimmed = options.name.trim();
        if trimmed.is_empty()
            || trimmed.encode_utf16().count() > 80
            || trimmed.chars().any(char::is_control)
        {
            return Err(McpError::Invalid(
                "客户端名称必须为不含控制字符的 1–80 个 UTF-16 单元".into(),
            ));
        }
        options.name = trimmed.to_owned();
        Ok(options)
    }
}

fn pair_and_serve(options: PairOptions) -> Result<()> {
    let mut qr_output = options.qr_output.clone().map(QrOutput::new).transpose()?;
    let api = ExternalApiClient::new(&options.base_url)?;
    let clock = PairClock {
        start: now_millis(),
        elapsed: Instant::now(),
    };
    let wait_deadline = clock
        .now()
        .saturating_add(ownmate_mcp::pair_retry::WAIT_BUDGET_MS);
    let mut owner = PairOwner::start(wait_deadline).ok();
    if let Some(owner) = &owner {
        eprintln!(
            "配对 session={}；可用 pair status/replace --session 查询或请求原进程换码。",
            owner.id()
        );
    } else {
        eprintln!(
            "私有配对控制不可用；仍可同进程临时配对与有界到期换码，不能跨进程控制或恢复未交换材料。"
        );
    }
    let mut generation = 0;
    let mut qr_expires = None;
    let result = (|| {
        let probe = credential_probe();
        let trusted_available =
            probe.available && ownmate_mcp::profiles::trusted_metadata_available();
        if options.setup && !trusted_available {
            return Err(McpError::Credential("setup 需要可用原生可信凭据和私有选择器；可改由 MCP Host 运行 pair --serve 并明确选择临时方式".into()));
        }
        let supported_modes: Vec<String> = if options.setup {
            vec!["trusted".into()]
        } else if trusted_available {
            eprintln!("原生凭据合成探测通过；正式凭据仍需保存并读回校验，探测不保证正式保存成功。");
            vec!["temporary".into(), "trusted".into()]
        } else {
            eprintln!("当前上下文无法完成可信凭据预检；本次只允许手机明确批准临时授权。");
            if !probe.cleanup_verified {
                eprintln!("隔离合成探测条目的清理未能确认；请在本机用户会话检查系统凭据库。");
            }
            vec!["temporary".into()]
        };
        let (identity, exchange) = wait_for_approval(
            &api,
            &options.name,
            &supported_modes,
            WaitContext {
                owner: &mut owner,
                output: &mut qr_output,
                generation: &mut generation,
                expires: &mut qr_expires,
                deadline: wait_deadline,
            },
            || clock.now(),
            std::thread::sleep,
        )?;
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
            update_owner(
                &mut owner,
                State::Saving,
                generation,
                qr_expires,
                qr_output.as_ref(),
            );
            eprintln!("正在保存并读回校验可信凭据；失败时在原期限内重试同一授权，旧连接保留。");
            ownmate_mcp::pairing::retry_before_deadline(
                deadline,
                || ownmate_mcp::profiles::stage_trusted(&session, deadline),
                now_millis,
                || std::thread::sleep(Duration::from_secs(5)),
            )?;
        }
        update_owner(
            &mut owner,
            State::Ready,
            generation,
            qr_expires,
            qr_output.as_ref(),
        );
        ownmate_mcp::pair_retry::retry(
            deadline,
            |timeout| api.client_ready_with_timeout(&mut session, deadline, timeout),
            || clock.now(),
            std::thread::sleep,
            || eprintln!("ready 瞬时失败；保留同一已校验候选，在原期限内有界重试。"),
        )?;
        if trust_mode == "trusted" {
            ownmate_mcp::profiles::activate_trusted(&session, deadline)?;
            eprintln!("可信凭据已读回校验，客户端 ready 已确认；可在 App 中随时撤销。");
        } else {
            eprintln!("临时授权已确认；本进程退出或原 30 分钟期限到期后需重新扫码。");
        }
        if let Some(output) = &mut qr_output {
            let _ = output.invalidate();
        }
        if options.setup {
            update_owner(
                &mut owner,
                State::Connected,
                generation,
                qr_expires,
                qr_output.as_ref(),
            );
            eprintln!("可信 setup 完成；退出安装配对进程，MCP Host 请运行 ownmate-mcp mcp。");
            Ok(())
        } else {
            update_owner(
                &mut owner,
                State::Serving,
                generation,
                qr_expires,
                qr_output.as_ref(),
            );
            let result = serve_stdio(&mut session);
            update_owner(
                &mut owner,
                State::Ended,
                generation,
                qr_expires,
                qr_output.as_ref(),
            );
            eprintln!("MCP stdio 已结束；临时会话随本进程结束，可信连接可由 mcp 重新载入。");
            result
        }
    })();
    if result.is_err() {
        if let Some(owner) = &mut owner {
            let _ = owner.failed();
        }
        if let Some(output) = &mut qr_output {
            let _ = output.invalidate();
        }
    }
    result
}

struct PairClock {
    start: u64,
    elapsed: Instant,
}
impl PairClock {
    fn now(&self) -> u64 {
        self.start
            .saturating_add(self.elapsed.elapsed().as_millis() as u64)
    }
}

struct WaitContext<'a> {
    owner: &'a mut Option<PairOwner>,
    output: &'a mut Option<QrOutput>,
    generation: &'a mut u32,
    expires: &'a mut Option<u64>,
    deadline: u64,
}

/// Real pairing seam: mock HTTP and virtual time, without constructing a native credential store.
fn wait_for_approval(
    api: &ExternalApiClient,
    name: &str,
    modes: &[String],
    context: WaitContext<'_>,
    clock: impl Fn() -> u64,
    mut wait: impl FnMut(Duration),
) -> Result<(
    PairingIdentity,
    ownmate_mcp::protocol::ExchangePairingResponse,
)> {
    'codes: loop {
        if *context.generation >= ownmate_mcp::pair_retry::MAX_QR_CODES
            || clock() >= context.deadline
        {
            update_owner(
                context.owner,
                State::Expired,
                *context.generation,
                *context.expires,
                context.output.as_ref(),
            );
            return Err(McpError::Invalid(
                "本流程已达到三张二维码或十五分钟等待上限；请重新运行 pair".into(),
            ));
        }
        *context.generation += 1;
        let identity = PairingIdentity::generate()?;
        let mut pairing = api.create_pairing_with_timeout(
            name,
            identity.public_key_base64(),
            modes,
            Duration::from_millis(context.deadline.saturating_sub(clock()).min(10_000)),
        )?;
        validate_pairing_response(&pairing, modes, name, identity.public_key_base64(), clock())?;
        *context.expires = Some(pairing.expires_at);
        let secret = Zeroizing::new(std::mem::take(&mut pairing.pairing_secret));
        if let Some(output) = context.output {
            output.write(render_qr_svg(&pairing.qr_payload)?.as_bytes())?;
            eprintln!(
                "当前二维码 SVG：{}；请本地转换为 PNG 图片附件，不要粘贴字符二维码。",
                output.path().display()
            );
        }
        update_owner(
            context.owner,
            State::WaitingPhone,
            *context.generation,
            *context.expires,
            context.output.as_ref(),
        );
        eprintln!(
            "请在 OwnMate → 设置 → 扫一扫 扫描当前第 {} 张码；旧图片不得复用。",
            *context.generation
        );
        eprintln!(
            "核对码：{}\n公钥指纹：{}",
            pairing.verification_code, pairing.client_fingerprint
        );
        eprintln!("{}", render_qr(&pairing.qr_payload)?);
        eprintln!("请在手机核对信息并选择可用授权方式。等待批准…");
        let mut approved = false;
        let mut force_replace = false;
        loop {
            if !approved && clock() >= context.deadline {
                update_owner(
                    context.owner,
                    State::Expired,
                    *context.generation,
                    *context.expires,
                    context.output.as_ref(),
                );
                if let Some(output) = context.output {
                    let _ = output.invalidate();
                }
                return Err(McpError::Invalid(
                    "十五分钟等待预算已到；新连接未完成".into(),
                ));
            }
            let requested = context
                .owner
                .as_ref()
                .map(PairOwner::take_replace)
                .transpose()?
                .unwrap_or(false);
            if !approved && (requested || force_replace || clock() >= pairing.expires_at) {
                update_owner(
                    context.owner,
                    State::Replacing,
                    *context.generation,
                    *context.expires,
                    context.output.as_ref(),
                );
                let outcome = ownmate_mcp::pair_retry::retry(
                    context.deadline,
                    |timeout| api.cancel_pairing(&pairing.pairing_id, &secret, timeout),
                    &clock,
                    &mut wait,
                    || eprintln!("取消请求瞬时失败；保留同一旧码材料重试，尚未展示新码。"),
                )?;
                match outcome {
                    ownmate_mcp::api::CancelOutcome::Cancelled
                    | ownmate_mcp::api::CancelOutcome::Expired => {
                        if let Some(output) = context.output {
                            output.invalidate()?;
                        }
                        eprintln!(
                            "旧码已取消或确认过期；原期限未延长，正在生成独立新码。请只展示最新图片。"
                        );
                        continue 'codes;
                    }
                    ownmate_mcp::api::CancelOutcome::AlreadyApproved => {
                        approved = true;
                        update_owner(
                            context.owner,
                            State::Exchanging,
                            *context.generation,
                            *context.expires,
                            context.output.as_ref(),
                        );
                        eprintln!("手机批准先完成；不生成新码，继续交换并完成原授权。");
                    }
                }
            }
            let exchange_deadline = if approved {
                pairing.expires_at.saturating_add(10 * 60 * 1000)
            } else {
                context
                    .deadline
                    .min(pairing.expires_at.saturating_add(10 * 60 * 1000))
            };
            let exchange = match ownmate_mcp::pair_retry::retry(
                exchange_deadline,
                |timeout| api.exchange_pairing_with_timeout(&pairing.pairing_id, &secret, timeout),
                &clock,
                &mut wait,
                || {
                    update_owner(
                        context.owner,
                        if approved {
                            State::Exchanging
                        } else {
                            State::NetworkRetry
                        },
                        *context.generation,
                        *context.expires,
                        context.output.as_ref(),
                    );
                    eprintln!("交换瞬时失败；在原期限内重试同一授权，保持当前进程存活。");
                },
            ) {
                Ok(value) => value,
                Err(McpError::ApiResponse {
                    status: 410,
                    ref code,
                    ..
                }) if !approved && code == "EXTERNAL_EXCHANGE_EXPIRED" => {
                    force_replace = true;
                    continue;
                }
                Err(error) => return Err(error),
            };
            if exchange.client_ready_version != Some(1)
                || exchange.supported_trust_modes.as_deref() != Some(modes)
            {
                return Err(McpError::Invalid(
                    "服务端未确认客户端完成协议；新连接尚未生效".into(),
                ));
            }
            if exchange.status == "pending" {
                if approved {
                    return Err(McpError::Invalid("批准后的配对状态倒退；未切换授权".into()));
                }
                update_owner(
                    context.owner,
                    State::WaitingPhone,
                    *context.generation,
                    *context.expires,
                    context.output.as_ref(),
                );
                wait(Duration::from_millis(
                    context
                        .deadline
                        .min(pairing.expires_at)
                        .saturating_sub(clock())
                        .min(2000),
                ));
                continue;
            }
            if exchange.status != "awaiting_client" && exchange.status != "active" {
                return Err(McpError::Invalid("授权响应状态无效".into()));
            }
            update_owner(
                context.owner,
                State::Exchanging,
                *context.generation,
                *context.expires,
                context.output.as_ref(),
            );
            return Ok((identity, exchange));
        }
    }
}

fn update_owner(
    owner: &mut Option<PairOwner>,
    state: State,
    generation: u32,
    expires: Option<u64>,
    output: Option<&QrOutput>,
) {
    if owner.as_mut().is_some_and(|owner| {
        owner
            .update(state, generation, expires, output.map(QrOutput::path))
            .is_err()
    }) {
        eprintln!("私有配对状态更新失败；已停止跨进程控制，授权秘密仍只在当前进程。");
        *owner = None;
    }
}

fn validate_pairing_response(
    pairing: &ownmate_mcp::protocol::CreatePairingResponse,
    supported_modes: &[String],
    name: &str,
    public_key: &str,
    now: u64,
) -> Result<()> {
    if pairing.client_ready_version != Some(1)
        || pairing.supported_trust_modes.as_deref() != Some(supported_modes)
    {
        return Err(McpError::Invalid(
            "服务端不支持客户端 ready 协议；请更新服务端后重新配对（二维码尚未显示）".into(),
        ));
    }
    if pairing.protocol_version != 1
        || !valid_pairing_id(&pairing.pairing_id)
        || pairing.pairing_secret.len() != 43
        || !pairing
            .pairing_secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        || pairing.verification_code.len() != 6
        || !pairing
            .verification_code
            .bytes()
            .all(|b| b.is_ascii_digit())
        || pairing.client_fingerprint != public_fingerprint(public_key)?
        || pairing.expires_at <= now
        || pairing.expires_at > now.saturating_add(5 * 60 * 1000 + 30_000)
        || pairing.qr_payload.len() > 4096
    {
        return Err(McpError::Invalid("配对响应无效".into()));
    }
    ownmate_mcp::pairing::validate_modes(supported_modes)?;
    let qr: Value = serde_json::from_str(&pairing.qr_payload)
        .map_err(|_| McpError::Invalid("配对二维码格式无效".into()))?;
    let fields = [
        "t",
        "v",
        "pid",
        "code",
        "fp",
        "name",
        "exp",
        "clientReadyVersion",
        "supportedTrustModes",
    ];
    if !qr.as_object().is_some_and(|object| {
        object.len() == fields.len() && object.keys().all(|k| fields.contains(&k.as_str()))
    }) || qr.get("t").and_then(Value::as_str) != Some("ownmate-external")
        || qr.get("v").and_then(Value::as_u64) != Some(1)
        || qr.get("pid").and_then(Value::as_str) != Some(&pairing.pairing_id)
        || qr.get("code").and_then(Value::as_str) != Some(&pairing.verification_code)
        || qr.get("fp").and_then(Value::as_str) != Some(&pairing.client_fingerprint)
        || qr.get("name").and_then(Value::as_str) != Some(name)
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

fn valid_pairing_id(value: &str) -> bool {
    value.strip_prefix("external_pairing_").is_some_and(|uuid| {
        uuid.len() == 36
            && uuid.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
                }
            })
    })
}

fn public_fingerprint(public_key: &str) -> Result<String> {
    let bytes = STANDARD
        .decode(public_key)
        .map_err(|_| McpError::Invalid("客户端公钥编码无效".into()))?;
    Ok(Sha256::digest(bytes)
        .iter()
        .take(6)
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":"))
}

fn render_qr(payload: &str) -> Result<String> {
    let code = QrCode::new(payload.as_bytes())
        .map_err(|_| McpError::Invalid("配对二维码生成失败".into()))?;
    Ok(code.render::<unicode::Dense1x2>().quiet_zone(true).build())
}

fn render_qr_svg(payload: &str) -> Result<String> {
    let code = QrCode::new(payload.as_bytes())
        .map_err(|_| McpError::Invalid("配对二维码图片生成失败".into()))?;
    Ok(code
        .render::<qrcode::render::svg::Color>()
        .quiet_zone(true)
        .module_dimensions(8, 8)
        .build())
}

fn display_status(value: &Value, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(value)?);
    } else {
        eprintln!("{}", serde_json::to_string_pretty(value)?);
    }
    Ok(())
}

fn pair_control(args: Vec<String>) -> Result<()> {
    let mut session = None;
    let mut json = false;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--session" if session.is_none() => {
                index += 1;
                session = Some(
                    args.get(index)
                        .ok_or_else(|| McpError::Invalid("--session 缺少 RUN_ID".into()))?
                        .as_str(),
                );
            }
            "--json" if !json => json = true,
            _ => {
                return Err(McpError::Invalid(
                    "pair status/replace 仅接受 --session RUN_ID [--json]".into(),
                ));
            }
        }
        index += 1;
    }
    let session = session.ok_or_else(|| {
        McpError::Invalid(
            "请用原 pair 进程输出的 --session RUN_ID；不能按名称或 IP 推测旧授权".into(),
        )
    })?;
    let value = if args[0] == "replace" {
        ownmate_mcp::pair_owner::replace(session)?
    } else {
        ownmate_mcp::pair_owner::status(session)?
    };
    display_status(&value, json)
}

fn error_action(error: &McpError) -> (&str, &str) {
    match error {
        McpError::Action {
            reason,
            next_action,
        } => (reason, next_action),
        McpError::PairTransport { retryable: true } => (
            "TRANSIENT_RETRY_EXHAUSTED",
            "check_network_then_start_new_pair_or_resume_verified_candidate",
        ),
        McpError::PairTransport { retryable: false } => (
            "TRANSPORT_SECURITY_OR_CONFIGURATION_FAILURE",
            "check_tls_and_network_configuration_do_not_disable_verification",
        ),
        McpError::ApiResponse { code, .. } => (
            code.as_str(),
            "inspect_local_status_do_not_assume_connection_succeeded",
        ),
        McpError::RateLimited { .. } => {
            ("RATE_LIMITED", "respect_retry_after_and_original_deadline")
        }
        McpError::Credential(_) => (
            "NATIVE_CREDENTIAL_OR_SELECTOR_UNAVAILABLE",
            "inspect_status_or_use_pair_serve_with_explicit_temporary_approval",
        ),
        McpError::Crypto => (
            "ENVELOPE_VALIDATION_FAILED",
            "do_not_use_connection_start_new_pair",
        ),
        McpError::Invalid(_) => (
            "INVALID_COMMAND_OR_PAIRING_STATE",
            "read_subcommand_help_and_local_status",
        ),
        _ => (
            "OPERATION_NOT_COMPLETED",
            "inspect_local_status_do_not_assume_connection_succeeded",
        ),
    }
}

fn command_help(args: &[String]) -> Result<()> {
    let values: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|v| !matches!(*v, "help" | "--help" | "-h"))
        .collect();
    let length = match values.as_slice() {
        ["pair", "status" | "replace", ..] | ["reminders", _, ..] => 2,
        [] => 0,
        _ => 1,
    };
    let path = &values[..length];
    match path {
        [] => print_help(),
        ["pair"] => eprintln!(
            "ownmate-mcp pair [--setup | --serve] [--name NAME] [--base-url HTTPS_URL] [--qr-output FILE.svg]\n默认 --serve：手机选择可用方式，ready 后提供同进程 MCP；stdin EOF 即结束，临时不可跨进程。\n--setup：只提供 trusted，原生保存/读回和 ready/选择器完成后退出，不需要 MCP stdin。\n二维码每张五分钟；同流程最多三张/十五分钟等待，换码先确认旧 pending 取消或过期。\n--qr-output：确定性 SVG，拒覆盖已有文件/链接；本地转 PNG 并展示最新图片附件。\nowner 私钥/secret 不落普通文件，不自动解锁系统凭据库。\nownmate-mcp pair status|replace --session RUN_ID [--json]"
        ),
        ["pair", "status"] => eprintln!(
            "ownmate-mcp pair status --session RUN_ID [--json]\n仅读私有非敏感状态和 OS owner 锁，不读原生凭据/请求网络。owner_lost 后不能恢复尚未交换材料；显示 reason/nextAction/evidence。"
        ),
        ["pair", "replace"] => eprintln!(
            "ownmate-mcp pair replace --session RUN_ID [--json]\n向活的原 pair owner 排队非敏感换码请求，不立即表示旧码已失效。等待 status 的新 generation/图片；批准若先赢则完成旧授权。不按名称/IP取消其它码。"
        ),
        ["status"] => eprintln!(
            "ownmate-mcp status [--json]\n仅读本机非敏感 selector/配对状态，不探测凭据、不联网。configured 不证明服务器 active 或 keyring 当前可读；旧 legacy 未检查。结果含 evidence/reason/nextAction。"
        ),
        ["doctor"] => eprintln!(
            "ownmate-mcp doctor --credential-probe\n明确执行随机独立合成凭据 set/read/比较/delete；不读实际 profile/token/内容。通过不保证正式 trusted 保存成功。"
        ),
        ["mcp"] => eprintln!(
            "ownmate-mcp mcp\n载入可信原生凭据；待完成候选优先幂等恢复原 ready，不退回旧权限。stdout 仅 JSON-RPC，stdin EOF 退出；不会读取内容来验证安装。"
        ),
        ["disconnect"] => eprintln!(
            "ownmate-mcp disconnect\n显式移除本机 OwnMate 外部凭据；不自动撤销云端 Grant、不擦除第三方已复制内容。云端撤销需用户在 App 执行。"
        ),
        ["list"] => eprintln!(
            "ownmate-mcp list\n读取并本地解密已授权类型，stdout 输出 JSON。会读取用户内容；安装验证不得自动执行。无额外参数；未授权类型不读取。"
        ),
        ["query"] => eprintln!(
            "ownmate-mcp query [--contains TEXT] [--tag TAG] [--from YYYY-MM-DD] [--through YYYY-MM-DD]\n读取/解密已授权数据后本地筛选，stdout JSON；安装验证不得自动执行。"
        ),
        ["read"] => eprintln!(
            "ownmate-mcp read ENTRY_ID_OR_OWNMATE_URI\n读取指定已授权实体并本地解密，stdout JSON；安装验证不得自动执行。"
        ),
        ["reminders"] => eprintln!(
            "ownmate-mcp reminders schema|validate|list|read|create|update|request-status\n各子命令支持 --help。schema/validate 离线；读取与写入需独立手机范围。写不隐含读，仅 create/update，不完成/删除。"
        ),
        ["reminders", "schema"] => eprintln!(
            "ownmate-mcp reminders schema\n离线输出版本化字段规范、示例、权限和提交说明；不读凭据、不联网。"
        ),
        ["reminders", "validate"] => eprintln!(
            "ownmate-mcp reminders validate create|update --input -\n从 stdin 读取 JSON，仅离线校验；不联网、不写入，不回显标题/正文。规范见 reminders schema。"
        ),
        ["reminders", "list"] => eprintln!(
            "ownmate-mcp reminders list [--filter all|today|overdue|range|noDate] [--status PENDING|COMPLETED] [--time-zone IANA] [--from YYYY-MM-DD --through YYYY-MM-DD]\n需 reminders:read，stdout JSON；会读取内容。"
        ),
        ["reminders", "read"] => eprintln!(
            "ownmate-mcp reminders read ID\n需 reminders:read；读取指定事项并输出 JSON，会读取内容。"
        ),
        ["reminders", "create"] => eprintln!(
            "ownmate-mcp reminders create --input -\n需 reminders:write；stdin JSON，先依 schema/validate 准备，仅提交加密 CREATE。queued 不等于已应用；手机处理结果以回执为准。"
        ),
        ["reminders", "update"] => eprintln!(
            "ownmate-mcp reminders update ID --input -\n需 reminders:write；stdin JSON 要携带完整 expectedVersion 与匹配 ID，依据 schema/validate；冲突不读取补版本。queued 不等于已应用。"
        ),
        ["reminders", "request-status"] => eprintln!(
            "ownmate-mcp reminders request-status REQUEST_ID\n需 reminders:write；只查本请求阶段/回执，不读取事项内容。"
        ),
        ["version" | "--version"] => {
            eprintln!("ownmate-mcp --version\n离线显示版本，不读取凭据/内容、不联网。")
        }
        _ => {
            return Err(McpError::Invalid(
                "帮助路径无效；请运行 ownmate-mcp --help".into(),
            ));
        }
    }
    Ok(())
}

fn print_help() {
    eprintln!("OwnMate CLI/MCP（按手机明确授权）");
    eprintln!(
        "  ownmate-mcp pair [--setup | --serve] [--name NAME] [--base-url URL] [--qr-output FILE.svg]"
    );
    eprintln!("  ownmate-mcp pair status|replace --session RUN_ID [--json]");
    eprintln!("  ownmate-mcp status --json         仅读非敏感本机状态，不证明云端或凭据可用");
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
    eprintln!(
        "每个子命令支持 --help。pair 默认 serve；可信安装用 --setup；临时需要同进程 MCP stdio。"
    );
}

#[cfg(test)]
mod pairing_protocol_tests {
    use super::*;
    const PUBLIC: &str = "c3ludGhldGljX3B1YmxpY19rZXk=";
    const ID1: &str = "external_pairing_00000000-0000-4000-8000-000000000001";
    const SECRET1: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    fn fixture() -> ownmate_mcp::protocol::CreatePairingResponse {
        let modes = vec!["temporary".to_string()];
        let fp = public_fingerprint(PUBLIC).unwrap();
        ownmate_mcp::protocol::CreatePairingResponse {
            protocol_version: 1, pairing_id: ID1.into(),
            pairing_secret: SECRET1.into(),
            verification_code: "123456".into(), client_fingerprint: fp.clone(),
            expires_at: 100, client_ready_version: Some(1), supported_trust_modes: Some(modes.clone()),
            qr_payload: serde_json::json!({"t":"ownmate-external","v":1,"pid":ID1,"name":"Synthetic client",
                "code":"123456","fp":fp,"exp":100,"clientReadyVersion":1,"supportedTrustModes":modes}).to_string(),
        }
    }

    #[test]
    fn legacy_server_is_rejected_before_qr_render_and_negotiation_cannot_expand_modes() {
        let modes = vec!["temporary".into()];
        let mut pairing = fixture();
        assert!(validate_pairing_response(&pairing, &modes, "Synthetic client", PUBLIC, 1).is_ok());
        pairing.client_ready_version = None;
        assert!(
            validate_pairing_response(&pairing, &modes, "Synthetic client", PUBLIC, 1)
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
        assert!(
            validate_pairing_response(&pairing, &modes, "Synthetic client", PUBLIC, 1).is_err()
        );
        let mut pairing = fixture();
        let mut qr: Value = serde_json::from_str(&pairing.qr_payload).unwrap();
        qr["supportedTrustModes"] = serde_json::json!(["temporary", "trusted"]);
        pairing.qr_payload = qr.to_string();
        assert!(
            validate_pairing_response(&pairing, &modes, "Synthetic client", PUBLIC, 1).is_err()
        );
    }

    #[test]
    fn qr_binds_owner_key_name_expiry_and_exact_nonsecret_fields_before_render() {
        let modes = vec!["temporary".into()];
        for mutation in ["unknown", "name", "code", "fp", "expired", "extended", "id"] {
            let mut value = fixture();
            let mut qr: Value = serde_json::from_str(&value.qr_payload).unwrap();
            match mutation {
                "unknown" => qr["hiddenCredential"] = serde_json::json!("PRIVATE_SYNTHETIC_VALUE"),
                "name" => qr["name"] = serde_json::json!("wrong owner"),
                "code" => {
                    value.verification_code = "ABCDEF".into();
                    qr["code"] = serde_json::json!("ABCDEF");
                }
                "fp" => {
                    value.client_fingerprint = "AA:AA:AA:AA:AA:AA".into();
                    qr["fp"] = serde_json::json!("AA:AA:AA:AA:AA:AA");
                }
                "expired" => {
                    value.expires_at = 1;
                    qr["exp"] = serde_json::json!(1);
                }
                "extended" => {
                    value.expires_at = 330_002;
                    qr["exp"] = serde_json::json!(330_002);
                }
                "id" => {
                    value.pairing_id = "other".into();
                    qr["pid"] = serde_json::json!("other");
                }
                _ => unreachable!(),
            }
            value.qr_payload = qr.to_string();
            let error = validate_pairing_response(&value, &modes, "Synthetic client", PUBLIC, 1)
                .unwrap_err();
            assert!(!error.to_string().contains("PRIVATE_SYNTHETIC_VALUE"));
        }
        let svg = render_qr_svg(&fixture().qr_payload).unwrap();
        assert!(svg.contains("shape-rendering=\"crispEdges\""));
        assert!(svg.contains("fill=\"#fff\""));
        assert!(!svg.contains(SECRET1));
        assert_eq!(svg, render_qr_svg(&fixture().qr_payload).unwrap());
    }

    #[test]
    fn setup_serve_and_svg_options_are_explicit_and_conflicting_modes_fail() {
        assert!(!PairOptions::parse(vec![]).unwrap().setup);
        assert!(
            PairOptions::parse(vec![
                "--setup".into(),
                "--qr-output".into(),
                "pair.svg".into()
            ])
            .unwrap()
            .setup
        );
        assert!(PairOptions::parse(vec!["--setup".into(), "--serve".into()]).is_err());
        assert!(PairOptions::parse(vec!["--name".into(), "\nPRIVATE\n".into()]).is_ok()); // trimmed before request
        assert!(PairOptions::parse(vec!["--name".into(), "a\nb".into()]).is_err());
        assert!(PairOptions::parse(vec!["--name".into(), "😀".repeat(41)]).is_err());
    }

    enum Reply {
        Create(u32, u64),
        Json(String, u16, Value),
        Lost(String),
    }
    type Requests = std::sync::Arc<std::sync::Mutex<Vec<(String, Value)>>>;
    fn id(index: u32) -> String {
        format!("external_pairing_00000000-0000-4000-8000-{index:012x}")
    }
    fn secret(index: u32) -> String {
        char::from_u32('A' as u32 + index - 1)
            .unwrap()
            .to_string()
            .repeat(43)
    }
    fn ok(data: Value) -> Value {
        serde_json::json!({"ok":true,"data":data})
    }
    fn failed(code: &str) -> Value {
        serde_json::json!({"ok":false,"message":"PRIVATE_SYNTHETIC_RESPONSE","data":{"code":code}})
    }
    fn exchange(status: &str) -> Value {
        ok(
            serde_json::json!({"protocolVersion":1,"status":status,"clientReadyVersion":1,
        "supportedTrustModes":["temporary"],"clientReadyExpiresAt":1_499_997,"clientReadyAt":null,"scopes":["journals:read"]}),
        )
    }
    fn ex(status: u16, data: Value) -> Reply {
        Reply::Json("/external-access/v1/pairings/exchange".into(), status, data)
    }
    fn cancel(index: u32, status: u16, data: Value) -> Reply {
        Reply::Json(
            format!("/external-access/v1/pairings/{}/cancel", id(index)),
            status,
            data,
        )
    }

    fn fake_pair_server(
        replies: Vec<Reply>,
    ) -> (ExternalApiClient, Requests, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let api =
            ExternalApiClient::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = requests.clone();
        let thread = std::thread::spawn(move || {
            for reply in replies {
                let end = Instant::now() + Duration::from_secs(3);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                && Instant::now() < end =>
                        {
                            std::thread::sleep(Duration::from_millis(1))
                        }
                        _ => panic!("expected synthetic pairing request did not arrive"),
                    }
                };
                // Accepted streams can inherit the listener's nonblocking mode on
                // some platforms. Only accept polling is nonblocking; bounded HTTP
                // reads use a blocking stream and the explicit read timeout below.
                stream.set_nonblocking(false).unwrap();
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
                        let length = header
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .and_then(|v| v.trim().parse::<usize>().ok())
                            })
                            .unwrap();
                        if bytes.len() >= offset + 4 + length {
                            break offset;
                        }
                    }
                };
                let path = String::from_utf8_lossy(&bytes[..offset])
                    .lines()
                    .next()
                    .unwrap()
                    .split_whitespace()
                    .nth(1)
                    .unwrap()
                    .to_owned();
                let body: Value = serde_json::from_slice(&bytes[offset + 4..]).unwrap();
                recorded.lock().unwrap().push((path.clone(), body.clone()));
                let (expected, status, data) = match reply {
                    Reply::Lost(expected) => {
                        assert_eq!(path, expected);
                        continue;
                    }
                    Reply::Json(expected, status, data) => (expected, status, data),
                    Reply::Create(index, expires) => {
                        let fp =
                            public_fingerprint(body["clientPublicKey"].as_str().unwrap()).unwrap();
                        let qr = serde_json::json!({"t":"ownmate-external","v":1,"pid":id(index),"code":"123456","fp":fp,
                            "name":body["clientName"],"exp":expires,"clientReadyVersion":1,"supportedTrustModes":body["supportedTrustModes"]});
                        (
                            "/external-access/v1/pairings".into(),
                            201,
                            ok(
                                serde_json::json!({"protocolVersion":1,"pairingId":id(index),
                            "pairingSecret":secret(index),"verificationCode":"123456","clientFingerprint":fp,"expiresAt":expires,
                            "qrPayload":qr.to_string(),"clientReadyVersion":1,"supportedTrustModes":body["supportedTrustModes"]}),
                            ),
                        )
                    }
                };
                assert_eq!(path, expected);
                let text = data.to_string();
                write!(stream,"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",text.len()).unwrap();
            }
        });
        (api, requests, thread)
    }

    fn synthetic_wait(
        api: &ExternalApiClient,
        now: &std::cell::Cell<u64>,
        deadline: u64,
        generation: &mut u32,
    ) -> Result<(
        PairingIdentity,
        ownmate_mcp::protocol::ExchangePairingResponse,
    )> {
        wait_for_approval(
            api,
            "Synthetic client",
            &["temporary".into()],
            WaitContext {
                owner: &mut None,
                output: &mut None,
                generation,
                expires: &mut None,
                deadline,
            },
            || now.get(),
            |d| now.set(now.get().saturating_add(d.as_millis() as u64)),
        )
    }

    #[test]
    fn expired_unapproved_qr_is_cancel_confirmed_then_new_identity_completes_exchange() {
        let (api, requests, thread) = fake_pair_server(vec![
            Reply::Create(1, 1001),
            ex(202, exchange("pending")),
            cancel(1, 410, failed("EXTERNAL_PAIRING_EXPIRED")),
            Reply::Create(2, 5001),
            ex(200, exchange("awaiting_client")),
        ]);
        let now = std::cell::Cell::new(1);
        let mut generation = 0;
        let (_, response) = synthetic_wait(&api, &now, 900_001, &mut generation).unwrap();
        thread.join().unwrap();
        assert_eq!(generation, 2);
        assert_eq!(response.status, "awaiting_client");
        let requests = requests.lock().unwrap();
        assert_ne!(
            requests[0].1["clientPublicKey"],
            requests[3].1["clientPublicKey"]
        );
        assert_eq!(requests[1].1["pairingSecret"], secret(1));
        assert_eq!(requests[2].1["pairingSecret"], secret(1));
        assert_eq!(requests[4].1["pairingSecret"], secret(2));
    }

    #[test]
    fn approval_wins_near_wait_budget_and_transient_retry_still_uses_original_completion_window() {
        // Virtual deadlines must leave real loopback I/O a useful budget. The 1 ms
        // QR expiry advances virtual time only; HTTP still has ~1 second, not 1 ms.
        let original_ready_deadline = 899_000 + 10 * 60 * 1000;
        let mut approved_response = exchange("awaiting_client");
        approved_response["data"]["clientReadyExpiresAt"] =
            serde_json::json!(original_ready_deadline);
        let (api, requests, thread) = fake_pair_server(vec![
            Reply::Create(1, 899_001),
            ex(202, exchange("pending")),
            cancel(1, 409, failed("EXTERNAL_PAIRING_ALREADY_APPROVED")),
            ex(503, failed("TEMPORARY")),
            ex(200, approved_response),
        ]);
        let now = std::cell::Cell::new(899_000);
        let mut generation = 0;
        let (_, response) = synthetic_wait(&api, &now, 900_000, &mut generation).unwrap();
        thread.join().unwrap();
        assert!(now.get() > 900_000);
        assert_eq!(generation, 1);
        assert_eq!(
            response.client_ready_expires_at,
            Some(original_ready_deadline)
        );
        let requests = requests.lock().unwrap();
        assert_eq!(requests[3].1, requests[4].1);
        assert_eq!(requests.len(), 5);
    }

    #[test]
    fn lost_cancel_reply_retries_same_owner_secret_before_any_new_qr() {
        let (api, requests, thread) = fake_pair_server(vec![
            Reply::Create(1, 1001),
            ex(202, exchange("pending")),
            Reply::Lost(format!("/external-access/v1/pairings/{ID1}/cancel")),
            cancel(
                1,
                200,
                ok(serde_json::json!({"protocolVersion":1,"pairingId":ID1,"status":"cancelled"})),
            ),
            Reply::Create(2, 5001),
            ex(200, exchange("awaiting_client")),
        ]);
        let now = std::cell::Cell::new(1);
        let mut generation = 0;
        synthetic_wait(&api, &now, 900_001, &mut generation).unwrap();
        thread.join().unwrap();
        let requests = requests.lock().unwrap();
        assert_eq!(requests[2], requests[3]);
        assert_eq!(generation, 2);
    }

    #[test]
    fn cancel_denied_or_malformed_ack_does_not_create_or_display_another_qr() {
        for (status, data) in [
            (403, failed("EXTERNAL_PAIRING_SECRET_INVALID")),
            (
                200,
                ok(
                    serde_json::json!({"protocolVersion":1,"pairingId":ID1,"status":"cancelled","secret":"PRIVATE"}),
                ),
            ),
            (
                200,
                ok(
                    serde_json::json!({"protocolVersion":1,"pairingId":"wrong","status":"cancelled"}),
                ),
            ),
        ] {
            let (api, requests, thread) = fake_pair_server(vec![
                Reply::Create(1, 1001),
                ex(202, exchange("pending")),
                cancel(1, status, data),
            ]);
            let now = std::cell::Cell::new(1);
            let mut generation = 0;
            let error = match synthetic_wait(&api, &now, 900_001, &mut generation) {
                Err(error) => error,
                Ok(_) => panic!("cancel failure must not yield a candidate"),
            };
            thread.join().unwrap();
            assert_eq!(generation, 1);
            assert_eq!(requests.lock().unwrap().len(), 3);
            assert!(!error.to_string().contains("PRIVATE"));
        }
    }

    #[test]
    fn renewal_stops_after_three_codes_without_extending_existing_expiries() {
        let mut replies = Vec::new();
        for index in 1..=3 {
            replies.extend([
                Reply::Create(index, index as u64 + 1),
                ex(202, exchange("pending")),
                cancel(index, 410, failed("EXTERNAL_PAIRING_EXPIRED")),
            ]);
        }
        let (api, requests, thread) = fake_pair_server(replies);
        let now = std::cell::Cell::new(1);
        let mut generation = 0;
        assert!(synthetic_wait(&api, &now, 900_001, &mut generation).is_err());
        thread.join().unwrap();
        assert_eq!(generation, 3);
        assert_eq!(now.get(), 4);
        assert_eq!(requests.lock().unwrap().len(), 9);
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
