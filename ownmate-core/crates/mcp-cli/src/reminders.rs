//! Shared reminder application layer for CLI and MCP. No implicit reads on the write path.
use crate::api::{ExternalApiClient, ReadResource, now_millis};
use crate::command_cache::CommandCache;
use crate::protocol::{ReminderCommandEnvelope, ReminderCommandReceipt};
use crate::storage::ExternalSession;
use crate::timezone::{Zone, date_days, date_from_days};
use crate::{McpError, Result};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const MAX_COMMAND_PLAINTEXT_BYTES: usize = 512 * 1024;
const MAX_COMMAND_CIPHERTEXT_BYTES: usize = MAX_COMMAND_PLAINTEXT_BYTES + 16;

pub fn decode_dek(session: &ExternalSession) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = STANDARD
        .decode(&session.dek_base64)
        .map_err(|_| McpError::Crypto)?;
    if bytes.len() != 32 || STANDARD.encode(&bytes) != session.dek_base64 {
        return Err(McpError::Crypto);
    }
    Ok(Zeroizing::new(bytes))
}

pub fn validate_request_id(id: &str) -> Result<()> {
    if !(16..=128).contains(&id.len())
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return Err(invalid("提醒请求标识格式无效"));
    }
    Ok(())
}

pub fn submit(
    api: &ExternalApiClient,
    session: &mut ExternalSession,
    key: &[u8],
    operation: &str,
    input: Value,
) -> Result<Value> {
    session.require_scope("reminders:write")?;
    crate::reminder_interface::validate(operation, input.clone())?;
    let now = now_millis();
    validate_semantics(operation, &input, now)?;
    let request_id = input["requestId"]
        .as_str()
        .ok_or_else(|| invalid("请求缺少标识"))?;
    validate_write_context(session)?;
    let cache = if session.is_trusted() {
        Some(CommandCache::for_grant(
            &session.base_url,
            &session.grant_id,
        )?)
    } else {
        None
    };
    let existing = if let Some(cache) = &cache {
        cache.load(request_id, now)?
    } else {
        session
            .temporary_commands
            .iter()
            .find(|c| c.request_id == request_id)
            .cloned()
    };
    let command = if let Some(existing) = existing {
        existing
    } else {
        // A bounded cache cannot retain IDs forever. Consult only this Grant's receipt
        // mailbox before regenerating an envelope: an already-known ID cannot extend TTL.
        match api.reminder_request_status(session, request_id) {
            Err(McpError::ApiResponse {
                status: 404, code, ..
            }) if code == "REMINDER_REQUEST_NOT_FOUND" => (),
            Err(error) => return Err(error),
            Ok(receipt) => {
                validate_receipt(&receipt, request_id)?;
                return Err(invalid(
                    "本 Grant 已有该 requestId，但本机原密文不可用；请查询原回执，不能重新生成或延长期限",
                ));
            }
        }
        let mut nonce = [0_u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let created = encrypt_command(session, operation, &input, key, now, nonce)?;
        if let Some(cache) = &cache {
            cache.store(&created, now)?
        } else {
            session.temporary_commands.retain(|c| c.expires_at > now);
            if session.temporary_commands.len() >= 512 {
                return Err(invalid("临时会话密文请求缓存已满"));
            }
            session.temporary_commands.push(created.clone());
            created
        }
    };
    validate_cached_command(session, operation, &input, key, &command, now)?;
    let receipt = api.submit_reminder_command(session, &command)?;
    validate_receipt(&receipt, request_id)?;
    if receipt.target_reminder_id != command.target_reminder_id
        || receipt.operation != command.operation
        || receipt.expires_at != command.expires_at
    {
        return Err(invalid("提醒操作响应身份不匹配"));
    }
    Ok(serde_json::to_value(receipt)?)
}

pub fn validate_write_context(session: &ExternalSession) -> Result<()> {
    session.require_scope("reminders:write")?;
    let context = session
        .write_context
        .as_ref()
        .ok_or_else(|| invalid("原授权不包含提醒写身份；请重新扫码批准"))?;
    if context.capability_version != 1
        || context.keyspace_id.is_empty()
        || context.keyspace_id.contains(['\n', '\u{1f}'])
        || context.target_device_id.is_empty()
        || context.target_device_id.contains('\u{1f}')
        || session.keyspace() != Some((context.keyspace_id.as_str(), context.keyspace_generation))
        || context.actions.len() != 2
        || !context.actions.iter().any(|a| a == "CREATE")
        || !context.actions.iter().any(|a| a == "UPDATE")
        || context.policy["commandTtlMs"].as_u64() != Some(86_400_000)
        || context.policy["dateHorizonDays"].as_u64() != Some(90)
        || context.policy["datePolicy"].as_str() != Some("today_through_90_days")
    {
        return Err(invalid("提醒写授权身份或策略不兼容"));
    }
    Ok(())
}

pub fn command_aad(command: &ReminderCommandEnvelope) -> Vec<u8> {
    [
        "OwnMate ReminderCommand v1",
        &command.grant_id,
        &command.request_id,
        &command.operation,
        &command.keyspace_id,
        &command.keyspace_generation.to_string(),
        &command.target_device_id,
        &command.target_reminder_id,
        &command.created_at.to_string(),
        &command.expires_at.to_string(),
        &command.key_id,
    ]
    .join("\u{1f}")
    .into_bytes()
}

fn encrypt_command(
    session: &ExternalSession,
    operation: &str,
    input: &Value,
    key: &[u8],
    now: u64,
    nonce: [u8; 12],
) -> Result<ReminderCommandEnvelope> {
    validate_write_context(session)?;
    let context = session
        .write_context
        .as_ref()
        .ok_or_else(|| invalid("缺少写授权身份"))?;
    let request_id = input["requestId"]
        .as_str()
        .ok_or_else(|| invalid("缺少请求标识"))?;
    let target = match operation {
        "create" => format!(
            "r_ext_{:x}",
            Sha256::digest(format!("{}\n{request_id}", session.grant_id).as_bytes())
        ),
        "update" => input["reminderId"]
            .as_str()
            .ok_or_else(|| invalid("缺少事项标识"))?
            .to_owned(),
        _ => return Err(invalid("不支持此提醒操作")),
    };
    let expires = now
        .saturating_add(86_400_000)
        .min(session.grant_expires_at.unwrap_or(u64::MAX));
    if expires <= now {
        return Err(invalid("提醒写授权已到期"));
    }
    let mut envelope = ReminderCommandEnvelope {
        protocol_version: 1,
        request_id: request_id.into(),
        operation: operation.to_ascii_uppercase(),
        grant_id: session.grant_id.clone(),
        keyspace_id: context.keyspace_id.clone(),
        keyspace_generation: context.keyspace_generation,
        target_device_id: context.target_device_id.clone(),
        target_reminder_id: target,
        created_at: now,
        expires_at: expires,
        key_id: session.dek_key_id.clone(),
        algorithm: "AES-256-GCM".into(),
        encryption_version: 1,
        nonce: STANDARD.encode(nonce),
        ciphertext: String::new(),
    };
    let plaintext = Zeroizing::new(serde_json::to_vec(input)?);
    if plaintext.len() > MAX_COMMAND_PLAINTEXT_BYTES {
        return Err(invalid("加密指令超过长度限制"));
    }
    let ciphertext = Aes256Gcm::new_from_slice(key)
        .map_err(|_| McpError::Crypto)?
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &command_aad(&envelope),
            },
        )
        .map_err(|_| McpError::Crypto)?;
    envelope.ciphertext = STANDARD.encode(ciphertext);
    Ok(envelope)
}

fn validate_cached_command(
    session: &ExternalSession,
    operation: &str,
    input: &Value,
    key: &[u8],
    envelope: &ReminderCommandEnvelope,
    now: u64,
) -> Result<()> {
    let context = session
        .write_context
        .as_ref()
        .ok_or_else(|| invalid("缺少写授权身份"))?;
    if envelope.protocol_version != 1
        || envelope.operation != operation.to_ascii_uppercase()
        || envelope.grant_id != session.grant_id
        || envelope.keyspace_id != context.keyspace_id
        || envelope.keyspace_generation != context.keyspace_generation
        || envelope.target_device_id != context.target_device_id
        || envelope.key_id != session.dek_key_id
        || envelope.algorithm != "AES-256-GCM"
        || envelope.encryption_version != 1
        || envelope.expires_at <= now
        || envelope.expires_at <= envelope.created_at
        || envelope.expires_at - envelope.created_at > 86_400_000
        || session
            .grant_expires_at
            .is_some_and(|expiry| envelope.expires_at > expiry)
    {
        return Err(invalid("原密文请求身份不符或已过期"));
    }
    let nonce = STANDARD
        .decode(&envelope.nonce)
        .map_err(|_| McpError::Crypto)?;
    let ciphertext = STANDARD
        .decode(&envelope.ciphertext)
        .map_err(|_| McpError::Crypto)?;
    if nonce.len() != 12 || !(17..=MAX_COMMAND_CIPHERTEXT_BYTES).contains(&ciphertext.len()) {
        return Err(McpError::Crypto);
    }
    let plain = Zeroizing::new(
        Aes256Gcm::new_from_slice(key)
            .map_err(|_| McpError::Crypto)?
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &command_aad(envelope),
                },
            )
            .map_err(|_| McpError::Crypto)?,
    );
    let original: Value = serde_json::from_slice(&plain).map_err(|_| McpError::Crypto)?;
    if &original != input {
        return Err(invalid("同一 requestId 不能更换操作或内容；请查询原回执"));
    }
    Ok(())
}

pub fn validate_semantics(operation: &str, input: &Value, now: u64) -> Result<()> {
    if operation == "update" {
        let version = input["expectedVersion"]
            .as_str()
            .ok_or_else(|| invalid("缺少提醒版本"))?;
        if version.len() != 68
            || !version.starts_with("rv1:")
            || !version[4..]
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(invalid(
                "提醒版本必须原样使用读取或本次已应用回执给出的 rv1 标记",
            ));
        }
    }
    let fields = if operation == "create" {
        input
    } else {
        &input["patch"]
    };
    if fields["due"]["kind"] == "none" && fields["recurrence"].as_str().is_some_and(|r| r != "NONE")
    {
        return Err(invalid("无日期提醒不能设置重复规则"));
    }
    let due = &fields["due"];
    if due.is_null() || due["kind"] == "none" {
        return Ok(());
    }
    let date = if due["kind"] == "date" {
        due["date"].as_str()
    } else {
        due["at"].as_str().and_then(|at| at.get(..10))
    }
    .ok_or_else(|| invalid("提醒日期无效"))?;
    let day = date_days(date)?;
    let zone_name = due["timeZone"]
        .as_str()
        .ok_or_else(|| invalid("提醒时区无效"))?;
    if let Ok(zone) = Zone::load(zone_name) {
        let today = date_days(&zone.local_date(now)?)?;
        if day < today || day > today + 90 {
            return Err(invalid("提醒日期必须在所选时区的今天至未来 90 天内"));
        }
        if due["kind"] == "dateTime" {
            zone.validate_local_datetime(
                due["at"].as_str().ok_or_else(|| invalid("提醒时间无效"))?,
            )?;
        }
    } else {
        // No database is bundled. A narrow UTC envelope rejects distant dates; the phone
        // remains authoritative for the exact IANA day/offset, including boundary dates.
        let utc_today = i64::try_from(now / 86_400_000).map_err(|_| invalid("当前日期超限"))?;
        if day < utc_today - 1 || day > utc_today + 91 {
            return Err(invalid("提醒日期超出今天至未来 90 天的可能时区范围"));
        }
    }
    Ok(())
}

pub fn request_status(
    api: &ExternalApiClient,
    session: &mut ExternalSession,
    request_id: &str,
) -> Result<Value> {
    session.require_scope("reminders:write")?;
    validate_request_id(request_id)?;
    validate_write_context(session)?;
    let receipt = api.reminder_request_status(session, request_id)?;
    validate_receipt(&receipt, request_id)?;
    Ok(serde_json::to_value(receipt)?)
}

fn validate_receipt(receipt: &ReminderCommandReceipt, request_id: &str) -> Result<()> {
    if receipt.protocol_version != 1
        || receipt.request_id != request_id
        || !["CREATE", "UPDATE"].contains(&receipt.operation.as_str())
        || !["queued", "applied", "rejected", "conflict", "expired"]
            .contains(&receipt.status.as_str())
        || ![
            "unknown",
            "pending",
            "permission_blocked",
            "permission_denied",
            "unscheduled",
            "scheduled",
            "disabled",
            "failed",
            "not_needed",
        ]
        .contains(&receipt.notification_status.as_str())
        || ![
            "unknown",
            "pending",
            "visible",
            "conflict",
            "failed",
            "not_applicable",
        ]
        .contains(&receipt.sync_visibility.as_str())
        || receipt.status != "applied"
            && (receipt.result_version.is_some() || receipt.applied_at.is_some())
    {
        return Err(invalid("提醒回执身份或阶段无效"));
    }
    for id in [&receipt.command_id, &receipt.target_reminder_id] {
        if id.is_empty()
            || id.len() > 160
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
        {
            return Err(invalid("提醒回执标识无效"));
        }
    }
    if receipt.rejection_code.as_ref().is_some_and(|code| {
        code.is_empty()
            || code.len() > 80
            || !code
                .bytes()
                .all(|b| b.is_ascii_alphabetic() || b.is_ascii_digit() || b == b'_')
    }) || receipt.operation_status.as_ref().is_some_and(|s| {
        !["queued", "applied", "rejected", "conflict", "expired"].contains(&s.as_str())
    }) || receipt.result_version.as_ref().is_some_and(|v| {
        v.len() != 68
            || !v.starts_with("rv1:")
            || !v[4..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }) {
        return Err(invalid("提醒回执含不兼容的结果字段"));
    }
    Ok(())
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReminderListQuery {
    pub filter: Option<String>,
    pub status: Option<String>,
    pub time_zone: Option<String>,
    pub from: Option<String>,
    pub through: Option<String>,
}

type QueryBounds = (Option<Zone>, Option<(u64, u64)>);

impl ReminderListQuery {
    pub fn parse(value: Value) -> Result<Self> {
        serde_json::from_value(value).map_err(|_| invalid("提醒查询参数无效"))
    }
    pub fn cli(args: Vec<String>) -> Result<Self> {
        let mut value = json!({});
        let mut args = args.into_iter();
        while let Some(flag) = args.next() {
            let key = match flag.as_str() {
                "--filter" => "filter",
                "--status" => "status",
                "--time-zone" => "timeZone",
                "--from" => "from",
                "--through" => "through",
                _ => return Err(invalid("未知提醒查询参数")),
            };
            if value.get(key).is_some() {
                return Err(invalid("重复提醒查询参数"));
            }
            value[key] = json!(
                args.next()
                    .filter(|v| !v.starts_with("--"))
                    .ok_or_else(|| invalid("提醒查询参数缺少值"))?
            );
        }
        Self::parse(value)
    }

    fn bounds(&self, now: u64) -> Result<QueryBounds> {
        let filter = self.filter.as_deref().unwrap_or("all");
        if !["all", "today", "overdue", "range", "noDate"].contains(&filter)
            || self
                .status
                .as_deref()
                .is_some_and(|s| !["PENDING", "COMPLETED"].contains(&s))
        {
            return Err(invalid("提醒筛选或状态无效"));
        }
        if filter != "range" && (self.from.is_some() || self.through.is_some()) {
            return Err(invalid("日期参数仅适用于 range 查询"));
        }
        let zone = self.time_zone.as_deref().map(Zone::load).transpose()?;
        if ["today", "overdue", "range"].contains(&filter) && zone.is_none() {
            return Err(invalid("今日、逾期与范围查询必须显式给出 IANA timeZone"));
        }
        let bounds = if filter == "today" {
            let zone = zone.as_ref().ok_or_else(|| invalid("缺少时区"))?;
            let day = zone.local_date(now)?;
            let next = date_from_days(date_days(&day)? + 1);
            Some((zone.day_start(&day)?, zone.day_start(&next)?))
        } else if filter == "range" {
            let from = self
                .from
                .as_deref()
                .ok_or_else(|| invalid("range 需要 from 和 through 日期"))?;
            let through = self
                .through
                .as_deref()
                .ok_or_else(|| invalid("range 需要 from 和 through 日期"))?;
            let first = date_days(from)?;
            let last = date_days(through)?;
            if first > last || last - first > 3660 {
                return Err(invalid("提醒日期范围无效或过大"));
            }
            let zone = zone.as_ref().ok_or_else(|| invalid("缺少时区"))?;
            Some((
                zone.day_start(from)?,
                zone.day_start(&date_from_days(last + 1))?,
            ))
        } else {
            None
        };
        Ok((zone, bounds))
    }
}

pub fn list(
    api: &ExternalApiClient,
    session: &mut ExternalSession,
    key: &[u8],
    query: ReminderListQuery,
) -> Result<Value> {
    session.require_scope("reminders:read")?;
    let evaluated_at = now_millis();
    let (zone, bounds) = query.bounds(evaluated_at)?;
    let items = api.list_resources(session, ReadResource::Reminder)?;
    let total = items.len();
    let fetched_at = now_millis();
    let mut selected = Vec::new();
    for item in items {
        let mut record = crate::projection::decrypt_projection_with_keyspace(
            ReadResource::Reminder,
            &item,
            &session.dek_key_id,
            key,
            session.keyspace(),
        )?;
        record["resourceUri"] = json!(crate::mcp::typed_resource_uri(
            ReadResource::Reminder,
            &item.entry_id
        ));
        let row = &record["record"];
        let due = row["dueAtMillis"].as_u64();
        if query
            .status
            .as_deref()
            .is_some_and(|status| row["status"] != status)
        {
            continue;
        }
        let matches = match query.filter.as_deref().unwrap_or("all") {
            "noDate" => due.is_none(),
            "today" | "range" => due
                .zip(bounds)
                .is_some_and(|(due, (start, end))| due >= start && due < end),
            "overdue" => {
                if row["status"] != "PENDING" {
                    false
                } else if let Some(due) = due {
                    if due % 1000 == 1 {
                        let zone = zone.as_ref().ok_or_else(|| invalid("缺少时区"))?;
                        zone.local_date(due)? < zone.local_date(evaluated_at)?
                    } else {
                        due < evaluated_at
                    }
                } else {
                    false
                }
            }
            _ => true,
        };
        if matches {
            selected.push(record);
        }
    }
    Ok(
        json!({"coverage":{"requiredScope":"reminders:read","allPagesRead":true,"cloudResourceCount":total,"returnedCount":selected.len(),
        "consistentSnapshot":false,"phoneLastSyncedAt":null,"fetchedAt":fetched_at,"evaluatedAt":evaluated_at,"timeZone":query.time_zone,
        "rangeStartInclusive":bounds.map(|v|v.0),"rangeEndExclusive":bounds.map(|v|v.1),"filter":query.filter.unwrap_or_else(||"all".into()),
        "unavailable":["unsyncedPhoneChanges"],"snapshotNote":"Cloud pagination has no stable snapshot token; phone unsynced changes are not included."},"reminders":selected}),
    )
}

pub fn read(
    api: &ExternalApiClient,
    session: &mut ExternalSession,
    key: &[u8],
    id: &str,
) -> Result<Value> {
    session.require_scope("reminders:read")?;
    let item = api.get_resource(session, ReadResource::Reminder, id)?;
    let mut reminder = crate::projection::decrypt_projection_with_keyspace(
        ReadResource::Reminder,
        &item,
        &session.dek_key_id,
        key,
        session.keyspace(),
    )?;
    reminder["resourceUri"] = json!(crate::mcp::typed_resource_uri(ReadResource::Reminder, id));
    let mut history = Vec::new();
    for item in api.list_resources(session, ReadResource::ReminderCompletion)? {
        let mut projected = crate::projection::decrypt_projection(
            ReadResource::ReminderCompletion,
            &item,
            &session.dek_key_id,
            key,
        )?;
        if projected["record"]["reminderId"] == id {
            projected["resourceUri"] = json!(crate::mcp::typed_resource_uri(
                ReadResource::ReminderCompletion,
                &item.entry_id
            ));
            history.push(projected);
        }
    }
    Ok(
        json!({"reminder":reminder,"history":history,"coverage":{"allHistoryPagesRead":true,"consistentSnapshot":false,"phoneLastSyncedAt":null,"fetchedAt":now_millis(),"unavailable":["unsyncedPhoneChanges"]}}),
    )
}

fn invalid(message: &str) -> McpError {
    McpError::Invalid(message.into())
}

#[cfg(test)]
pub(crate) fn fixture_envelope() -> ReminderCommandEnvelope {
    encrypt_command(&fixture_session(), "create", &json!({"requestId":"fixture_request_001","title":"fixture title","due":{"kind":"none"},"recurrence":"NONE"}), &[7;32], 1_800_000_000_000, [9;12]).unwrap()
}

#[cfg(test)]
pub(crate) fn fixture_session() -> ExternalSession {
    ExternalSession {
        protocol_version: 1,
        base_url: "http://127.0.0.1:1".into(),
        grant_id: "fixture_grant".into(),
        trust_mode: "temporary".into(),
        access_token: "REDACTED_SYNTHETIC_ACCESS_TOKEN".into(), // git-guard: ignore — synthetic test-only placeholder
        access_expires_at: u64::MAX,
        refresh_token: None,
        grant_expires_at: Some(u64::MAX),
        dek_key_id: "ownmate_dek_v1".into(),
        dek_base64: STANDARD.encode([7; 32]),
        keyspace_id: Some("fixture_space".into()),
        keyspace_generation: Some(3),
        scopes: vec!["reminders:write".into()],
        temporary_commands: vec![],
        write_context: Some(crate::protocol::ReminderWriteContext {
            capability_version: 1,
            keyspace_id: "fixture_space".into(),
            keyspace_generation: 3,
            target_device_id: "fixture_phone".into(),
            actions: vec!["CREATE".into(), "UPDATE".into()],
            policy: json!({"commandTtlMs":86400000,"dateHorizonDays":90,"datePolicy":"today_through_90_days"}),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn maximum_notes_survive_encryption_and_cached_retry() {
        let session = fixture_session();
        for notes in ["汉".repeat(65_536), "\u{0001}".repeat(65_536)] {
            let input = json!({"requestId":"fixture_request_001","title":"fixture title",
                "notes":notes,"due":{"kind":"none"},"recurrence":"NONE"});
            assert!(crate::reminder_interface::validate("create", input.clone()).is_ok());
            let envelope =
                encrypt_command(&session, "create", &input, &[7; 32], 1_000, [9; 12]).unwrap();
            assert!(
                validate_cached_command(&session, "create", &input, &[7; 32], &envelope, 1_000)
                    .is_ok()
            );
            assert!(
                STANDARD.decode(&envelope.ciphertext).unwrap().len()
                    <= MAX_COMMAND_CIPHERTEXT_BYTES
            );
        }
        let too_large = json!({"requestId":"fixture_request_001","title":"fixture title",
            "notes":"x".repeat(MAX_COMMAND_PLAINTEXT_BYTES),"due":{"kind":"none"},"recurrence":"NONE"});
        assert!(encrypt_command(&session, "create", &too_large, &[7; 32], 1_000, [9; 12]).is_err());
    }

    fn fake_api(
        count: usize,
        respond: impl Fn(usize, &str, &Value) -> (u16, Value) + Send + 'static,
    ) -> (ExternalApiClient, std::thread::JoinHandle<Vec<Value>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let api =
            ExternalApiClient::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let task = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for index in 0..count {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut bytes = Vec::new();
                let mut chunk = [0; 4096];
                let split = loop {
                    let n = stream.read(&mut chunk).unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                        break pos + 4;
                    }
                };
                let headers = std::str::from_utf8(&bytes[..split]).unwrap().to_owned();
                let length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                while bytes.len() < split + length {
                    let n = stream.read(&mut chunk).unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&chunk[..n]);
                }
                let body = if length == 0 {
                    Value::Null
                } else {
                    serde_json::from_slice(&bytes[split..split + length]).unwrap()
                };
                let (status, response) = respond(index, headers.lines().next().unwrap(), &body);
                let text = serde_json::to_string(&response).unwrap();
                write!(stream,"HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nRetry-After: 7\r\n\r\n{text}",text.len()).unwrap();
                requests.push(body);
            }
            requests
        });
        (api, task)
    }

    fn queued_receipt(envelope: &Value) -> Value {
        json!({"protocolVersion":1,"commandId":"fixture_command","requestId":envelope["requestId"],"targetReminderId":envelope["targetReminderId"],"operation":envelope["operation"],"status":"queued","expiresAt":envelope["expiresAt"],"operationStatus":null,"resultVersion":null,"appliedAt":null,"rejectionCode":null,"notificationStatus":"pending","syncVisibility":"pending"})
    }

    #[test]
    fn fake_api_429_does_not_retry_and_next_call_reuses_original_ciphertext() {
        let (api, task) = fake_api(3, |index, path, body| {
            if index == 0 {
                assert_eq!(
                    path,
                    "GET /external-access/v1/reminder-commands/fixture_request_001 HTTP/1.1"
                );
                return (
                    404,
                    json!({"ok":false,"data":{"code":"REMINDER_REQUEST_NOT_FOUND"},"message":"Request not found"}),
                );
            }
            assert_eq!(path, "POST /external-access/v1/reminder-commands HTTP/1.1");
            if index == 1 {
                (
                    429,
                    json!({"ok":false,"message":"rate limited","retryAfter":7}),
                )
            } else {
                let mut receipt = queued_receipt(body);
                receipt["title"] = json!("server-private-content");
                (200, json!({"ok":true,"data":receipt}))
            }
        });
        let mut session = fixture_session();
        let input = json!({"requestId":"fixture_request_001","title":"fixture title","due":{"kind":"none"},"recurrence":"NONE"});
        let error = submit(&api, &mut session, &[7; 32], "create", input.clone()).unwrap_err();
        assert!(matches!(
            error,
            McpError::RateLimited {
                retry_after_seconds: 7
            }
        ));
        assert_eq!(session.temporary_commands.len(), 1);
        let receipt = submit(&api, &mut session, &[7; 32], "create", input.clone()).unwrap();
        assert_eq!(receipt["status"], "queued");
        assert!(!receipt.to_string().contains("server-private-content"));
        let requests = task.join().unwrap();
        assert_eq!(requests[1], requests[2]);
        let mut changed = input;
        changed["title"] = json!("changed");
        assert!(submit(&api, &mut session, &[7; 32], "create", changed).is_err());
    }

    #[test]
    fn fake_api_get_receipt_never_returns_existing_reminder_or_conflict_version() {
        let (api, task) = fake_api(1, |_, path, _| {
            assert_eq!(
                path,
                "GET /external-access/v1/reminder-commands/fixture_request_001 HTTP/1.1"
            );
            let mut receipt = queued_receipt(&serde_json::to_value(fixture_envelope()).unwrap());
            receipt["status"] = json!("conflict");
            receipt["operationStatus"] = json!("conflict");
            receipt["rejectionCode"] = json!("VERSION_CONFLICT");
            receipt["reminder"] = json!({"title":"secret current reminder","expectedVersion":"secret current version"});
            (200, json!({"ok":true,"data":receipt}))
        });
        let output = request_status(&api, &mut fixture_session(), "fixture_request_001").unwrap();
        assert_eq!(output["status"], "conflict");
        assert!(!output.to_string().contains("secret"));
        assert!(output["resultVersion"].is_null());
        task.join().unwrap();
    }

    #[test]
    fn missing_local_envelope_cannot_recreate_a_known_server_request_or_extend_ttl() {
        let (api, task) = fake_api(1, |_, path, _| {
            assert!(path.starts_with("GET /external-access/v1/reminder-commands/"));
            (
                200,
                json!({"ok":true,"data":queued_receipt(&serde_json::to_value(fixture_envelope()).unwrap())}),
            )
        });
        let mut session = fixture_session();
        let input = json!({"requestId":"fixture_request_001","title":"fixture title","due":{"kind":"none"},"recurrence":"NONE"});
        assert!(submit(&api, &mut session, &[7; 32], "create", input).is_err());
        assert!(session.temporary_commands.is_empty());
        task.join().unwrap();
    }

    fn encrypted_reminder(id: &str, due: Option<u64>) -> Value {
        let payload = json!({"payloadVersion":2,"resourceType":"reminder","reminder":{"id":id,"title":"fixture","notes":"","dueAtMillis":due,"recurrence":"NONE","status":"PENDING","completedAtMillis":null,"createdAt":1,"updatedAt":2,"schedulingDeviceId":"fixture_phone","completionCycle":0}});
        let ciphertext = Aes256Gcm::new_from_slice(&[7; 32])
            .unwrap()
            .encrypt(
                Nonce::from_slice(&[9; 12]),
                Payload {
                    msg: &serde_json::to_vec(&payload).unwrap(),
                    aad: format!("ownmate.sync.v2\nentryId={id}").as_bytes(),
                },
            )
            .unwrap();
        json!({"entryId":id,"keyId":"ownmate_dek_v1","ciphertext":STANDARD.encode(ciphertext),"nonce":STANDARD.encode([9;12]),"algorithm":"AES-256-GCM","encryptionVersion":1,"revision":3,"journalSchemaVersion":0,"serverUpdatedAt":4})
    }

    #[test]
    fn fake_api_reads_all_pages_before_filter_and_reports_no_stable_snapshot() {
        let (api, task) = fake_api(2, |index, path, _| {
            if index == 0 {
                assert_eq!(path, "GET /external-access/v1/reminders?limit=200 HTTP/1.1");
            } else {
                assert_eq!(
                    path,
                    "GET /external-access/v1/reminders?limit=200&cursor=next HTTP/1.1"
                );
            }
            (
                200,
                json!({"ok":true,"data":{"protocolVersion":1,"items":[encrypted_reminder(if index==0{"dated"}else{"undated"},if index==0{Some(100)}else{None})],"hasMore":index==0,"nextCursor":if index==0{Some("next")}else{None}}}),
            )
        });
        let mut session = fixture_session();
        session.scopes = vec!["reminders:read".into()];
        let output = list(
            &api,
            &mut session,
            &[7; 32],
            ReminderListQuery::parse(json!({"filter":"noDate"})).unwrap(),
        )
        .unwrap();
        assert_eq!(output["coverage"]["cloudResourceCount"], 2);
        assert_eq!(output["reminders"].as_array().unwrap().len(), 1);
        assert_eq!(output["reminders"][0]["resourceId"], "undated");
        assert!(
            output["reminders"][0]["expectedVersion"]
                .as_str()
                .unwrap()
                .starts_with("rv1:")
        );
        assert_eq!(output["coverage"]["consistentSnapshot"], false);
        assert!(output["coverage"]["phoneLastSyncedAt"].is_null());
        task.join().unwrap();
    }
    #[test]
    fn command_authenticates_every_routing_field_and_never_changes_a_retry() {
        let session = fixture_session();
        let envelope = fixture_envelope();
        let fixture: Value =
            serde_json::from_str(include_str!("reminder-command-fixture-v1.json")).unwrap();
        assert_eq!(
            serde_json::to_value(&envelope).unwrap(),
            fixture["envelope"]
        );
        let payload = fixture["reminderPayloadJson"].as_str().unwrap();
        assert_eq!(
            crate::projection::reminder_expected_version(
                "fixture_space",
                3,
                "fixture",
                payload.as_bytes()
            ),
            fixture["expectedVersion"]
        );
        let input = json!({"requestId":"fixture_request_001","title":"fixture title","due":{"kind":"none"},"recurrence":"NONE"});
        assert!(
            validate_cached_command(
                &session,
                "create",
                &input,
                &[7; 32],
                &envelope,
                envelope.created_at
            )
            .is_ok()
        );
        let mut changed = input.clone();
        changed["title"] = json!("other");
        assert!(
            validate_cached_command(
                &session,
                "create",
                &changed,
                &[7; 32],
                &envelope,
                envelope.created_at
            )
            .is_err()
        );
        for field in [
            "requestId",
            "grantId",
            "operation",
            "keyspaceId",
            "targetDeviceId",
            "targetReminderId",
            "keyId",
        ] {
            let mut value = serde_json::to_value(&envelope).unwrap();
            value[field] = json!("tampered");
            let changed: ReminderCommandEnvelope = serde_json::from_value(value).unwrap();
            assert!(
                validate_cached_command(
                    &session,
                    "create",
                    &input,
                    &[7; 32],
                    &changed,
                    envelope.created_at
                )
                .is_err()
            );
        }
        for field in ["keyspaceGeneration", "createdAt", "expiresAt"] {
            let mut value = serde_json::to_value(&envelope).unwrap();
            value[field] = json!(value[field].as_u64().unwrap() - 1);
            let changed: ReminderCommandEnvelope = serde_json::from_value(value).unwrap();
            assert!(
                validate_cached_command(
                    &session,
                    "create",
                    &input,
                    &[7; 32],
                    &changed,
                    envelope.created_at
                )
                .is_err()
            );
        }
        assert!(
            validate_cached_command(
                &session,
                "create",
                &input,
                &[7; 32],
                &envelope,
                envelope.expires_at
            )
            .is_err()
        );
    }

    #[test]
    fn temporary_grant_caps_command_expiry_and_version_must_be_an_actual_token() {
        let mut session = fixture_session();
        let now = 1_800_000_000_000;
        session.grant_expires_at = Some(now + 1000);
        let input = json!({"requestId":"fixture_request_001","title":"fixture title","due":{"kind":"none"},"recurrence":"NONE"});
        assert_eq!(
            encrypt_command(&session, "create", &input, &[7; 32], now, [9; 12])
                .unwrap()
                .expires_at,
            now + 1000
        );
        session.grant_expires_at = Some(now);
        assert!(encrypt_command(&session, "create", &input, &[7; 32], now, [9; 12]).is_err());
        assert!(
            validate_semantics(
                "update",
                &json!({"expectedVersion":"invented-version-1234","patch":{"notes":""}}),
                now
            )
            .is_err()
        );
    }
    #[test]
    fn write_only_cannot_read_and_missing_context_cannot_write() {
        let api = ExternalApiClient::new("http://127.0.0.1:1").unwrap();
        let mut session = fixture_session();
        assert!(list(&api, &mut session, &[7; 32], ReminderListQuery::default()).is_err());
        assert!(read(&api, &mut session, &[7; 32], "fixture").is_err());
        session.write_context = None;
        assert!(request_status(&api, &mut session, "fixture_request_001").is_err());
    }
    #[test]
    fn date_horizon_and_combination_are_preflighted_without_phone() {
        let now = 1_791_072_000_000;
        for date in ["2020-01-01", "2099-01-01"] {
            let input = json!({"due":{"kind":"date","date":date,"timeZone":"Unknown/Zone"},"recurrence":"NONE"});
            assert!(validate_semantics("create", &input, now).is_err());
        }
        assert!(
            validate_semantics(
                "create",
                &json!({"due":{"kind":"none"},"recurrence":"DAILY"}),
                now
            )
            .is_err()
        );
        assert!(ReminderListQuery::parse(json!({"unknown":true})).is_err());
        assert!(
            ReminderListQuery::parse(json!({"filter":"today"}))
                .unwrap()
                .bounds(now)
                .is_err()
        );
    }
}
