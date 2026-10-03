use crate::{McpError, Result};
use serde_json::{Map, Value, json};

const CREATE_FIELDS: &[&str] = &["requestId", "title", "notes", "due", "recurrence"];
const UPDATE_FIELDS: &[&str] = &["requestId", "reminderId", "expectedVersion", "patch"];
const PATCH_FIELDS: &[&str] = &["title", "notes", "due", "recurrence"];
const RECURRENCES: &[&str] = &["NONE", "DAILY", "WEEKLY"];

pub fn contract() -> Result<Value> {
    Ok(serde_json::from_str(include_str!(
        "reminder-interface-v1.json"
    ))?)
}

pub fn validate(operation: &str, value: Value) -> Result<Value> {
    let object = require_object(&value)?;
    match operation {
        "create" => validate_create(object)?,
        "update" => validate_update(object)?,
        _ => return Err(invalid("不支持此提醒操作")),
    }
    Ok(json!({
        "status": "shape_valid",
        "operation": operation,
        "checksPending": [
            "authorization", "timeZoneResolution", "currentReminderVersion", "phoneApplication"
        ],
        "submitted": false
    }))
}

fn validate_create(object: &Map<String, Value>) -> Result<()> {
    require_allowed_fields(object, CREATE_FIELDS)?;
    require_identifier(required(object, "requestId")?, 16, &[])?;
    validate_title(required(object, "title")?)?;
    if let Some(notes) = object.get("notes") {
        validate_notes(notes)?;
    }
    let due_kind = validate_due(required(object, "due")?)?;
    let recurrence = validate_recurrence(required(object, "recurrence")?)?;
    if due_kind == "none" && recurrence != "NONE" {
        return Err(invalid("无日期提醒不能设置重复规则"));
    }
    Ok(())
}

fn validate_update(object: &Map<String, Value>) -> Result<()> {
    require_allowed_fields(object, UPDATE_FIELDS)?;
    require_identifier(required(object, "requestId")?, 16, &[])?;
    require_identifier(required(object, "reminderId")?, 1, b".:")?;
    let version = require_string(required(object, "expectedVersion")?)?;
    if !(16..=1024).contains(&version.len()) || !version.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(invalid("提醒版本标记格式无效"));
    }
    let patch = require_object(required(object, "patch")?)?;
    require_allowed_fields(patch, PATCH_FIELDS)?;
    if patch.is_empty() {
        return Err(invalid("提醒修改不能为空"));
    }
    if let Some(title) = patch.get("title") {
        validate_title(title)?;
    }
    if let Some(notes) = patch.get("notes") {
        validate_notes(notes)?;
    }
    if let Some(due) = patch.get("due") {
        validate_due(due)?;
    }
    if let Some(recurrence) = patch.get("recurrence") {
        validate_recurrence(recurrence)?;
    }
    // The phone must combine this patch with the current reminder before checking semantics.
    Ok(())
}

fn validate_title(value: &Value) -> Result<()> {
    let title = require_string(value)?;
    if title.trim().is_empty() || title.encode_utf16().count() > 200 {
        return Err(invalid("提醒标题为空或超过长度限制"));
    }
    Ok(())
}

fn validate_notes(value: &Value) -> Result<()> {
    if require_string(value)?.encode_utf16().count() > 65_536 {
        return Err(invalid("提醒备注超过长度限制"));
    }
    Ok(())
}

fn validate_recurrence(value: &Value) -> Result<&str> {
    let recurrence = require_string(value)?;
    if !RECURRENCES.contains(&recurrence) {
        return Err(invalid("提醒重复规则无效"));
    }
    Ok(recurrence)
}

fn validate_due(value: &Value) -> Result<&str> {
    let object = require_object(value)?;
    let kind = require_string(required(object, "kind")?)?;
    match kind {
        "none" => require_allowed_fields(object, &["kind"])?,
        "date" => {
            require_allowed_fields(object, &["kind", "date", "timeZone"])?;
            if !crate::query::valid_date(require_string(required(object, "date")?)?) {
                return Err(invalid("提醒日期格式或日期无效"));
            }
            validate_time_zone(required(object, "timeZone")?)?;
        }
        "dateTime" => {
            require_allowed_fields(object, &["kind", "at", "timeZone"])?;
            if !valid_date_time(require_string(required(object, "at")?)?) {
                return Err(invalid("提醒时间需为带明确偏移的分钟精度 RFC3339 时间"));
            }
            validate_time_zone(required(object, "timeZone")?)?;
        }
        _ => return Err(invalid("提醒日期类型无效")),
    }
    Ok(kind)
}

fn validate_time_zone(value: &Value) -> Result<()> {
    let zone = require_string(value)?;
    if zone.is_empty() || zone.len() > 128 {
        return Err(invalid("提醒时区标识格式无效"));
    }
    if zone == "UTC" {
        return Ok(());
    }
    let Some((region, name)) = zone.split_once('/') else {
        return Err(invalid("提醒时区标识格式无效"));
    };
    if region.is_empty()
        || !region
            .bytes()
            .all(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        || name.split('/').any(|part| {
            part.is_empty()
                || !part.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+')
                })
        })
    {
        return Err(invalid("提醒时区标识格式无效"));
    }
    Ok(())
}

fn valid_date_time(value: &str) -> bool {
    let bytes = value.as_bytes();
    if !value.is_ascii()
        || ![20, 25].contains(&bytes.len())
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || &bytes[17..19] != b"00"
        || !crate::query::valid_date(&value[..10])
        || two_digits(&bytes[11..13]).is_none_or(|hour| hour > 23)
        || two_digits(&bytes[14..16]).is_none_or(|minute| minute > 59)
    {
        return false;
    }
    if bytes.len() == 20 {
        return bytes[19] == b'Z';
    }
    matches!(bytes[19], b'+' | b'-')
        && bytes[22] == b':'
        && two_digits(&bytes[20..22]).is_some_and(|hour| hour <= 23)
        && two_digits(&bytes[23..25]).is_some_and(|minute| minute <= 59)
        && &bytes[19..25] != b"-00:00"
}

fn two_digits(bytes: &[u8]) -> Option<u8> {
    (bytes[0].is_ascii_digit() && bytes[1].is_ascii_digit())
        .then(|| (bytes[0] - b'0') * 10 + bytes[1] - b'0')
}

fn require_identifier(value: &Value, min_length: usize, extra_allowed: &[u8]) -> Result<()> {
    let id = require_string(value)?;
    if !(min_length..=128).contains(&id.len())
        || !id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'_' | b'-')
                || extra_allowed.contains(&byte)
        })
    {
        return Err(invalid("提醒请求或资源标识格式无效"));
    }
    Ok(())
}

fn required<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a Value> {
    object
        .get(field)
        .ok_or_else(|| invalid("提醒请求缺少必填字段"))
}

fn require_allowed_fields(object: &Map<String, Value>, allowed: &[&str]) -> Result<()> {
    if object
        .keys()
        .any(|field| !allowed.contains(&field.as_str()))
    {
        return Err(invalid("提醒请求包含不支持的字段"));
    }
    Ok(())
}

fn require_object(value: &Value) -> Result<&Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| invalid("提醒请求字段需为 JSON 对象"))
}

fn require_string(value: &Value) -> Result<&str> {
    value
        .as_str()
        .ok_or_else(|| invalid("提醒请求字段需为字符串"))
}

fn invalid(message: &'static str) -> McpError {
    McpError::Invalid(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create() -> Value {
        json!({
            "requestId":"request_1234567890", "title":"散步", "notes":"",
            "due":{"kind":"date", "date":"2026-10-03", "timeZone":"Asia/Shanghai"},
            "recurrence":"NONE"
        })
    }

    fn update() -> Value {
        json!({
            "requestId":"request_1234567890", "reminderId":"reminder_1",
            "expectedVersion":"version_1234567890", "patch":{"notes":""}
        })
    }

    #[test]
    fn valid_shapes_never_submit_or_echo_content() {
        for (operation, value) in [("create", create()), ("update", update())] {
            let output = validate(operation, value).unwrap();
            assert_eq!(output["status"], "shape_valid");
            assert_eq!(output["operation"], operation);
            assert_eq!(output["submitted"], false);
            assert_eq!(
                output["checksPending"],
                json!([
                    "authorization",
                    "timeZoneResolution",
                    "currentReminderVersion",
                    "phoneApplication"
                ])
            );
            assert_eq!(output.as_object().unwrap().len(), 4);
        }
    }

    #[test]
    fn rejects_unknown_fields_at_every_object_level() {
        for field in [
            "status",
            "completedAt",
            "owner",
            "linkedJournalId",
            "unknown",
        ] {
            let mut request = create();
            request[field] = json!("private-value");
            let error = validate("create", request).unwrap_err().to_string();
            assert!(!error.contains("private-value"));
            let mut request = update();
            request["patch"][field] = json!("private-value");
            assert!(validate("update", request).is_err());
        }
        let mut request = update();
        request["unknown"] = json!(true);
        assert!(validate("update", request).is_err());
        for due in [
            json!({"kind":"none", "date":"2026-10-03"}),
            json!({"kind":"date", "date":"2026-10-03", "timeZone":"UTC", "at":"unused"}),
            json!({"kind":"dateTime", "at":"2026-10-03T09:00:00Z", "timeZone":"UTC", "date":"unused"}),
        ] {
            let mut request = create();
            request["due"] = due;
            assert!(validate("create", request).is_err());
        }
    }

    #[test]
    fn required_fields_and_explicit_null_are_rejected() {
        for field in ["requestId", "title", "due", "recurrence"] {
            let mut request = create();
            request.as_object_mut().unwrap().remove(field);
            assert!(validate("create", request).is_err());
        }
        for field in CREATE_FIELDS {
            let mut request = create();
            request[*field] = Value::Null;
            assert!(validate("create", request).is_err());
        }
        for field in UPDATE_FIELDS {
            let mut request = update();
            request[*field] = Value::Null;
            assert!(validate("update", request).is_err());
        }
        for value in [
            Value::Null,
            json!([]),
            json!(true),
            json!(0),
            json!("value"),
        ] {
            assert!(validate("create", value).is_err());
        }
    }

    #[test]
    fn validates_utf16_limits_without_trimming_or_echoing_values() {
        let mut request = create();
        request["title"] = json!("😀".repeat(100));
        assert!(validate("create", request.clone()).is_ok());
        request["title"] = json!("😀".repeat(101));
        assert!(validate("create", request).is_err());
        for title in ["", " \t\n", "\u{2003}"] {
            let mut request = create();
            request["title"] = json!(title);
            assert!(validate("create", request).is_err());
        }
        let mut request = create();
        request["notes"] = json!("😀".repeat(32_768));
        assert!(validate("create", request.clone()).is_ok());
        request["notes"] = json!("😀".repeat(32_769));
        assert!(validate("create", request).is_err());
        let mut request = create();
        request.as_object_mut().unwrap().remove("notes");
        assert!(validate("create", request).is_ok());
    }

    #[test]
    fn patches_are_nonempty_typed_and_do_not_guess_current_values() {
        for patch in [
            json!({}),
            json!([]),
            Value::Null,
            json!({"title":false}),
            json!({"notes":0}),
        ] {
            let mut request = update();
            request["patch"] = patch;
            assert!(validate("update", request).is_err());
        }
        for patch in [
            json!({"due":{"kind":"none"}}),
            json!({"recurrence":"DAILY"}),
            json!({"due":{"kind":"none"}, "recurrence":"DAILY"}),
        ] {
            let mut request = update();
            request["patch"] = patch;
            let result = validate("update", request).unwrap();
            assert_eq!(result["status"], "shape_valid");
            assert_eq!(result["submitted"], false);
        }
    }

    #[test]
    fn validates_calendar_dates_and_minute_precision_offsets() {
        for date in ["2000-02-29", "2024-02-29", "9999-12-31"] {
            let mut request = create();
            request["due"]["date"] = json!(date);
            assert!(validate("create", request).is_ok());
        }
        for date in [
            "1900-02-29",
            "2026-02-29",
            "0000-01-01",
            "2026-04-31",
            "2026-1-01",
        ] {
            let mut request = create();
            request["due"]["date"] = json!(date);
            assert!(validate("create", request).is_err());
        }
        for at in [
            "2026-10-03T09:00:00+08:00",
            "2026-10-03T09:00:00-04:00",
            "2026-10-03T09:00:00Z",
        ] {
            assert!(valid_date_time(at));
        }
        for at in [
            "2026-02-29T09:00:00+08:00",
            "2026-10-03T24:00:00+08:00",
            "2026-10-03T09:60:00+08:00",
            "2026-10-03T09:00:01+08:00",
            "2026-10-03T09:00:60+08:00",
            "2026-10-03T09:00:00.000+08:00",
            "2026-10-03T09:00:00",
            "2026-10-03 09:00:00+08:00",
            "2026-10-03T09:00:00+24:00",
            "2026-10-03T09:00:00+08:60",
            "2026-10-03T09:00:00-00:00",
            "2026-10-03T09:00:00z",
            "中文",
        ] {
            assert!(!valid_date_time(at));
        }
        let mut request = create();
        request["due"] = json!({"kind":"dateTime", "at":"2026-10-03T09:00:00+08:00", "timeZone":"Asia/Shanghai"});
        assert!(validate("create", request).is_ok());
    }

    #[test]
    fn identifiers_versions_and_time_zones_only_accept_bounded_shapes() {
        for id in [
            "short",
            "request_1234567890/",
            "request_1234567890\n",
            "请求_1234567890123456",
        ] {
            let mut request = create();
            request["requestId"] = json!(id);
            assert!(validate("create", request).is_err());
        }
        let mut request = create();
        request["requestId"] = json!("a".repeat(129));
        assert!(validate("create", request).is_err());
        for id in ["", "a/b", "../other", "a%2Fb", "记录", "a\n"] {
            let mut request = update();
            request["reminderId"] = json!(id);
            assert!(validate("update", request).is_err());
        }
        let mut request = update();
        request["reminderId"] = json!("old.reminder:123-456_7");
        assert!(validate("update", request).is_ok());
        for version in [
            "short",
            "version_1234567890\n",
            "version 1234567890",
            "版本1234567890123456",
        ] {
            let mut request = update();
            request["expectedVersion"] = json!(version);
            assert!(validate("update", request).is_err());
        }
        let mut request = update();
        request["expectedVersion"] = json!("a".repeat(1025));
        assert!(validate("update", request).is_err());
        for zone in [
            "",
            "Unknown",
            "0Region/Zone",
            "Asia//Shanghai",
            "/Asia/Shanghai",
            "Asia/Shanghai/",
            "../UTC",
            "Asia/ Shanghai",
            "中国/上海",
        ] {
            let mut request = create();
            request["due"]["timeZone"] = json!(zone);
            assert!(validate("create", request).is_err());
        }
        let mut request = create();
        request["due"]["timeZone"] = json!("Unknown/Zone");
        assert!(validate("create", request).is_ok());
        for zone in ["UTC", "Etc/GMT+8", "America/Argentina/Buenos_Aires"] {
            let mut request = create();
            request["due"]["timeZone"] = json!(zone);
            assert!(validate("create", request).is_ok());
        }
    }

    #[test]
    fn rejects_missing_due_fields_and_unsupported_recurrences() {
        for due in [
            json!({}),
            json!({"kind":null}),
            json!({"kind":"date", "date":"2026-10-03"}),
            json!({"kind":"date", "timeZone":"UTC"}),
            json!({"kind":"other"}),
            json!({"kind":"dateTime", "at":"2026-10-03T09:00:00Z"}),
        ] {
            let mut request = create();
            request["due"] = due;
            assert!(validate("create", request).is_err());
        }
        for recurrence in [json!("MONTHLY"), json!("daily"), json!(0), Value::Null] {
            let mut request = create();
            request["recurrence"] = recurrence;
            assert!(validate("create", request).is_err());
        }
        for recurrence in ["NONE", "DAILY", "WEEKLY"] {
            let mut request = create();
            request["due"] = json!({"kind":"none"});
            request["recurrence"] = json!(recurrence);
            assert_eq!(validate("create", request).is_ok(), recurrence == "NONE");
        }
        assert!(validate("delete", create()).is_err());
        assert!(validate("complete", create()).is_err());
    }

    #[test]
    fn contract_fields_match_the_local_validator() {
        let contract = contract().unwrap();
        assert_eq!(contract["protocolVersion"], 1);
        assert_eq!(contract["lifecycle"]["status"], "enabled");
        assert_eq!(contract["lifecycle"]["writeEnabled"], true);
        assert_eq!(contract["lifecycle"]["productionVerified"], false);
        for (operation, allowed, required) in [
            (
                "create",
                CREATE_FIELDS,
                &["requestId", "title", "due", "recurrence"][..],
            ),
            ("update", UPDATE_FIELDS, UPDATE_FIELDS),
        ] {
            let schema = &contract["operations"][operation]["inputSchema"];
            assert_eq!(schema["type"], "object");
            assert_eq!(schema["additionalProperties"], false);
            let properties = schema["properties"].as_object().unwrap();
            assert_eq!(properties.len(), allowed.len());
            assert!(allowed.iter().all(|field| properties.contains_key(*field)));
            let actual_required = schema["required"].as_array().unwrap();
            assert_eq!(actual_required.len(), required.len());
            assert!(required.iter().all(|field| {
                actual_required
                    .iter()
                    .any(|value| value.as_str() == Some(*field))
            }));
        }
        let patch = &contract["$defs"]["patch"];
        assert_eq!(patch["additionalProperties"], false);
        assert_eq!(patch["minProperties"], 1);
        let fields = patch["properties"].as_object().unwrap();
        assert_eq!(fields.len(), PATCH_FIELDS.len());
        assert!(PATCH_FIELDS.iter().all(|field| fields.contains_key(*field)));
        assert_eq!(contract["$defs"]["recurrence"]["enum"], json!(RECURRENCES));
        assert_eq!(contract["$defs"]["title"]["x-ownmate-maxUtf16Length"], 200);
        assert_eq!(
            contract["$defs"]["notes"]["x-ownmate-maxUtf16Length"],
            65_536
        );
    }
}
