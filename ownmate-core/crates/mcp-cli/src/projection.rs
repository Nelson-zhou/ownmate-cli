use crate::api::ReadResource;
use crate::crypto::{decrypt_mcp_journal, decrypt_payload};
use crate::protocol::OpaqueJournal;
use crate::{McpError, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Reminder {
    id: String,
    title: String,
    notes: String,
    due_at_millis: Option<u64>,
    recurrence: String,
    status: String,
    completed_at_millis: Option<u64>,
    created_at: u64,
    updated_at: u64,
    scheduling_device_id: String,
    completion_cycle: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Completion {
    occurrence_id: String,
    reminder_id: String,
    title: String,
    due_at_millis: Option<u64>,
    completed_at_millis: u64,
    reversed_at_millis: Option<u64>,
    completion_cycle: u64,
}

pub fn decrypt_projection(
    kind: ReadResource,
    item: &OpaqueJournal,
    key_id: &str,
    key: &[u8],
) -> Result<Value> {
    if kind == ReadResource::Journal {
        return Ok(serde_json::to_value(decrypt_mcp_journal(
            item, key_id, key,
        )?)?);
    }
    let plain = decrypt_payload(item, key_id, key)?;
    project(kind, &item.entry_id, &plain)
}

fn project(kind: ReadResource, id: &str, plain: &[u8]) -> Result<Value> {
    if kind == ReadResource::Fragment {
        return project_fragment(id, plain);
    }
    if plain.len() > 512 * 1024
        || std::str::from_utf8(plain)
            .map_err(|_| invalid())?
            .encode_utf16()
            .count()
            > 128 * 1024
    {
        return Err(invalid());
    }
    let root: Value = serde_json::from_slice(plain).map_err(|_| invalid())?;
    let (resource_type, field) = match kind {
        ReadResource::Reminder => ("reminder", "reminder"),
        ReadResource::ReminderCompletion => ("reminderCompletion", "completion"),
        _ => return Err(invalid()),
    };
    let object = root.as_object().ok_or_else(invalid)?;
    if object.len() != 3
        || root["payloadVersion"].as_u64() != Some(2)
        || root["resourceType"].as_str() != Some(resource_type)
        || !object.contains_key(field)
    {
        return Err(invalid());
    }
    let expected_fields = if kind == ReadResource::Reminder {
        11
    } else {
        7
    };
    if root[field].as_object().map(|v| v.len()) != Some(expected_fields) {
        return Err(invalid());
    }
    let record = match kind {
        ReadResource::Reminder => {
            let row: Reminder =
                serde_json::from_value(root[field].clone()).map_err(|_| invalid())?;
            if row.id != id
                || row.id.is_empty()
                || row.id.len() > 160
                || row.id.chars().any(char::is_control)
                || !valid_title(&row.title)
                || row.notes.encode_utf16().count() > 64 * 1024
                || !["NONE", "DAILY", "WEEKLY"].contains(&row.recurrence.as_str())
                || !["PENDING", "COMPLETED"].contains(&row.status.as_str())
                || (row.status == "COMPLETED") != row.completed_at_millis.is_some()
                || row.scheduling_device_id.is_empty()
                || row.scheduling_device_id.len() > 160
            {
                return Err(invalid());
            }
            let mut value = serde_json::to_value(row)?;
            value
                .as_object_mut()
                .ok_or_else(invalid)?
                .remove("schedulingDeviceId");
            value
        }
        ReadResource::ReminderCompletion => {
            let row: Completion =
                serde_json::from_value(root[field].clone()).map_err(|_| invalid())?;
            let due = row
                .due_at_millis
                .map_or_else(|| "nodue".into(), |n| n.to_string());
            let occurrence = format!("reminder-completion:{}:{due}", row.reminder_id);
            let wire = completion_resource_id(&occurrence, row.completion_cycle);
            if id != wire
                || row.occurrence_id != occurrence
                || row.reminder_id.is_empty()
                || row.reminder_id.len() > 160
                || !valid_title(&row.title)
                || row
                    .reversed_at_millis
                    .is_some_and(|n| n < row.completed_at_millis)
            {
                return Err(invalid());
            }
            serde_json::to_value(row)?
        }
        _ => return Err(invalid()),
    };
    Ok(json!({"version":1, "kind":resource_type, "resourceId":id, "record":record}))
}

fn project_fragment(id: &str, plain: &[u8]) -> Result<Value> {
    if plain.len() > 4 * 1024 * 1024 {
        return Err(invalid());
    }
    let root: Value = serde_json::from_slice(plain).map_err(|_| invalid())?;
    if !root["payloadVersion"]
        .as_u64()
        .is_some_and(|v| (1..=3).contains(&v))
        || root.get("deleted").is_some_and(|v| v != false)
    {
        return Err(invalid());
    }
    let row = root["fragment"].as_object().ok_or_else(invalid)?;
    let date = row
        .get("date")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let text = row
        .get("text")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let kind = row
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    if !crate::query::valid_date(date)
        || text.encode_utf16().count() > 1024 * 1024
        || !["TEXT", "VOICE", "IMAGE"].contains(&kind)
    {
        return Err(invalid());
    }
    let created = row
        .get("createdAt")
        .and_then(Value::as_u64)
        .ok_or_else(invalid)?;
    let updated = row
        .get("updatedAt")
        .and_then(Value::as_u64)
        .ok_or_else(invalid)?;
    let completion_source = if row.get("payloadType").and_then(Value::as_str)
        == Some("reminder.completion")
    {
        let source_version = row.get("payloadVersion").and_then(Value::as_u64);
        if !matches!(source_version, Some(1 | 2)) {
            return Err(invalid());
        }
        let payload: Value = serde_json::from_str(
            row.get("payloadJson")
                .and_then(Value::as_str)
                .ok_or_else(invalid)?,
        )
        .map_err(|_| invalid())?;
        let reminder_id = payload["reminderId"].as_str().ok_or_else(invalid)?;
        let due = match payload.get("dueAtMillis") {
            None | Some(Value::Null) => None,
            Some(value) => Some(value.as_u64().ok_or_else(invalid)?),
        };
        let occurrence = format!(
            "reminder-completion:{reminder_id}:{}",
            due.map_or_else(|| "nodue".into(), |v| v.to_string())
        );
        if payload["version"].as_u64() != source_version
            || reminder_id.is_empty()
            || id != occurrence
        {
            return Err(invalid());
        }
        if source_version == Some(1) {
            None
        } else {
            let cycle = payload["completionCycle"].as_u64().ok_or_else(invalid)?;
            Some(
                json!({"occurrenceId":occurrence,"completedAtMillis":created,"completionCycle":cycle,
                "completionResourceId":completion_resource_id(&occurrence, cycle)}),
            )
        }
    } else {
        None
    };
    Ok(
        json!({"version":1,"kind":"fragment","resourceId":id,"record":{
            "date":date,"type":kind,"text":text,"createdAt":created,"updatedAt":updated,
            "contentAvailability": if kind == "TEXT" { "text" } else { "textOnly; media not read" },
            "completionSource":completion_source
        }}),
    )
}

fn completion_resource_id(occurrence: &str, cycle: u64) -> String {
    format!(
        "rc_{:x}",
        Sha256::digest(format!("{occurrence}\ncycle:{cycle}").as_bytes())
    )
}

fn valid_title(title: &str) -> bool {
    !title.trim().is_empty() && title.encode_utf16().count() <= 200
}

fn invalid() -> McpError {
    McpError::Invalid("只读资源载荷校验失败".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cycle_hash_matches_android_vector_and_legacy_fragment_does_not_guess_cycle() {
        assert_eq!(
            completion_resource_id("reminder-completion:fixture:10", 3),
            "rc_77fe575bf1754d613054235ae21cc84886c9a8f88e1b255963a367812616b9cb"
        );
        let legacy = json!({"payloadVersion":3,"fragment":{
            "date":"2026-10-01","type":"TEXT","text":"fixture","createdAt":123,"updatedAt":123,
            "payloadType":"reminder.completion","payloadVersion":1,
            "payloadJson":json!({"version":1,"reminderId":"r"}).to_string()
        }});
        let result = project_fragment(
            "reminder-completion:r:nodue",
            &serde_json::to_vec(&legacy).unwrap(),
        )
        .unwrap();
        assert!(result["record"]["completionSource"].is_null());
        assert_eq!(result["record"]["text"], "fixture");
    }
    #[test]
    fn completion_fragment_requires_exact_source_identity() {
        let mut root = json!({"payloadVersion":3,"fragment":{
            "date":"2026-10-01","type":"TEXT","text":"完成了","createdAt":123,"updatedAt":123,
            "payloadType":"reminder.completion","payloadVersion":2,
            "payloadJson":json!({"version":2,"reminderId":"r","recurrence":"NONE","completionCycle":3}).to_string()
        }});
        let id = "reminder-completion:r:nodue";
        let bytes = serde_json::to_vec(&root).unwrap();
        let projected = project_fragment(id, &bytes).unwrap();
        assert_eq!(
            projected["record"]["completionSource"]["completionResourceId"],
            completion_resource_id(id, 3)
        );
        assert!(project_fragment("other", &bytes).is_err());
        root["fragment"]["payloadVersion"] = json!(3);
        assert!(project_fragment(id, &serde_json::to_vec(&root).unwrap()).is_err());
    }

    #[test]
    fn fragment_projection_excludes_location_media_and_rejects_invalid_date() {
        let mut value = json!({"payloadVersion":3,"containerId":"private-container","fragment":{
            "date":"2026-10-01","createdAt":1,"updatedAt":2,"type":"VOICE","text":"fixture",
            "latitude":30,"longitude":114,"locationName":"private-location","audioTranscript":"private-transcript"
        },"assets":[{"objectId":"private-media"}],"journalEntryIds":["private-entry"]});
        let projected = project(
            ReadResource::Fragment,
            "fragment-fixture",
            &serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
        for forbidden in [
            "private-location",
            "private-media",
            "private-container",
            "private-transcript",
            "latitude",
            "longitude",
        ] {
            assert!(!projected.to_string().contains(forbidden));
        }
        value["fragment"]["date"] = json!("2026-02-30");
        assert!(
            project(
                ReadResource::Fragment,
                "fragment-fixture",
                &serde_json::to_vec(&value).unwrap()
            )
            .is_err()
        );
    }
    fn reminder() -> Value {
        json!({"payloadVersion":2,"resourceType":"reminder","reminder":{
            "id":"fixture","title":"fixture","notes":"line1\nline2","dueAtMillis":null,
            "recurrence":"NONE","status":"PENDING","completedAtMillis":null,
            "createdAt":1,"updatedAt":2,"schedulingDeviceId":"private-device","completionCycle":0
        }})
    }
    #[test]
    fn reminder_projection_excludes_device_identity_and_rejects_inconsistent_state() {
        let mut value = reminder();
        let result = project(
            ReadResource::Reminder,
            "fixture",
            &serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
        assert!(!result.to_string().contains("private-device"));
        assert!(
            project(
                ReadResource::Reminder,
                "wrong",
                &serde_json::to_vec(&value).unwrap()
            )
            .is_err()
        );
        value["reminder"]["status"] = json!("COMPLETED");
        assert!(
            project(
                ReadResource::Reminder,
                "fixture",
                &serde_json::to_vec(&value).unwrap()
            )
            .is_err()
        );
    }
    #[test]
    fn unknown_fields_and_deleted_payloads_are_not_projected() {
        let mut value = reminder();
        value["reminder"]["latitude"] = json!(30);
        assert!(
            project(
                ReadResource::Reminder,
                "fixture",
                &serde_json::to_vec(&value).unwrap()
            )
            .is_err()
        );
        value = json!({"payloadVersion":1,"resourceType":"reminder","deleted":true});
        assert!(
            project(
                ReadResource::Reminder,
                "fixture",
                &serde_json::to_vec(&value).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn completion_identity_and_reversal_are_verified() {
        let occurrence = "reminder-completion:fixture:10";
        let id = completion_resource_id(occurrence, 3);
        let mut value = json!({"payloadVersion":2,"resourceType":"reminderCompletion","completion":{
            "occurrenceId":occurrence,"reminderId":"fixture","title":"fixture",
            "dueAtMillis":10,"completedAtMillis":20,"reversedAtMillis":30,"completionCycle":3
        }});
        assert!(
            project(
                ReadResource::ReminderCompletion,
                &id,
                &serde_json::to_vec(&value).unwrap()
            )
            .is_ok()
        );
        assert!(
            project(
                ReadResource::ReminderCompletion,
                "wrong",
                &serde_json::to_vec(&value).unwrap()
            )
            .is_err()
        );
        value["completion"]["reversedAtMillis"] = json!(19);
        assert!(
            project(
                ReadResource::ReminderCompletion,
                &id,
                &serde_json::to_vec(&value).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn unicode_notes_use_the_android_utf16_limit_not_a_smaller_byte_limit() {
        let mut value = reminder();
        value["reminder"]["notes"] = json!("文".repeat(60_000));
        assert!(
            project(
                ReadResource::Reminder,
                "fixture",
                &serde_json::to_vec(&value).unwrap()
            )
            .is_ok()
        );
        value["reminder"]
            .as_object_mut()
            .unwrap()
            .remove("dueAtMillis");
        assert!(
            project(
                ReadResource::Reminder,
                "fixture",
                &serde_json::to_vec(&value).unwrap()
            )
            .is_err()
        );
    }
}
