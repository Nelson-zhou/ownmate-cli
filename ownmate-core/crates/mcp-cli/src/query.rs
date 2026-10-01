use crate::protocol::McpJournalV1;
use crate::{McpError, Result};
use serde_json::{Value, json};

#[derive(Default)]
pub struct Query {
    contains: Option<String>,
    tag: Option<String>,
    from: Option<String>,
    through: Option<String>,
}

impl Query {
    pub fn report_typed(&self, records: Vec<Value>, scopes: &[String]) -> Value {
        let completion_ids: std::collections::HashSet<String> = records
            .iter()
            .filter(|r| r["kind"] == "reminderCompletion")
            .filter_map(|r| r["resourceId"].as_str().map(str::to_owned))
            .collect();
        let mut counts = serde_json::Map::new();
        let mut selected = Vec::new();
        let mut missing_date = 0;
        let mut empty_text = 0;
        let mut matched_duplicate_sources = 0;
        for record in records {
            let kind = record["kind"].as_str().unwrap_or("journal").to_owned();
            let count = counts.entry(kind.clone()).or_insert(json!(0));
            *count = json!(count.as_u64().unwrap_or(0) + 1);
            let body = if kind == "journal" {
                &record
            } else {
                &record["record"]
            };
            if ["title", "text", "notes"]
                .iter()
                .all(|field| body[field].as_str().is_none_or(|v| v.trim().is_empty()))
            {
                empty_text += 1;
            }
            let date = match kind.as_str() {
                "journal" => body["occurredAt"]
                    .as_str()
                    .and_then(|v| v.get(..10))
                    .map(str::to_owned),
                "fragment" => body["date"].as_str().map(str::to_owned),
                "reminder" => body["dueAtMillis"].as_u64().and_then(utc_date),
                "reminderCompletion" => body["completedAtMillis"].as_u64().and_then(utc_date),
                _ => None,
            };
            if date.is_none() {
                missing_date += 1;
            }
            let matches_text = self.contains.as_ref().is_none_or(|needle| {
                ["title", "text", "notes"].iter().any(|field| {
                    body[field]
                        .as_str()
                        .is_some_and(|text| text.contains(needle))
                })
            });
            let matches_tag = self.tag.as_ref().is_none_or(|tag| {
                body["tags"]
                    .as_array()
                    .is_some_and(|tags| tags.iter().any(|v| v.as_str() == Some(tag)))
            });
            let matches_date = self
                .from
                .as_ref()
                .is_none_or(|from| date.as_ref().is_some_and(|d| d >= from))
                && self
                    .through
                    .as_ref()
                    .is_none_or(|through| date.as_ref().is_some_and(|d| d <= through));
            if matches_text && matches_tag && matches_date {
                let duplicate = body["completionSource"]["completionResourceId"]
                    .as_str()
                    .filter(|id| completion_ids.contains(*id))
                    .map(|id| format!("ownmate://reminder-completions/{id}"));
                if duplicate.is_some() {
                    matched_duplicate_sources += 1;
                }
                selected.push(json!({"reference":{"resourceUri":record["resourceUri"],"date":date,"kind":kind,"sameEventAs":duplicate},"record":record}));
            }
        }
        json!({"coverage":{
            "scopes":scopes,"allPagesRead":true,"countsByKind":counts,"matchedCount":selected.len(),
            "missingDateCount":missing_date,
            "emptyTextCount":empty_text,
            "dateFilter":{"from":self.from,"through":self.through,"basis":"journal/fragment: recorded local calendar day; reminder: due day in UTC; completion: completion day in UTC; inclusive"},
            "unavailable":["mediaContents","mediaTranscripts","unsyncedLocalRecords"],
            "matchedDuplicateCompletionSources":matched_duplicate_sources,
            "completionLinking":"exactResourceIdentityOnly; both sources retained",
            "note":"Counts describe resources, not independent life events. sameEventAs marks exact verified completion links without removing either source; unmatched or missing history is not inferred. Future due dates are plans, not overdue evidence; missing dates are not invented."
        },"records":selected})
    }

    pub fn parse(args: Vec<String>) -> Result<Self> {
        let mut query = Self::default();
        let mut args = args.into_iter();
        while let Some(flag) = args.next() {
            let slot = match flag.as_str() {
                "--contains" => &mut query.contains,
                "--tag" => &mut query.tag,
                "--from" => &mut query.from,
                "--through" => &mut query.through,
                _ => return Err(McpError::Invalid(format!("未知查询参数: {flag}"))),
            };
            if slot.is_some() {
                return Err(McpError::Invalid(format!("重复查询参数: {flag}")));
            }
            let value = args
                .next()
                .filter(|s| !s.trim().is_empty() && !s.starts_with("--"))
                .ok_or_else(|| McpError::Invalid(format!("{flag} 缺少值")))?;
            *slot = Some(value);
        }
        for date in [&query.from, &query.through].into_iter().flatten() {
            if !valid_date(date) {
                return Err(McpError::Invalid("日期须为有效的 YYYY-MM-DD".into()));
            }
        }
        if query
            .from
            .as_ref()
            .zip(query.through.as_ref())
            .is_some_and(|(a, b)| a > b)
        {
            return Err(McpError::Invalid("开始日期不能晚于结束日期".into()));
        }
        Ok(query)
    }

    pub fn report(&self, records: Vec<McpJournalV1>) -> Value {
        self.report_typed(
            records
                .into_iter()
                .map(|record| {
                    let uri = crate::mcp::typed_resource_uri(
                        crate::api::ReadResource::Journal,
                        &record.entry_id,
                    );
                    let mut value = json!(record);
                    value["resourceUri"] = json!(uri);
                    value
                })
                .collect(),
            &["journals:read".into()],
        )
    }
}

fn utc_date(millis: u64) -> Option<String> {
    // Gregorian civil date from epoch days; cap at the supported query year range.
    let days = millis / 86_400_000;
    if days > 2_932_896 {
        return None;
    }
    let z = days as i64 + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    Some(format!("{year:04}-{month:02}-{day:02}"))
}

pub(crate) fn valid_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(i, b)| i != 4 && i != 7 && !b.is_ascii_digit())
    {
        return false;
    }
    let year: u32 = value[..4].parse().unwrap_or(0);
    let month: usize = value[5..7].parse().unwrap_or(0);
    let day: u32 = value[8..].parse().unwrap_or(0);
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    year > 0 && (1..=12).contains(&month) && day > 0 && day <= days[month - 1]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn completion_links_preserve_both_sources_and_never_guess_by_text() {
        let records = vec![
            json!({"kind":"reminderCompletion","resourceId":"rc_a","resourceUri":"ownmate://reminder-completions/rc_a","record":{"title":"完成了"}}),
            json!({"kind":"fragment","resourceUri":"ownmate://fragments/a","record":{"text":"完成了","completionSource":{"completionResourceId":"rc_a"}}}),
            json!({"kind":"fragment","resourceUri":"ownmate://fragments/b","record":{"text":"完成了","completionSource":{"completionResourceId":"rc_missing"}}}),
        ];
        let report = Query::default()
            .report_typed(records, &["reminders:read".into(), "fragments:read".into()]);
        assert_eq!(report["coverage"]["matchedCount"], 3);
        assert_eq!(report["coverage"]["matchedDuplicateCompletionSources"], 1);
        assert_eq!(
            report["records"][1]["reference"]["sameEventAs"],
            "ownmate://reminder-completions/rc_a"
        );
        assert!(report["records"][2]["reference"]["sameEventAs"].is_null());
    }
    #[test]
    fn epoch_days_cover_leap_days_and_reject_out_of_range() {
        assert_eq!(utc_date(0).as_deref(), Some("1970-01-01"));
        assert_eq!(utc_date(951_782_400_000).as_deref(), Some("2000-02-29"));
        assert_eq!(utc_date(253_402_214_400_000).as_deref(), Some("9999-12-31"));
        assert_eq!(utc_date(253_402_300_800_000), None);
        assert_eq!(utc_date(u64::MAX), None);
    }

    #[test]
    fn typed_query_keeps_scope_coverage_and_does_not_invent_dates() {
        let records = vec![
            json!({"kind":"fragment","resourceUri":"ownmate://fragments/a","record":{"date":"2000-02-29","text":"工作"}}),
            json!({"kind":"reminder","resourceUri":"ownmate://reminders/b","record":{"dueAtMillis":null,"title":"工作"}}),
            json!({"kind":"reminderCompletion","resourceUri":"ownmate://reminder-completions/c","record":{"completedAtMillis":951_782_400_000u64,"title":"工作"}}),
        ];
        let query = Query::parse(vec![
            "--from".into(),
            "2000-02-29".into(),
            "--through".into(),
            "2000-02-29".into(),
        ])
        .unwrap();
        let report = query.report_typed(
            records.clone(),
            &["fragments:read".into(), "reminders:read".into()],
        );
        assert_eq!(report["coverage"]["matchedCount"], 2);
        assert_eq!(report["coverage"]["missingDateCount"], 1);
        assert_eq!(report["coverage"]["countsByKind"]["reminder"], 1);
        assert_eq!(
            report["records"][0]["reference"]["resourceUri"],
            "ownmate://fragments/a"
        );
        let tag = Query::parse(vec!["--tag".into(), "生活".into()]).unwrap();
        assert_eq!(
            tag.report_typed(records, &[])["coverage"]["matchedCount"],
            0
        );
    }
    #[test]
    fn rejects_unknown_missing_and_duplicate_filters() {
        for args in [
            vec!["--bad"],
            vec!["--tag"],
            vec!["--tag", "a", "--tag", "b"],
        ] {
            assert!(Query::parse(args.into_iter().map(str::to_owned).collect()).is_err());
        }
    }
    #[test]
    fn empty_coverage_is_explicit() {
        let report = Query::default().report(vec![]);
        assert_eq!(report["coverage"]["matchedCount"], 0);
        assert_eq!(report["coverage"]["allPagesRead"], true);
        assert_eq!(report["coverage"]["scopes"], json!(["journals:read"]));
    }

    #[test]
    fn date_ranges_reject_invalid_and_reversed_dates() {
        for date in [
            "2026-02-29",
            "2026-13-01",
            "0000-01-01",
            "2026-01-00",
            "中文-日期",
        ] {
            assert!(!valid_date(date));
        }
        assert!(valid_date("2024-02-29"));
        assert!(!valid_date("1900-02-29"));
        assert!(valid_date("2000-02-29"));
        assert!(
            Query::parse(vec![
                "--from".into(),
                "2026-10-01".into(),
                "--through".into(),
                "2026-09-30".into()
            ])
            .is_err()
        );
    }

    #[test]
    fn calendar_bounds_are_inclusive_and_keep_references() {
        let record: McpJournalV1 = serde_json::from_str(include_str!(
            "../../../../contracts/external-access/v1/fixtures/mcp-journal.json"
        ))
        .unwrap();
        let date = record.occurred_at[..10].to_string();
        let query = Query::parse(vec![
            "--from".into(),
            date.clone(),
            "--through".into(),
            date,
        ])
        .unwrap();
        let report = query.report(vec![record.clone()]);
        assert_eq!(report["coverage"]["matchedCount"], 1);
        assert_eq!(
            report["records"][0]["reference"]["resourceUri"],
            crate::mcp::typed_resource_uri(crate::api::ReadResource::Journal, &record.entry_id)
        );
        let query = Query::parse(vec!["--from".into(), "9999-01-01".into()]).unwrap();
        assert_eq!(query.report(vec![record])["coverage"]["matchedCount"], 0);
    }
}
