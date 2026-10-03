//! Read the host's IANA TZif data without adding a bundled timezone dependency.
//! Missing databases or transition coverage fail explicitly; UTC works on all platforms.
use crate::{McpError, Result};
use std::path::Path;

pub struct Zone {
    transitions: Vec<(i64, usize)>,
    offsets: Vec<i32>,
    default_type: usize,
    fixed_tail: Option<i32>,
    has_tail: bool,
}

impl Zone {
    pub fn load(name: &str) -> Result<Self> {
        if name == "UTC" {
            return Ok(Self {
                transitions: vec![],
                offsets: vec![0],
                default_type: 0,
                fixed_tail: Some(0),
                has_tail: false,
            });
        }
        if name.len() > 128
            || !name.contains('/')
            || name.split('/').any(|part| {
                part.is_empty()
                    || part == "."
                    || part == ".."
                    || !part.bytes().all(|b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'+' | b'.')
                    })
            })
        {
            return Err(invalid());
        }
        for root in ["/usr/share/zoneinfo", "/var/db/timezone/zoneinfo"] {
            let root = match std::fs::canonicalize(root) {
                Ok(root) => root,
                Err(_) => continue,
            };
            let path = match std::fs::canonicalize(root.join(name)) {
                Ok(path) => path,
                Err(_) => continue,
            };
            if !path.starts_with(&root) || !Path::new(&path).is_file() {
                return Err(invalid());
            }
            let metadata = std::fs::metadata(&path)?;
            if metadata.len() > 1024 * 1024 {
                return Err(invalid());
            }
            return Self::from_tzif(&std::fs::read(path)?);
        }
        Err(McpError::Invalid(
            "本机无法解析所选 IANA 时区；查询请使用可用的系统时区数据或 UTC".into(),
        ))
    }

    fn from_tzif(bytes: &[u8]) -> Result<Self> {
        let (version, counts) = header(bytes, 0)?;
        let (start, width, counts) = if matches!(version, b'2' | b'3' | b'4') {
            let next = 44_usize
                .checked_add(block_size(counts, 4)?)
                .ok_or_else(invalid)?;
            let (_, second) = header(bytes, next)?;
            (next + 44, 8, second)
        } else if version == 0 {
            (44, 4, counts)
        } else {
            return Err(invalid());
        };
        let [ut, std, leap, times, types, chars] = counts;
        if types == 0 || types > 256 || times > 100000 || chars > 65536 || leap != 0 {
            return Err(invalid());
        }
        let end = start
            .checked_add(block_size([ut, std, leap, times, types, chars], width)?)
            .ok_or_else(invalid)?;
        if end > bytes.len() {
            return Err(invalid());
        }
        let mut transitions = Vec::with_capacity(times);
        for i in 0..times {
            let pos = start + i * width;
            let time = if width == 8 {
                i64::from_be_bytes(bytes[pos..pos + 8].try_into().map_err(|_| invalid())?)
            } else {
                i32::from_be_bytes(bytes[pos..pos + 4].try_into().map_err(|_| invalid())?) as i64
            };
            let index = bytes[start + times * width + i] as usize;
            if index >= types || transitions.last().is_some_and(|(last, _)| *last >= time) {
                return Err(invalid());
            }
            transitions.push((time, index));
        }
        let info = start + times * (width + 1);
        let mut offsets = Vec::with_capacity(types);
        let mut default_type = 0;
        for i in 0..types {
            let pos = info + i * 6;
            let offset = i32::from_be_bytes(bytes[pos..pos + 4].try_into().map_err(|_| invalid())?);
            if !(-86400..=86400).contains(&offset)
                || bytes[pos + 4] > 1
                || bytes[pos + 5] as usize >= chars
            {
                return Err(invalid());
            }
            offsets.push(offset);
        }
        if let Some(index) = (0..types).find(|i| bytes[info + i * 6 + 4] == 0) {
            default_type = index;
        }
        let tail = std::str::from_utf8(&bytes[end..])
            .map_err(|_| invalid())?
            .trim_matches('\n');
        let has_tail = !tail.is_empty();
        let fixed_tail = fixed_posix_offset(tail);
        Ok(Self {
            transitions,
            offsets,
            default_type,
            fixed_tail,
            has_tail,
        })
    }

    fn offset(&self, seconds: i64) -> Result<i32> {
        if self
            .transitions
            .last()
            .is_some_and(|(last, _)| seconds > *last)
            && self.has_tail
        {
            return self.fixed_tail.ok_or_else(|| {
                McpError::Invalid("本机时区转换表不覆盖该日期；手机仍须最终验证".into())
            });
        }
        let index = self
            .transitions
            .partition_point(|(time, _)| *time <= seconds);
        Ok(self.offsets[if index == 0 {
            self.default_type
        } else {
            self.transitions[index - 1].1
        }])
    }

    pub fn local_date(&self, millis: u64) -> Result<String> {
        let seconds = i64::try_from(millis / 1000).map_err(|_| invalid())?;
        Ok(date_from_days(
            (seconds + self.offset(seconds)? as i64).div_euclid(86400),
        ))
    }

    pub fn day_start(&self, date: &str) -> Result<u64> {
        let wall = date_days(date)?.checked_mul(86400).ok_or_else(invalid)?;
        let mut candidates = Vec::new();
        let mut offsets = self.offsets.clone();
        if let Some(offset) = self.fixed_tail {
            offsets.push(offset);
        }
        for offset in offsets {
            let candidate = wall - offset as i64;
            if self.offset(candidate)? == offset {
                candidates.push(candidate);
            }
        }
        // A midnight gap starts the civil day at the first valid instant in that day.
        if candidates.is_empty() {
            for &(time, _) in &self.transitions {
                let after = time + self.offset(time)? as i64;
                let before = time + self.offset(time - 1)? as i64;
                if before <= wall && after > wall && after < wall + 86400 {
                    candidates.push(time);
                }
            }
        }
        let seconds = candidates.into_iter().min().ok_or_else(invalid)?;
        u64::try_from(seconds)
            .ok()
            .and_then(|n| n.checked_mul(1000))
            .ok_or_else(invalid)
    }

    pub fn validate_local_datetime(&self, at: &str) -> Result<()> {
        if !at.is_ascii() || (at.len() != 20 && at.len() != 25) {
            return Err(invalid());
        }
        let day = date_days(at.get(..10).ok_or_else(invalid)?)?;
        let hour: i64 = at
            .get(11..13)
            .ok_or_else(invalid)?
            .parse()
            .map_err(|_| invalid())?;
        let minute: i64 = at
            .get(14..16)
            .ok_or_else(invalid)?
            .parse()
            .map_err(|_| invalid())?;
        let offset: i32 = if at.len() == 20 && at.ends_with('Z') {
            0
        } else {
            let h: i32 = at[20..22].parse().map_err(|_| invalid())?;
            let m: i32 = at[23..25].parse().map_err(|_| invalid())?;
            (h * 3600 + m * 60) * if &at[19..20] == "-" { -1 } else { 1 }
        };
        if hour > 23 || minute > 59 {
            return Err(invalid());
        }
        let instant = day * 86400 + hour * 3600 + minute * 60 - offset as i64;
        if self.offset(instant)? != offset {
            return Err(McpError::Invalid(
                "输入偏移与 IANA 时区不符或落在不存在的夏令时时刻".into(),
            ));
        }
        Ok(())
    }
}

fn header(bytes: &[u8], start: usize) -> Result<(u8, [usize; 6])> {
    let data = bytes.get(start..start + 44).ok_or_else(invalid)?;
    if &data[..4] != b"TZif" {
        return Err(invalid());
    }
    let mut counts = [0; 6];
    for (i, count) in counts.iter_mut().enumerate() {
        *count = u32::from_be_bytes(
            data[20 + i * 4..24 + i * 4]
                .try_into()
                .map_err(|_| invalid())?,
        ) as usize;
    }
    Ok((data[4], counts))
}
fn block_size([ut, std, leap, times, types, chars]: [usize; 6], width: usize) -> Result<usize> {
    times
        .checked_mul(width + 1)
        .and_then(|n| types.checked_mul(6).and_then(|t| n.checked_add(t)))
        .and_then(|n| n.checked_add(chars))
        .and_then(|n| leap.checked_mul(width + 4).and_then(|l| n.checked_add(l)))
        .and_then(|n| n.checked_add(std))
        .and_then(|n| n.checked_add(ut))
        .ok_or_else(invalid)
}
fn fixed_posix_offset(tail: &str) -> Option<i32> {
    if tail.is_empty() || tail.contains(',') {
        return None;
    }
    let start = if tail.starts_with('<') {
        tail.find('>')? + 1
    } else {
        tail.bytes().position(|b| !b.is_ascii_alphabetic())?
    };
    let value = &tail[start..];
    let (sign, value) = if let Some(v) = value.strip_prefix('-') {
        (-1, v)
    } else {
        (1, value.strip_prefix('+').unwrap_or(value))
    };
    let parts: Vec<_> = value.split(':').collect();
    if parts.len() > 3 {
        return None;
    }
    let hours: i32 = parts[0].parse().ok()?;
    let minutes: i32 = parts.get(1).map_or(Some(0), |v| v.parse().ok())?;
    let seconds: i32 = parts.get(2).map_or(Some(0), |v| v.parse().ok())?;
    if hours > 24 || minutes > 59 || seconds > 59 {
        return None;
    }
    Some(-(hours * 3600 + minutes * 60 + seconds) * sign)
}
pub fn date_days(date: &str) -> Result<i64> {
    if !crate::query::valid_date(date) {
        return Err(invalid());
    }
    let mut year: i64 = date[..4].parse().map_err(|_| invalid())?;
    let month: i64 = date[5..7].parse().map_err(|_| invalid())?;
    let day: i64 = date[8..].parse().map_err(|_| invalid())?;
    year -= i64::from(month <= 2);
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    Ok(era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468)
}
pub fn date_from_days(days: i64) -> String {
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}
fn invalid() -> McpError {
    McpError::Invalid("IANA 时区数据或自然日无效".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn calendar_roundtrips_and_timezone_escape_is_denied() {
        for date in ["1970-01-01", "2000-02-29", "2026-10-03", "9999-12-31"] {
            assert_eq!(date_from_days(date_days(date).unwrap()), date);
        }
        for zone in ["../UTC", "Asia/../Shanghai", "Unknown/Zone"] {
            assert!(Zone::load(zone).is_err());
        }
        assert_eq!(
            Zone::load("UTC").unwrap().day_start("1970-01-01").unwrap(),
            0
        );
    }
    #[test]
    fn system_database_respects_dst_short_long_days_and_fixed_tail() {
        if let Ok(zone) = Zone::load("America/New_York") {
            assert_eq!(
                zone.day_start("2026-03-09").unwrap() - zone.day_start("2026-03-08").unwrap(),
                23 * 3600 * 1000
            );
            assert_eq!(
                zone.day_start("2026-11-02").unwrap() - zone.day_start("2026-11-01").unwrap(),
                25 * 3600 * 1000
            );
            assert!(
                zone.validate_local_datetime("2026-03-08T02:30:00-05:00")
                    .is_err()
            );
            assert!(
                zone.validate_local_datetime("2026-11-01T01:30:00-04:00")
                    .is_ok()
            );
            assert!(
                zone.validate_local_datetime("2026-11-01T01:30:00-05:00")
                    .is_ok()
            );
        }
        if let Ok(zone) = Zone::load("Asia/Shanghai") {
            assert!(
                zone.validate_local_datetime("2026-10-03T09:00:00+08:00")
                    .is_ok()
            );
            assert!(
                zone.validate_local_datetime("2026-10-03T09:00:00+09:00")
                    .is_err()
            );
        }
    }
}
