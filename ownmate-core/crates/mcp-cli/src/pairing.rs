//! Bounded retries retain the same approved, validated session and original deadline.
use crate::storage::ExternalSession;
use crate::{McpError, Result};

const MAX_ATTEMPTS: usize = 6;

pub fn retry_before_deadline<T>(
    deadline: u64,
    mut operation: impl FnMut() -> Result<T>,
    mut clock: impl FnMut() -> u64,
    mut wait: impl FnMut(),
) -> Result<T> {
    let mut last = None;
    for attempt in 0..MAX_ATTEMPTS {
        if clock() >= deadline {
            break;
        }
        match operation() {
            Ok(value) => return Ok(value),
            Err(error) => last = Some(error),
        }
        if attempt + 1 < MAX_ATTEMPTS {
            wait();
        }
    }
    Err(last
        .unwrap_or_else(|| McpError::Api("客户端完成期限已到；新连接尚未生效，请重新扫码".into())))
}

pub fn validate_modes(modes: &[String]) -> Result<()> {
    if modes.is_empty()
        || modes.len() > 2
        || modes
            .iter()
            .any(|mode| mode != "temporary" && mode != "trusted")
        || (modes.len() == 2 && modes[0] == modes[1])
    {
        return Err(McpError::Invalid("客户端支持的授权方式无效".into()));
    }
    Ok(())
}

pub fn validate_session_mode(session: &ExternalSession, now: u64) -> Result<()> {
    if session.access_token.is_empty() || session.access_expires_at <= now {
        return Err(McpError::Invalid("授权访问令牌无效或已到期".into()));
    }
    if session.trust_mode == "trusted" {
        crate::storage::validate_trusted(session)?;
        if session.grant_expires_at.is_some() {
            return Err(McpError::Invalid("可信授权期限结构无效".into()));
        }
    } else if session.trust_mode == "temporary" {
        if session.refresh_token.is_some()
            || session
                .grant_expires_at
                .is_none_or(|expiry| expiry <= now || expiry > now.saturating_add(30 * 60 * 1000))
            || session
                .grant_expires_at
                .is_some_and(|expiry| session.access_expires_at > expiry)
        {
            return Err(McpError::Invalid("临时授权凭据结构无效".into()));
        }
    } else {
        return Err(McpError::Invalid("授权方式无效".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn retries_reuse_the_same_session_and_never_extend_the_deadline() {
        let session = crate::reminders::fixture_session();
        let original = serde_json::to_string(&session).unwrap();
        let now = Cell::new(1);
        let attempts = Cell::new(0);
        retry_before_deadline(
            20,
            || {
                attempts.set(attempts.get() + 1);
                assert_eq!(serde_json::to_string(&session).unwrap(), original);
                if attempts.get() < 3 {
                    Err(McpError::Credential("synthetic denial".into()))
                } else {
                    Ok(())
                }
            },
            || now.get(),
            || now.set(now.get() + 5),
        )
        .unwrap();
        assert_eq!(attempts.get(), 3);
        assert_eq!(now.get(), 11);
        assert!(
            retry_before_deadline::<()>(
                now.get(),
                || panic!("expired retry"),
                || now.get(),
                || panic!("wait")
            )
            .is_err()
        );
    }

    #[test]
    fn persistent_failure_is_bounded_and_does_not_convert_to_temporary() {
        let attempts = Cell::new(0);
        let error = retry_before_deadline::<()>(
            100,
            || {
                attempts.set(attempts.get() + 1);
                Err(McpError::Credential("synthetic denial".into()))
            },
            || 1,
            || {},
        )
        .unwrap_err();
        assert_eq!(attempts.get(), MAX_ATTEMPTS);
        assert!(matches!(error, McpError::Credential(_)));
    }

    #[test]
    fn temporary_expiry_is_absolute_and_mode_shapes_fail_closed() {
        let mut session = crate::reminders::fixture_session();
        session.grant_expires_at = Some(1800001);
        session.access_expires_at = 1800001;
        assert!(validate_session_mode(&session, 1).is_ok());
        assert!(validate_session_mode(&session, 1800001).is_err());
        session.refresh_token = Some("synthetic".into());
        assert!(validate_session_mode(&session, 1).is_err());
        for modes in [
            vec![],
            vec!["other".into()],
            vec!["temporary".into(), "temporary".into()],
        ] {
            assert!(validate_modes(&modes).is_err());
        }
    }
}
