//! Retries retain the exact request and deadlines; only classified transient failures retry.
use crate::{McpError, Result};
use std::time::Duration;

pub const WAIT_BUDGET_MS: u64 = 15 * 60 * 1000;
pub const MAX_QR_CODES: u32 = 3;
const RETRY_BUDGET_MS: u64 = 30_000;
const REQUEST_BUDGET_MS: u64 = 10_000;

pub fn transient(error: &McpError) -> bool {
    matches!(
        error,
        McpError::PairTransport { retryable: true }
            | McpError::ApiResponse {
                status: 502..=504,
                ..
            }
            | McpError::RateLimited { .. }
    )
}

pub fn retry<T>(
    deadline: u64,
    mut operation: impl FnMut(Duration) -> Result<T>,
    mut clock: impl FnMut() -> u64,
    mut wait: impl FnMut(Duration),
    mut report: impl FnMut(),
) -> Result<T> {
    let end = deadline.min(clock().saturating_add(RETRY_BUDGET_MS));
    let mut last = None;
    for attempt in 0..4 {
        let remaining = end.saturating_sub(clock());
        if remaining == 0 {
            break;
        }
        match operation(Duration::from_millis(remaining.min(REQUEST_BUDGET_MS))) {
            Ok(value) => return Ok(value),
            Err(error) => {
                if !transient(&error) || attempt == 3 {
                    return Err(error);
                }
                let delay = match &error {
                    McpError::RateLimited {
                        retry_after_seconds,
                    } => retry_after_seconds.saturating_mul(1000),
                    _ => 1000 << attempt,
                };
                if delay >= end.saturating_sub(clock()) {
                    return Err(error);
                }
                last = Some(error);
                report();
                wait(Duration::from_millis(delay));
            }
        }
    }
    Err(last.unwrap_or_else(|| McpError::Invalid("配对请求原期限已到；未确认新连接".into())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn transient_retry_keeps_request_and_clips_timeout_to_original_deadline() {
        let now = Cell::new(1_u64);
        let attempts = Cell::new(0);
        let request = "SYNTHETIC_SECRET_NOT_LIVE";
        let value = retry(
            2500,
            |timeout| {
                assert!(timeout.as_millis() <= 2499);
                assert_eq!(request, "SYNTHETIC_SECRET_NOT_LIVE");
                attempts.set(attempts.get() + 1);
                if attempts.get() == 2 {
                    Ok(42)
                } else {
                    Err(McpError::PairTransport { retryable: true })
                }
            },
            || now.get(),
            |delay| now.set(now.get() + delay.as_millis() as u64),
            || {},
        )
        .unwrap();
        assert_eq!(value, 42);
        assert_eq!(attempts.get(), 2);
        assert_eq!(now.get(), 1001);
    }

    #[test]
    fn permanent_errors_and_long_retry_after_never_retry() {
        for error in [
            McpError::PairTransport { retryable: false },
            McpError::ApiResponse {
                status: 401,
                code: "DENIED".into(),
                message: "fixed".into(),
            },
            McpError::ApiResponse {
                status: 403,
                code: "DENIED".into(),
                message: "fixed".into(),
            },
            McpError::RateLimited {
                retry_after_seconds: 60,
            },
        ] {
            let mut next = Some(error);
            assert!(
                retry::<()>(
                    60_000,
                    |_| Err(next.take().unwrap()),
                    || 1,
                    |_| panic!("must not wait"),
                    || {}
                )
                .is_err()
            );
        }
    }

    #[test]
    fn failure_is_bounded_and_expired_operation_is_not_called() {
        let now = Cell::new(1);
        let calls = Cell::new(0);
        assert!(
            retry::<()>(
                60_000,
                |_| {
                    calls.set(calls.get() + 1);
                    Err(McpError::PairTransport { retryable: true })
                },
                || now.get(),
                |d| now.set(now.get() + d.as_millis() as u64),
                || {}
            )
            .is_err()
        );
        assert_eq!(calls.get(), 4);
        assert_eq!(now.get(), 7001);
        assert!(retry::<()>(1, |_| panic!("expired"), || 1, |_| panic!("expired"), || {}).is_err());
    }
}
