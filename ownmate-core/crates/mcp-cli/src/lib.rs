pub mod api;
pub mod command_cache;
pub mod crypto;
pub mod mcp;
pub mod projection;
pub mod protocol;
pub mod query;
pub mod reminder_interface;
pub mod reminders;
pub mod storage;
pub mod timezone;

use thiserror::Error;

pub const DEFAULT_API_BASE_URL: &str = "https://api.ownmate.space";

#[derive(Debug, Error)]
pub enum McpError {
    #[error("{0}")]
    Invalid(String),
    #[error("网络请求失败: {0}")]
    Network(String),
    #[error("OwnMate API 拒绝请求: {0}")]
    Api(String),
    #[error("OwnMate API 拒绝请求（HTTP {status}, {code}）: {message}")]
    ApiResponse {
        status: u16,
        code: String,
        message: String,
    },
    #[error("OwnMate API 限流，请在 {retry_after_seconds} 秒后以原 requestId 重试")]
    RateLimited { retry_after_seconds: u64 },
    #[error("密码学验证失败")]
    Crypto,
    #[error("系统凭据库不可用: {0}")]
    Credential(String),
    #[error("JSON 数据无效: {0}")]
    Json(#[from] serde_json::Error),
    #[error("I/O 失败: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, McpError>;
