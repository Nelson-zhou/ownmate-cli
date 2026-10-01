pub mod api;
pub mod crypto;
pub mod mcp;
pub mod protocol;
pub mod storage;

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
