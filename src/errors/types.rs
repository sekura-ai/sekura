use thiserror::Error;

#[derive(Debug, Error)]
pub enum SekuraError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Authentication error: {0}")]
    Authentication(String),

    #[error("Permission error: {0}")]
    Permission(String),

    #[error("LLM API error: {0}")]
    LLMApi(String),

    #[error("Rate limited: {0}")]
    RateLimit(String),

    #[error("Billing/quota error: {0}")]
    Billing(String),

    #[error("Container error: {0}")]
    Container(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Output validation error: {0}")]
    OutputValidation(String),

    #[error("Git error: {0}")]
    Git(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Execution limit reached: {0}")]
    ExecutionLimit(String),

    #[error("Invalid target: {0}")]
    InvalidTarget(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("YAML error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("Docker error: {0}")]
    Docker(#[from] bollard::errors::Error),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Prompt error: {0}")]
    Prompt(String),

    #[error("Browser error: {0}")]
    Browser(String),
}
