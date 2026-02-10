use super::types::SekuraError;

#[derive(Debug, Clone)]
pub struct ErrorClassification {
    pub error_type: &'static str,
    pub retryable: bool,
}

impl SekuraError {
    /// Classify this error to determine its type and whether it can be retried.
    pub fn classify(&self) -> ErrorClassification {
        match self {
            // Retryable errors
            SekuraError::RateLimit(_) => ErrorClassification {
                error_type: "RateLimitError",
                retryable: true,
            },
            SekuraError::Billing(_) => ErrorClassification {
                error_type: "BillingError",
                retryable: true,
            },
            SekuraError::Network(_) => ErrorClassification {
                error_type: "NetworkError",
                retryable: true,
            },
            SekuraError::Timeout(_) => ErrorClassification {
                error_type: "TimeoutError",
                retryable: true,
            },
            SekuraError::OutputValidation(_) => ErrorClassification {
                error_type: "OutputValidationError",
                retryable: true,
            },
            SekuraError::LLMApi(_) => ErrorClassification {
                error_type: "LLMApiError",
                retryable: true,
            },

            // Non-retryable errors
            SekuraError::Authentication(_) => ErrorClassification {
                error_type: "AuthenticationError",
                retryable: false,
            },
            SekuraError::Permission(_) => ErrorClassification {
                error_type: "PermissionError",
                retryable: false,
            },
            SekuraError::Config(_) => ErrorClassification {
                error_type: "ConfigError",
                retryable: false,
            },
            SekuraError::InvalidTarget(_) => ErrorClassification {
                error_type: "InvalidTargetError",
                retryable: false,
            },
            SekuraError::ExecutionLimit(_) => ErrorClassification {
                error_type: "ExecutionLimitError",
                retryable: false,
            },

            // Default: retryable
            SekuraError::Container(_) => ErrorClassification {
                error_type: "ContainerError",
                retryable: true,
            },
            SekuraError::Git(_) => ErrorClassification {
                error_type: "GitError",
                retryable: true,
            },
            SekuraError::Io(_) => ErrorClassification {
                error_type: "IoError",
                retryable: true,
            },
            SekuraError::Json(_) => ErrorClassification {
                error_type: "JsonError",
                retryable: true,
            },
            SekuraError::Yaml(_) => ErrorClassification {
                error_type: "YamlError",
                retryable: true,
            },
            SekuraError::Docker(_) => ErrorClassification {
                error_type: "DockerError",
                retryable: true,
            },
            SekuraError::Database(_) => ErrorClassification {
                error_type: "DatabaseError",
                retryable: true,
            },
            SekuraError::Internal(_) => ErrorClassification {
                error_type: "InternalError",
                retryable: true,
            },
            SekuraError::Prompt(_) => ErrorClassification {
                error_type: "PromptError",
                retryable: false,
            },
        }
    }
}
