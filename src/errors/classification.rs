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
            SekuraError::Browser(_) => ErrorClassification {
                error_type: "BrowserError",
                retryable: true,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_is_retryable() {
        let err = SekuraError::RateLimit("too many requests".into());
        let class = err.classify();
        assert!(class.retryable);
        assert_eq!(class.error_type, "RateLimitError");
    }

    #[test]
    fn test_auth_error_not_retryable() {
        let err = SekuraError::Authentication("bad key".into());
        let class = err.classify();
        assert!(!class.retryable);
        assert_eq!(class.error_type, "AuthenticationError");
    }

    #[test]
    fn test_config_error_not_retryable() {
        let err = SekuraError::Config("invalid config".into());
        let class = err.classify();
        assert!(!class.retryable);
    }

    #[test]
    fn test_network_error_retryable() {
        let err = SekuraError::Network("connection refused".into());
        assert!(err.classify().retryable);
    }

    #[test]
    fn test_timeout_retryable() {
        let err = SekuraError::Timeout("timed out".into());
        assert!(err.classify().retryable);
    }

    #[test]
    fn test_billing_retryable() {
        let err = SekuraError::Billing("quota exceeded".into());
        assert!(err.classify().retryable);
    }

    #[test]
    fn test_permission_not_retryable() {
        let err = SekuraError::Permission("access denied".into());
        assert!(!err.classify().retryable);
    }

    #[test]
    fn test_execution_limit_not_retryable() {
        let err = SekuraError::ExecutionLimit("max iterations".into());
        assert!(!err.classify().retryable);
    }

    #[test]
    fn test_container_retryable() {
        let err = SekuraError::Container("not running".into());
        assert!(err.classify().retryable);
    }

    #[test]
    fn test_browser_retryable() {
        let err = SekuraError::Browser("crashed".into());
        assert!(err.classify().retryable);
    }
}
