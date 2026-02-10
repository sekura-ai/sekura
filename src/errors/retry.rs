use std::time::Duration;
use std::future::Future;

use super::classification::ErrorClassification;
use super::types::SekuraError;
use tracing::{warn, info};

impl ErrorClassification {
    /// Calculate the retry delay for this error classification based on the
    /// current attempt number (0-indexed).
    ///
    /// - RateLimitError: 30s + (attempt * 10s), capped at 120s
    /// - BillingError: 300s * attempt, capped at 1800s
    /// - Default: exponential backoff 2^attempt + random jitter (0-1s), capped at 30s
    pub fn retry_delay(&self, attempt: u32) -> Duration {
        match self.error_type {
            "RateLimitError" => {
                let secs = 30 + (attempt as u64 * 10);
                Duration::from_secs(secs.min(120))
            }
            "BillingError" => {
                let secs = 300 * (attempt as u64);
                Duration::from_secs(secs.min(1800))
            }
            _ => {
                let base: f64 = 2.0_f64.powi(attempt as i32);
                let jitter: f64 = rand::random::<f64>();
                let secs = (base + jitter).min(30.0);
                Duration::from_secs_f64(secs)
            }
        }
    }
}

/// Retry configuration for pipeline operations.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub pipeline_testing: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            pipeline_testing: false,
        }
    }
}

/// Execute an async operation with retry logic.
///
/// Retries only if the error is classified as retryable and we haven't
/// exceeded max_retries. In pipeline_testing mode, retries are skipped.
pub async fn with_retry<F, Fut, T>(
    operation_name: &str,
    config: &RetryConfig,
    mut factory: F,
) -> Result<T, SekuraError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, SekuraError>>,
{
    let max_attempts = if config.pipeline_testing {
        1 // No retries in testing mode
    } else {
        config.max_retries + 1
    };

    let mut last_error = None;

    for attempt in 0..max_attempts {
        match factory().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                let classification = e.classify();

                if !classification.retryable || attempt + 1 >= max_attempts {
                    if !classification.retryable {
                        warn!(
                            operation = operation_name,
                            error_type = classification.error_type,
                            "Non-retryable error, failing immediately"
                        );
                    } else {
                        warn!(
                            operation = operation_name,
                            attempt = attempt + 1,
                            max = max_attempts,
                            "Max retries exhausted"
                        );
                    }
                    return Err(e);
                }

                let delay = classification.retry_delay(attempt);
                warn!(
                    operation = operation_name,
                    attempt = attempt + 1,
                    max = max_attempts,
                    error_type = classification.error_type,
                    delay_secs = delay.as_secs(),
                    error = %e,
                    "Retrying after error"
                );

                tokio::time::sleep(delay).await;
                last_error = Some(e);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| SekuraError::Internal("Retry loop exited unexpectedly".into())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[test]
    fn test_retry_delay_rate_limit() {
        let class = ErrorClassification { error_type: "RateLimitError", retryable: true };
        assert_eq!(class.retry_delay(0), Duration::from_secs(30));
        assert_eq!(class.retry_delay(1), Duration::from_secs(40));
        assert_eq!(class.retry_delay(9), Duration::from_secs(120)); // capped
    }

    #[test]
    fn test_retry_delay_billing() {
        let class = ErrorClassification { error_type: "BillingError", retryable: true };
        assert_eq!(class.retry_delay(0), Duration::from_secs(0));
        assert_eq!(class.retry_delay(1), Duration::from_secs(300));
        assert_eq!(class.retry_delay(10), Duration::from_secs(1800)); // capped
    }

    #[test]
    fn test_retry_delay_default_exponential() {
        let class = ErrorClassification { error_type: "NetworkError", retryable: true };
        let d0 = class.retry_delay(0);
        let d1 = class.retry_delay(1);
        // Attempt 0: 2^0 + jitter = ~1-2s
        assert!(d0.as_secs_f64() >= 1.0 && d0.as_secs_f64() < 3.0);
        // Attempt 1: 2^1 + jitter = ~2-3s
        assert!(d1.as_secs_f64() >= 2.0 && d1.as_secs_f64() < 4.0);
    }

    #[tokio::test]
    async fn test_with_retry_succeeds_first_try() {
        let config = RetryConfig { max_retries: 3, pipeline_testing: false };
        let result = with_retry("test", &config, || async {
            Ok::<_, SekuraError>(42)
        }).await;
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn test_with_retry_non_retryable_fails_immediately() {
        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = attempts.clone();
        let config = RetryConfig { max_retries: 3, pipeline_testing: false };

        let result = with_retry("test", &config, || {
            let attempts = attempts_clone.clone();
            async move {
                attempts.fetch_add(1, Ordering::SeqCst);
                Err::<(), _>(SekuraError::Config("bad config".into()))
            }
        }).await;

        assert!(result.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 1); // Only 1 attempt
    }

    #[tokio::test]
    async fn test_with_retry_pipeline_testing_no_retries() {
        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = attempts.clone();
        let config = RetryConfig { max_retries: 3, pipeline_testing: true };

        let result = with_retry("test", &config, || {
            let attempts = attempts_clone.clone();
            async move {
                attempts.fetch_add(1, Ordering::SeqCst);
                Err::<(), _>(SekuraError::Network("timeout".into()))
            }
        }).await;

        assert!(result.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 1); // No retries in test mode
    }
}
