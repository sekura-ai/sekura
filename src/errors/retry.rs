use std::time::Duration;

use super::classification::ErrorClassification;

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
