use crate::errors::SekuraError;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct TotpResult {
    pub code: String,
    pub timestamp: u64,
    pub seconds_remaining: u32,
}

/// Generate a TOTP code from a base32-encoded secret.
/// Uses RFC 6238 with SHA-1 and 30-second time steps.
pub fn generate_totp(secret: &str) -> Result<TotpResult, SekuraError> {
    // Clean the secret (remove spaces, hyphens)
    let clean_secret: String = secret.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_uppercase();

    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        clean_secret.as_bytes().to_vec(),
    ).map_err(|e| SekuraError::Authentication(format!("Invalid TOTP secret: {}", e)))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| SekuraError::Internal(format!("System time error: {}", e)))?;

    let timestamp = now.as_secs();
    let code = totp.generate(timestamp);
    let seconds_remaining = 30 - (timestamp % 30) as u32;

    Ok(TotpResult {
        code,
        timestamp,
        seconds_remaining,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_generates_6_digits() {
        // Use a valid base32 secret
        let result = generate_totp("JBSWY3DPEHPK3PXP");
        assert!(result.is_ok());
        let totp = result.unwrap();
        assert_eq!(totp.code.len(), 6);
        assert!(totp.code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_totp_seconds_remaining() {
        let result = generate_totp("JBSWY3DPEHPK3PXP").unwrap();
        assert!(result.seconds_remaining > 0);
        assert!(result.seconds_remaining <= 30);
    }

    #[test]
    fn test_totp_cleans_secret() {
        // Secret with spaces and hyphens should be cleaned
        let result = generate_totp("JBSW Y3DP-EHPK-3PXP");
        assert!(result.is_ok());
        let totp = result.unwrap();
        assert_eq!(totp.code.len(), 6);
    }

    #[test]
    fn test_totp_timestamp_is_recent() {
        let result = generate_totp("JBSWY3DPEHPK3PXP").unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Timestamp should be within 1 second of now
        assert!((result.timestamp as i64 - now as i64).abs() <= 1);
    }
}
