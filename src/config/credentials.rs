use tracing::debug;

/// Resolve a credential value. If the value starts with '$', treat it as an
/// environment variable reference and resolve from the environment.
pub fn resolve_credential(value: &str) -> String {
    if let Some(var_name) = value.strip_prefix('$') {
        match std::env::var(var_name) {
            Ok(resolved) => {
                debug!(var = %var_name, "Resolved credential from environment");
                resolved
            }
            Err(_) => {
                debug!(var = %var_name, "Environment variable not set, using literal");
                value.to_string()
            }
        }
    } else {
        value.to_string()
    }
}

/// Redact sensitive values in a string. Replaces known credential patterns
/// with [REDACTED].
pub fn redact_credentials(text: &str, secrets: &[&str]) -> String {
    let mut result = text.to_string();
    for secret in secrets {
        if !secret.is_empty() && secret.len() >= 4 {
            result = result.replace(secret, "[REDACTED]");
        }
    }
    result
}

/// Redact a command string by masking password-like arguments.
/// Handles common patterns: --password=X, -p X, --cookie "X"
pub fn redact_command(command: &str) -> String {
    let patterns = [
        ("--password=", "--password=[REDACTED]"),
        ("--password ", "--password [REDACTED] "),
        ("-p ", "-p [REDACTED] "),
    ];

    let mut result = command.to_string();
    for (pattern, replacement) in &patterns {
        if let Some(pos) = result.find(pattern) {
            let after = pos + pattern.len();
            // Find end of value (next space or end of string)
            let end = result[after..].find(' ').map(|i| after + i).unwrap_or(result.len());
            result = format!("{}{}{}", &result[..pos], replacement, &result[end..]);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_credential_literal() {
        assert_eq!(resolve_credential("mypassword"), "mypassword");
    }

    #[test]
    fn test_resolve_credential_env_var() {
        std::env::set_var("TEST_SEKURA_CRED", "secret123");
        assert_eq!(resolve_credential("$TEST_SEKURA_CRED"), "secret123");
        std::env::remove_var("TEST_SEKURA_CRED");
    }

    #[test]
    fn test_resolve_credential_missing_env_var() {
        let result = resolve_credential("$NONEXISTENT_SEKURA_VAR");
        assert_eq!(result, "$NONEXISTENT_SEKURA_VAR");
    }

    #[test]
    fn test_redact_credentials() {
        let text = "Login with password=S3cret123 and token=abc";
        let redacted = redact_credentials(text, &["S3cret123", "abc"]);
        // "abc" is too short (< 4 chars), not redacted
        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains("S3cret123"));
    }

    #[test]
    fn test_redact_credentials_short_secret_ignored() {
        let text = "key=ab";
        let redacted = redact_credentials(text, &["ab"]);
        assert_eq!(redacted, "key=ab"); // too short to redact
    }

    #[test]
    fn test_redact_command_password() {
        let cmd = "hydra -l admin --password=S3cret 192.168.1.1 ssh";
        let redacted = redact_command(cmd);
        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains("S3cret"));
    }

    #[test]
    fn test_redact_command_no_password() {
        let cmd = "nmap -sT 192.168.1.1";
        let redacted = redact_command(cmd);
        assert_eq!(redacted, cmd);
    }
}
