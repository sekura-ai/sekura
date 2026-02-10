use std::collections::HashMap;
use std::sync::LazyLock;
use crate::pipeline::state::ScanContext;

static COOKIE_FLAGS: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    HashMap::from([
        ("curl", "-b {cookie_file}"),
        ("sqlmap", "--cookie='{cookie_string}'"),
        ("gobuster", "-H 'Cookie: {cookie_string}'"),
        ("ffuf", "-H 'Cookie: {cookie_string}'"),
        ("wfuzz", "-b '{cookie_string}'"),
        ("nikto", ""),
        ("dirb", "-c '{cookie_string}'"),
        ("whatweb", "--cookie='{cookie_string}'"),
        ("hydra", ""),
        ("nmap", ""),
        ("masscan", ""),
    ])
});

/// Inject cookies into a tool command based on tool-specific flag patterns.
pub fn inject_cookies(command: &str, tool: &str, context: &ScanContext) -> String {
    // Skip if no cookies available
    let (cookie_string, cookie_file) = match (&context.cookie_string, &context.cookie_file) {
        (None, None) => return command.to_string(),
        (cs, cf) => (cs, cf),
    };

    // Get tool-specific cookie flag
    let flag_template = match COOKIE_FLAGS.get(tool) {
        Some(f) if !f.is_empty() => *f,
        _ => return command.to_string(),
    };

    // Check if command already has cookie flags
    if command.contains("-b ") || command.contains("--cookie") || command.contains("Cookie:") {
        return command.to_string();
    }

    // Resolve cookie flag
    let mut flag = flag_template.to_string();
    if let Some(cs) = cookie_string {
        flag = flag.replace("{cookie_string}", cs);
    }
    if let Some(cf) = cookie_file {
        flag = flag.replace("{cookie_file}", &cf.to_string_lossy());
    }

    // Don't append if still has unresolved placeholders
    if flag.contains('{') {
        return command.to_string();
    }

    format!("{} {}", command.trim(), flag)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_context(cookie_string: Option<&str>, cookie_file: Option<&str>) -> ScanContext {
        use std::collections::HashMap;
        ScanContext {
            target: "http://example.com".to_string(),
            target_url: None,
            open_ports: vec![],
            web_port: None,
            cookie_string: cookie_string.map(|s| s.to_string()),
            cookie_file: cookie_file.map(|s| PathBuf::from(s)),
            authenticated: cookie_string.is_some(),
            code_analysis: None,
            recon_data: None,
            intensity: crate::config::Intensity::Standard,
            extra: HashMap::new(),
        }
    }

    #[test]
    fn test_inject_cookie_sqlmap() {
        let ctx = make_context(Some("session=abc123"), None);
        let result = inject_cookies("sqlmap -u http://example.com", "sqlmap", &ctx);
        assert!(result.contains("--cookie='session=abc123'"));
    }

    #[test]
    fn test_inject_cookie_gobuster() {
        let ctx = make_context(Some("session=abc123"), None);
        let result = inject_cookies("gobuster dir -u http://example.com", "gobuster", &ctx);
        assert!(result.contains("Cookie: session=abc123"));
    }

    #[test]
    fn test_inject_cookie_nmap() {
        let ctx = make_context(Some("session=abc123"), None);
        let result = inject_cookies("nmap -sV example.com", "nmap", &ctx);
        // nmap doesn't support cookie injection, command should be unchanged
        assert_eq!(result, "nmap -sV example.com");
    }

    #[test]
    fn test_no_duplicate_injection() {
        let ctx = make_context(Some("session=abc123"), None);
        let result = inject_cookies("sqlmap -u http://example.com --cookie='existing'", "sqlmap", &ctx);
        // Should not add another --cookie flag
        assert_eq!(result.matches("--cookie").count(), 1);
    }

    #[test]
    fn test_no_cookies_available() {
        let ctx = make_context(None, None);
        let result = inject_cookies("sqlmap -u http://example.com", "sqlmap", &ctx);
        assert_eq!(result, "sqlmap -u http://example.com");
    }

    #[test]
    fn test_inject_cookie_curl_with_file() {
        let ctx = make_context(None, Some("/tmp/cookies.txt"));
        let result = inject_cookies("curl http://example.com", "curl", &ctx);
        assert!(result.contains("-b /tmp/cookies.txt"));
    }

    #[test]
    fn test_inject_cookie_unknown_tool() {
        let ctx = make_context(Some("session=abc123"), None);
        let result = inject_cookies("unknowntool http://example.com", "unknowntool", &ctx);
        assert_eq!(result, "unknowntool http://example.com");
    }

    #[test]
    fn test_inject_cookie_ffuf() {
        let ctx = make_context(Some("token=xyz"), None);
        let result = inject_cookies("ffuf -u http://example.com/FUZZ", "ffuf", &ctx);
        assert!(result.contains("Cookie: token=xyz"));
    }

    #[test]
    fn test_no_duplicate_cookie_header() {
        let ctx = make_context(Some("session=abc"), None);
        let result = inject_cookies("ffuf -u http://x.com -H 'Cookie: old'", "ffuf", &ctx);
        // Already has Cookie: header, should not add another
        assert_eq!(result.matches("Cookie:").count(), 1);
    }
}
