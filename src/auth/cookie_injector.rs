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
