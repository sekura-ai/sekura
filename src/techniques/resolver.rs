use crate::pipeline::state::ScanContext;

pub fn resolve_command(template: &str, context: &ScanContext) -> String {
    let mut cmd = template.to_string();
    cmd = cmd.replace("{target}", &context.target);

    if let Some(url) = &context.target_url {
        cmd = cmd.replace("{target_url}", url);
    }

    if !context.open_ports.is_empty() {
        let ports: String = context.open_ports.iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        cmd = cmd.replace("{open_ports}", &ports);
    }

    cmd = cmd.replace("{intensity}", context.intensity.as_str());

    if let Some(cookie) = &context.cookie_string {
        cmd = cmd.replace("{cookie_string}", cookie);
    }

    if let Some(cookie_file) = &context.cookie_file {
        cmd = cmd.replace("{cookie_file}", &cookie_file.to_string_lossy());
    }

    // Ensure cookie placeholders resolve to empty for unauthenticated scans
    if context.cookie_string.is_none() {
        cmd = cmd.replace("{cookie_string}", "");
    }
    if context.cookie_file.is_none() {
        cmd = cmd.replace("{cookie_file}", "");
    }

    if let Some(web_port) = context.web_port {
        cmd = cmd.replace("{web_port}", &web_port.to_string());
    }

    // Replace any extra context variables
    for (key, value) in &context.extra {
        cmd = cmd.replace(&format!("{{{}}}", key), value);
    }

    cmd
}

/// Returns true if the command still has unresolved {placeholders}
pub fn has_unresolved(command: &str) -> bool {
    let re = regex::Regex::new(r"\{[a-z_]+\}").unwrap();
    re.is_match(command)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Intensity;

    fn make_context() -> ScanContext {
        ScanContext {
            target: "192.168.1.1".to_string(),
            target_url: Some("http://192.168.1.1:8080".to_string()),
            open_ports: vec![22, 80, 443, 8080],
            web_port: Some(8080),
            intensity: Intensity::Standard,
            cookie_string: Some("session=abc123".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn test_resolve_target() {
        let ctx = make_context();
        let cmd = resolve_command("nmap -sV {target}", &ctx);
        assert_eq!(cmd, "nmap -sV 192.168.1.1");
    }

    #[test]
    fn test_resolve_target_url() {
        let ctx = make_context();
        let cmd = resolve_command("nikto -h {target_url}", &ctx);
        assert_eq!(cmd, "nikto -h http://192.168.1.1:8080");
    }

    #[test]
    fn test_resolve_open_ports() {
        let ctx = make_context();
        let cmd = resolve_command("nmap -p {open_ports} {target}", &ctx);
        assert_eq!(cmd, "nmap -p 22,80,443,8080 192.168.1.1");
    }

    #[test]
    fn test_resolve_intensity() {
        let ctx = make_context();
        let cmd = resolve_command("scan --intensity {intensity}", &ctx);
        assert_eq!(cmd, "scan --intensity standard");
    }

    #[test]
    fn test_resolve_cookie() {
        let ctx = make_context();
        let cmd = resolve_command("curl -b '{cookie_string}' {target_url}", &ctx);
        assert_eq!(cmd, "curl -b 'session=abc123' http://192.168.1.1:8080");
    }

    #[test]
    fn test_resolve_web_port() {
        let ctx = make_context();
        let cmd = resolve_command("nmap -p {web_port} {target}", &ctx);
        assert_eq!(cmd, "nmap -p 8080 192.168.1.1");
    }

    #[test]
    fn test_has_unresolved_true() {
        assert!(has_unresolved("nmap {target} -p {missing_var}"));
    }

    #[test]
    fn test_has_unresolved_false() {
        assert!(!has_unresolved("nmap 192.168.1.1 -p 80"));
    }

    #[test]
    fn test_resolve_extra_vars() {
        let mut ctx = make_context();
        ctx.extra.insert("domain".to_string(), "example.com".to_string());
        let cmd = resolve_command("dig axfr @{target} {domain}", &ctx);
        assert_eq!(cmd, "dig axfr @192.168.1.1 example.com");
    }

    #[test]
    fn test_cookie_string_resolves_empty_when_none() {
        let mut ctx = make_context();
        ctx.cookie_string = None;
        let cmd = resolve_command("python3 scanner.py --cookie '{cookie_string}'", &ctx);
        assert_eq!(cmd, "python3 scanner.py --cookie ''");
        assert!(!has_unresolved(&cmd));
    }

    #[test]
    fn test_cookie_file_resolves_empty_when_none() {
        let mut ctx = make_context();
        ctx.cookie_file = None;
        let cmd = resolve_command("curl -b {cookie_file} {target_url}", &ctx);
        assert_eq!(cmd, "curl -b  http://192.168.1.1:8080");
        assert!(!has_unresolved(&cmd));
    }
}
