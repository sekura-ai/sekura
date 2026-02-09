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
