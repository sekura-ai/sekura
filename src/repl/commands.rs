/// All slash commands supported by the REPL.
#[derive(Debug, Clone)]
pub enum SlashCommand {
    Scan {
        target: Option<String>,
        repo: Option<String>,
        intensity: Option<String>,
        provider: Option<String>,
        model: Option<String>,
        skip_whitebox: bool,
        skip_blackbox: bool,
        skip_exploit: bool,
        auth: Option<String>,
        file: Option<String>,
    },
    Status,
    Stop,
    Findings {
        severity_filter: Option<String>,
    },
    Agents,
    Config {
        key: Option<String>,
        value: Option<String>,
    },
    Report {
        scan_id: Option<String>,
        action: ReportAction,
    },
    History,
    Container {
        action: ContainerAction,
    },
    Serve {
        port: Option<u16>,
    },
    Init,
    Version,
    Clear,
    Help {
        command: Option<String>,
    },
    Exit,
}

#[derive(Debug, Clone)]
pub enum ReportAction {
    Summary,
    Findings { severity_filter: Option<String> },
    Finding(usize),
    Executive,
    Evidence(String),
    Full,
    Html,
}

#[derive(Debug, Clone)]
pub enum ContainerAction {
    Status,
    Start,
    Stop,
    Rebuild,
}

/// Description of a command for help display.
pub struct CommandHelp {
    pub name: &'static str,
    pub usage: &'static str,
    pub description: &'static str,
}

pub static COMMAND_HELP: &[CommandHelp] = &[
    CommandHelp {
        name: "scan",
        usage: "/scan --target <url> [--repo <path>] [--intensity quick|standard|thorough] [--provider <name>] [--model <id>] [--auth <cookie>] [--file <path.json>]",
        description: "Start a penetration test against a target. Use --auth to pass a session cookie for authenticated scanning. Use --file to load target config from a JSON file.",
    },
    CommandHelp {
        name: "status",
        usage: "/status",
        description: "Show current pipeline state, agents, and cost",
    },
    CommandHelp {
        name: "stop",
        usage: "/stop",
        description: "Cancel the currently running scan",
    },
    CommandHelp {
        name: "findings",
        usage: "/findings [--severity critical|high|medium|low|info]",
        description: "List findings from the last scan",
    },
    CommandHelp {
        name: "agents",
        usage: "/agents",
        description: "List all agents and their current status",
    },
    CommandHelp {
        name: "config",
        usage: "/config [key] [value]",
        description: "View or set defaults (provider, model, intensity)",
    },
    CommandHelp {
        name: "report",
        usage: "/report [findings [--severity X] | finding <N> | executive | evidence <category> | full | html] [--scan <id>]",
        description: "Summary dashboard (default), or drill into findings/evidence/executive/full/html",
    },
    CommandHelp {
        name: "history",
        usage: "/history",
        description: "Show scan history",
    },
    CommandHelp {
        name: "container",
        usage: "/container [status|start|stop|rebuild]",
        description: "Manage the Kali Docker container",
    },
    CommandHelp {
        name: "serve",
        usage: "/serve [--port N]",
        description: "Start the API server in the background",
    },
    CommandHelp {
        name: "init",
        usage: "/init",
        description: "Set up everything needed to scan (Docker image, container, LLM config)",
    },
    CommandHelp {
        name: "version",
        usage: "/version",
        description: "Show version and build info",
    },
    CommandHelp {
        name: "clear",
        usage: "/clear",
        description: "Clear the terminal screen",
    },
    CommandHelp {
        name: "help",
        usage: "/help [command]",
        description: "Show help for all or a specific command",
    },
    CommandHelp {
        name: "exit",
        usage: "/exit",
        description: "Quit the REPL",
    },
];

/// All command names for tab completion.
pub static COMMAND_NAMES: &[&str] = &[
    "/scan",
    "/status",
    "/stop",
    "/findings",
    "/agents",
    "/config",
    "/report",
    "/history",
    "/container",
    "/serve",
    "/init",
    "/version",
    "/clear",
    "/help",
    "/exit",
];

/// Parse a raw input line into a SlashCommand, or return an error message.
pub fn parse_command(input: &str) -> Result<SlashCommand, String> {
    let input = input.trim();
    if !input.starts_with('/') {
        return Err("Commands must start with /. Type /help for available commands.".into());
    }

    let parts: Vec<&str> = input.split_whitespace().collect();
    if parts.is_empty() {
        return Err("Empty command".into());
    }

    let cmd = parts[0];
    let args = &parts[1..];

    match cmd {
        "/scan" => parse_scan(args),
        "/status" => Ok(SlashCommand::Status),
        "/stop" => Ok(SlashCommand::Stop),
        "/findings" => parse_findings(args),
        "/agents" => Ok(SlashCommand::Agents),
        "/config" => parse_config(args),
        "/report" => parse_report(args),
        "/history" => Ok(SlashCommand::History),
        "/container" => parse_container(args),
        "/serve" => parse_serve(args),
        "/init" => Ok(SlashCommand::Init),
        "/version" => Ok(SlashCommand::Version),
        "/clear" => Ok(SlashCommand::Clear),
        "/help" => Ok(SlashCommand::Help {
            command: args.first().map(|s| s.trim_start_matches('/').to_string()),
        }),
        "/exit" | "/quit" | "/q" => Ok(SlashCommand::Exit),
        other => Err(format!("Unknown command: {}. Type /help for available commands.", other)),
    }
}

fn parse_scan(args: &[&str]) -> Result<SlashCommand, String> {
    let mut target = None;
    let mut repo = None;
    let mut intensity = None;
    let mut provider = None;
    let mut model = None;
    let mut skip_whitebox = false;
    let mut skip_blackbox = false;
    let mut skip_exploit = false;
    let mut auth = None;
    let mut file = None;

    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "--target" | "-t" => {
                i += 1;
                target = args.get(i).map(|s| s.to_string());
            }
            "--repo" | "-r" => {
                i += 1;
                repo = args.get(i).map(|s| s.to_string());
            }
            "--intensity" => {
                i += 1;
                intensity = args.get(i).map(|s| s.to_string());
            }
            "--provider" => {
                i += 1;
                provider = args.get(i).map(|s| s.to_string());
            }
            "--model" => {
                i += 1;
                model = args.get(i).map(|s| s.to_string());
            }
            "--auth" => {
                i += 1;
                auth = args.get(i).map(|s| s.to_string());
            }
            "--file" | "-f" => {
                i += 1;
                file = args.get(i).map(|s| s.to_string());
            }
            "--skip-whitebox" => skip_whitebox = true,
            "--skip-blackbox" => skip_blackbox = true,
            "--skip-exploit" => skip_exploit = true,
            other => {
                return Err(format!("Unknown flag for /scan: {}", other));
            }
        }
        i += 1;
    }

    Ok(SlashCommand::Scan {
        target,
        repo,
        intensity,
        provider,
        model,
        skip_whitebox,
        skip_blackbox,
        skip_exploit,
        auth,
        file,
    })
}

fn parse_findings(args: &[&str]) -> Result<SlashCommand, String> {
    let mut severity_filter = None;
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "--severity" => {
                i += 1;
                severity_filter = args.get(i).map(|s| s.to_string());
            }
            other => {
                return Err(format!("Unknown flag for /findings: {}", other));
            }
        }
        i += 1;
    }
    Ok(SlashCommand::Findings { severity_filter })
}

fn parse_config(args: &[&str]) -> Result<SlashCommand, String> {
    Ok(SlashCommand::Config {
        key: args.first().map(|s| s.to_string()),
        value: args.get(1).map(|s| s.to_string()),
    })
}

fn parse_container(args: &[&str]) -> Result<SlashCommand, String> {
    let action = match args.first().copied() {
        Some("status") | None => ContainerAction::Status,
        Some("start") => ContainerAction::Start,
        Some("stop") => ContainerAction::Stop,
        Some("rebuild") => ContainerAction::Rebuild,
        Some(other) => {
            return Err(format!(
                "Unknown container action: {}. Use: status, start, stop, rebuild",
                other
            ));
        }
    };
    Ok(SlashCommand::Container { action })
}

fn parse_report(args: &[&str]) -> Result<SlashCommand, String> {
    let mut scan_id = None;
    let mut i = 0;

    // Extract --scan flag from anywhere in args
    let mut filtered_args: Vec<&str> = Vec::new();
    while i < args.len() {
        if args[i] == "--scan" {
            i += 1;
            scan_id = args.get(i).map(|s| s.to_string());
        } else {
            filtered_args.push(args[i]);
        }
        i += 1;
    }

    let args = &filtered_args;

    if args.is_empty() {
        return Ok(SlashCommand::Report {
            scan_id,
            action: ReportAction::Summary,
        });
    }

    match args[0] {
        "findings" => {
            let mut severity_filter = None;
            let mut j = 1;
            while j < args.len() {
                match args[j] {
                    "--severity" => {
                        j += 1;
                        severity_filter = args.get(j).map(|s| s.to_string());
                    }
                    other => {
                        return Err(format!("Unknown flag for /report findings: {}", other));
                    }
                }
                j += 1;
            }
            Ok(SlashCommand::Report {
                scan_id,
                action: ReportAction::Findings { severity_filter },
            })
        }
        "finding" => {
            let n = args
                .get(1)
                .ok_or("Usage: /report finding <N>")?
                .parse::<usize>()
                .map_err(|_| "Finding number must be a positive integer".to_string())?;
            if n == 0 {
                return Err("Finding number is 1-indexed (starts at 1)".into());
            }
            Ok(SlashCommand::Report {
                scan_id,
                action: ReportAction::Finding(n),
            })
        }
        "executive" => Ok(SlashCommand::Report {
            scan_id,
            action: ReportAction::Executive,
        }),
        "evidence" => {
            let category = args
                .get(1)
                .ok_or("Usage: /report evidence <injection|xss|auth|ssrf|authz>")?
                .to_string();
            let valid = ["injection", "xss", "auth", "ssrf", "authz"];
            if !valid.contains(&category.as_str()) {
                return Err(format!(
                    "Unknown evidence category: {}. Valid: {}",
                    category,
                    valid.join(", ")
                ));
            }
            Ok(SlashCommand::Report {
                scan_id,
                action: ReportAction::Evidence(category),
            })
        }
        "full" => Ok(SlashCommand::Report {
            scan_id,
            action: ReportAction::Full,
        }),
        "html" => Ok(SlashCommand::Report {
            scan_id,
            action: ReportAction::Html,
        }),
        // If not a known sub-command, treat as scan_id (for backward compat)
        other => {
            if scan_id.is_some() {
                return Err(format!("Unknown report sub-command: {}", other));
            }
            Ok(SlashCommand::Report {
                scan_id: Some(other.to_string()),
                action: ReportAction::Summary,
            })
        }
    }
}

fn parse_serve(args: &[&str]) -> Result<SlashCommand, String> {
    let mut port = None;
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "--port" => {
                i += 1;
                if let Some(p) = args.get(i) {
                    port = Some(p.parse::<u16>().map_err(|_| format!("Invalid port: {}", p))?);
                }
            }
            other => {
                return Err(format!("Unknown flag for /serve: {}", other));
            }
        }
        i += 1;
    }
    Ok(SlashCommand::Serve { port })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_report_no_args() {
        let cmd = parse_command("/report").unwrap();
        match cmd {
            SlashCommand::Report { scan_id, action } => {
                assert!(scan_id.is_none());
                assert!(matches!(action, ReportAction::Summary));
            }
            _ => panic!("Expected Report"),
        }
    }

    #[test]
    fn test_parse_report_scan_id() {
        let cmd = parse_command("/report abc123").unwrap();
        match cmd {
            SlashCommand::Report { scan_id, action } => {
                assert_eq!(scan_id, Some("abc123".to_string()));
                assert!(matches!(action, ReportAction::Summary));
            }
            _ => panic!("Expected Report"),
        }
    }

    #[test]
    fn test_parse_report_findings() {
        let cmd = parse_command("/report findings").unwrap();
        match cmd {
            SlashCommand::Report { action, .. } => {
                assert!(matches!(action, ReportAction::Findings { severity_filter: None }));
            }
            _ => panic!("Expected Report"),
        }
    }

    #[test]
    fn test_parse_report_findings_severity() {
        let cmd = parse_command("/report findings --severity critical").unwrap();
        match cmd {
            SlashCommand::Report { action, .. } => match action {
                ReportAction::Findings { severity_filter } => {
                    assert_eq!(severity_filter, Some("critical".to_string()));
                }
                _ => panic!("Expected Findings action"),
            },
            _ => panic!("Expected Report"),
        }
    }

    #[test]
    fn test_parse_report_finding_number() {
        let cmd = parse_command("/report finding 3").unwrap();
        match cmd {
            SlashCommand::Report { action, .. } => {
                assert!(matches!(action, ReportAction::Finding(3)));
            }
            _ => panic!("Expected Report"),
        }
    }

    #[test]
    fn test_parse_report_finding_zero_error() {
        let result = parse_command("/report finding 0");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("1-indexed"));
    }

    #[test]
    fn test_parse_report_finding_missing_number() {
        let result = parse_command("/report finding");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_report_executive() {
        let cmd = parse_command("/report executive").unwrap();
        match cmd {
            SlashCommand::Report { action, .. } => {
                assert!(matches!(action, ReportAction::Executive));
            }
            _ => panic!("Expected Report"),
        }
    }

    #[test]
    fn test_parse_report_evidence_injection() {
        let cmd = parse_command("/report evidence injection").unwrap();
        match cmd {
            SlashCommand::Report { action, .. } => match action {
                ReportAction::Evidence(cat) => assert_eq!(cat, "injection"),
                _ => panic!("Expected Evidence action"),
            },
            _ => panic!("Expected Report"),
        }
    }

    #[test]
    fn test_parse_report_evidence_invalid() {
        let result = parse_command("/report evidence bogus");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown evidence category"));
    }

    #[test]
    fn test_parse_report_full() {
        let cmd = parse_command("/report full").unwrap();
        match cmd {
            SlashCommand::Report { action, .. } => {
                assert!(matches!(action, ReportAction::Full));
            }
            _ => panic!("Expected Report"),
        }
    }

    #[test]
    fn test_parse_report_html() {
        let cmd = parse_command("/report html").unwrap();
        match cmd {
            SlashCommand::Report { action, .. } => {
                assert!(matches!(action, ReportAction::Html));
            }
            _ => panic!("Expected Report"),
        }
    }

    #[test]
    fn test_parse_report_scan_flag() {
        let cmd = parse_command("/report findings --scan my-scan-id").unwrap();
        match cmd {
            SlashCommand::Report { scan_id, action } => {
                assert_eq!(scan_id, Some("my-scan-id".to_string()));
                assert!(matches!(action, ReportAction::Findings { .. }));
            }
            _ => panic!("Expected Report"),
        }
    }

    #[test]
    fn test_parse_scan_target() {
        let cmd = parse_command("/scan --target http://example.com").unwrap();
        match cmd {
            SlashCommand::Scan { target, .. } => {
                assert_eq!(target, Some("http://example.com".to_string()));
            }
            _ => panic!("Expected Scan"),
        }
    }

    #[test]
    fn test_parse_scan_all_flags() {
        let cmd = parse_command("/scan --target http://x.com --repo /tmp/repo --intensity thorough --skip-whitebox --skip-exploit").unwrap();
        match cmd {
            SlashCommand::Scan {
                target, repo, intensity, skip_whitebox, skip_exploit, skip_blackbox, ..
            } => {
                assert_eq!(target, Some("http://x.com".to_string()));
                assert_eq!(repo, Some("/tmp/repo".to_string()));
                assert_eq!(intensity, Some("thorough".to_string()));
                assert!(skip_whitebox);
                assert!(skip_exploit);
                assert!(!skip_blackbox);
            }
            _ => panic!("Expected Scan"),
        }
    }

    #[test]
    fn test_parse_container_status() {
        let cmd = parse_command("/container status").unwrap();
        assert!(matches!(cmd, SlashCommand::Container { action: ContainerAction::Status }));
    }

    #[test]
    fn test_parse_container_start() {
        let cmd = parse_command("/container start").unwrap();
        assert!(matches!(cmd, SlashCommand::Container { action: ContainerAction::Start }));
    }

    #[test]
    fn test_parse_container_stop() {
        let cmd = parse_command("/container stop").unwrap();
        assert!(matches!(cmd, SlashCommand::Container { action: ContainerAction::Stop }));
    }

    #[test]
    fn test_parse_container_rebuild() {
        let cmd = parse_command("/container rebuild").unwrap();
        assert!(matches!(cmd, SlashCommand::Container { action: ContainerAction::Rebuild }));
    }

    #[test]
    fn test_parse_container_default_is_status() {
        let cmd = parse_command("/container").unwrap();
        assert!(matches!(cmd, SlashCommand::Container { action: ContainerAction::Status }));
    }

    #[test]
    fn test_parse_unknown_command() {
        let result = parse_command("/foobar");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown command"));
    }

    #[test]
    fn test_parse_no_slash_prefix() {
        let result = parse_command("scan --target x");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Commands must start with /"));
    }

    #[test]
    fn test_parse_exit_aliases() {
        assert!(matches!(parse_command("/exit").unwrap(), SlashCommand::Exit));
        assert!(matches!(parse_command("/quit").unwrap(), SlashCommand::Exit));
        assert!(matches!(parse_command("/q").unwrap(), SlashCommand::Exit));
    }

    #[test]
    fn test_parse_serve_port() {
        let cmd = parse_command("/serve --port 8080").unwrap();
        match cmd {
            SlashCommand::Serve { port } => assert_eq!(port, Some(8080)),
            _ => panic!("Expected Serve"),
        }
    }

    #[test]
    fn test_parse_serve_no_port() {
        let cmd = parse_command("/serve").unwrap();
        match cmd {
            SlashCommand::Serve { port } => assert!(port.is_none()),
            _ => panic!("Expected Serve"),
        }
    }

    #[test]
    fn test_parse_help_specific_command() {
        let cmd = parse_command("/help scan").unwrap();
        match cmd {
            SlashCommand::Help { command } => assert_eq!(command, Some("scan".to_string())),
            _ => panic!("Expected Help"),
        }
    }

    #[test]
    fn test_parse_help_strips_slash() {
        let cmd = parse_command("/help /scan").unwrap();
        match cmd {
            SlashCommand::Help { command } => assert_eq!(command, Some("scan".to_string())),
            _ => panic!("Expected Help"),
        }
    }

    #[test]
    fn test_parse_config_key_value() {
        let cmd = parse_command("/config provider openai").unwrap();
        match cmd {
            SlashCommand::Config { key, value } => {
                assert_eq!(key, Some("provider".to_string()));
                assert_eq!(value, Some("openai".to_string()));
            }
            _ => panic!("Expected Config"),
        }
    }

    #[test]
    fn test_parse_findings_severity_filter() {
        let cmd = parse_command("/findings --severity high").unwrap();
        match cmd {
            SlashCommand::Findings { severity_filter } => {
                assert_eq!(severity_filter, Some("high".to_string()));
            }
            _ => panic!("Expected Findings"),
        }
    }

    #[test]
    fn test_command_names_count() {
        assert_eq!(COMMAND_NAMES.len(), 15);
        assert_eq!(COMMAND_HELP.len(), 15);
    }
}
