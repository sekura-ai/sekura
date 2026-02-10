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
        usage: "/report [scan_id]",
        description: "Show the final report for a scan",
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
        "/report" => Ok(SlashCommand::Report {
            scan_id: args.first().map(|s| s.to_string()),
        }),
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
