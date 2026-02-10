use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use console::style;
use rustyline::error::ReadlineError;
use rustyline::{Config, Editor, ExternalPrinter as _};
use tokio::sync::{mpsc, RwLock};
use tokio_util::sync::CancellationToken;

use crate::config::{ContainerConfig, Intensity};
use crate::container::ContainerManager;
use crate::errors::SekuraError;
use crate::models::finding::{Finding, Severity};
use crate::pipeline::orchestrator::PipelineOrchestrator;
use crate::pipeline::state::{PipelineConfig, PipelineState, PipelineStatus};
use crate::repl::banner;
use crate::repl::commands::{self, ContainerAction, ModelAction, ReportAction, SlashCommand};
use crate::repl::completer::ReplHelper;
use crate::repl::events::PipelineEvent;
use crate::repl::progress::ScanProgress;
use crate::repl::renderer;

/// Shared state for the REPL session.
struct SessionState {
    /// Currently running pipeline's state
    pipeline_state: Option<Arc<RwLock<PipelineState>>>,
    /// Cancel token for the running pipeline
    cancel_token: Option<CancellationToken>,
    /// Accumulated findings from the last scan
    findings: Vec<(String, Severity, String)>,
    /// Default configuration values
    defaults: HashMap<String, String>,
    /// Whether a scan is currently running
    scan_running: bool,
    /// Scan history: (scan_id, target, status, findings_count)
    history: Vec<(String, String, String, usize)>,
}

impl SessionState {
    fn new() -> Self {
        let mut defaults = HashMap::new();
        defaults.insert("provider".into(), "anthropic".into());
        defaults.insert("intensity".into(), "standard".into());
        defaults.insert("output".into(), "./results".into());

        // Load persisted config from .sekura/config.json if it exists
        if let Ok(content) = std::fs::read_to_string(".sekura/config.json") {
            if let Ok(saved) = serde_json::from_str::<HashMap<String, String>>(&content) {
                for (k, v) in saved {
                    defaults.insert(k, v);
                }
            }
        }

        // Restore API keys from persisted config into environment
        // so resolve_api_key_from_env can find them
        if let Some(provider) = defaults.get("provider") {
            let env_var = match provider.as_str() {
                "anthropic" => Some("ANTHROPIC_API_KEY"),
                "openai" => Some("OPENAI_API_KEY"),
                "gemini" => Some("GEMINI_API_KEY"),
                "openrouter" => Some("OPENROUTER_API_KEY"),
                _ => None,
            };
            if let Some(var) = env_var {
                if std::env::var(var).is_err() {
                    if let Some(key) = defaults.get("api_key") {
                        if !key.is_empty() {
                            std::env::set_var(var, key);
                        }
                    }
                }
            }
        }

        Self {
            pipeline_state: None,
            cancel_token: None,
            findings: Vec::new(),
            defaults,
            scan_running: false,
            history: Vec::new(),
        }
    }

    /// Persist current defaults to .sekura/config.json
    fn save_defaults(&self) {
        let _ = std::fs::create_dir_all(".sekura");
        if let Ok(json) = serde_json::to_string_pretty(&self.defaults) {
            let _ = std::fs::write(".sekura/config.json", json);
        }
    }
}

pub struct ReplSession;

impl ReplSession {
    pub fn new() -> Self {
        Self
    }

    pub async fn run(self) -> Result<(), SekuraError> {
        banner::show_splash();

        let state = Arc::new(tokio::sync::Mutex::new(SessionState::new()));
        let (event_tx, mut event_rx) = mpsc::unbounded_channel::<PipelineEvent>();

        // Set up rustyline editor
        let config = Config::builder()
            .auto_add_history(true)
            .build();
        let mut editor = Editor::with_config(config)
            .map_err(|e| SekuraError::Internal(format!("Failed to initialize REPL: {}", e)))?;
        editor.set_helper(Some(ReplHelper::default()));

        // Try to get an ExternalPrinter for printing events while readline is active
        let printer = editor.create_external_printer()
            .map_err(|e| SekuraError::Internal(format!("Failed to create printer: {}", e)))?;
        let printer = Arc::new(tokio::sync::Mutex::new(printer));

        // Spawn event receiver task that renders pipeline events with progress bars
        let printer_clone = printer.clone();
        let state_clone = state.clone();
        let event_task = tokio::spawn(async move {
            let mut progress: Option<ScanProgress> = None;

            while let Some(event) = event_rx.recv().await {
                // Track findings in session state
                if let PipelineEvent::FindingDiscovered {
                    ref title,
                    ref severity,
                    ref category,
                } = event
                {
                    let mut s = state_clone.lock().await;
                    s.findings.push((title.clone(), severity.clone(), category.clone()));
                }

                // Track completion in session state
                if let PipelineEvent::PipelineCompleted {
                    total_findings, ..
                } = &event
                {
                    let mut s = state_clone.lock().await;
                    s.scan_running = false;
                    if let Some(last) = s.history.last_mut() {
                        last.2 = "completed".into();
                        last.3 = *total_findings;
                    }
                }
                if let PipelineEvent::PipelineFailed { ref error } = event {
                    let mut s = state_clone.lock().await;
                    s.scan_running = false;
                    if let Some(last) = s.history.last_mut() {
                        last.2 = format!("failed: {}", error);
                    }
                }

                // Create progress display on scan start
                if let PipelineEvent::PipelineStarted { .. } = &event {
                    progress = Some(ScanProgress::new());
                }

                if let Some(ref mut prog) = progress {
                    // Update progress bars
                    prog.handle_event(&event);

                    // Print text for events that aren't already shown by progress bars.
                    // Phase/technique events are handled visually by bars — no text needed.
                    match &event {
                        PipelineEvent::PipelineStarted { .. }
                        | PipelineEvent::FindingDiscovered { .. }
                        | PipelineEvent::AgentStarted { .. }
                        | PipelineEvent::AgentCompleted { .. }
                        | PipelineEvent::AgentFailed { .. }
                        | PipelineEvent::Log { .. } => {
                            let line = renderer::render_event(&event);
                            prog.println(&line);
                        }
                        // CostWarning already calls println inside handle_event
                        // Phase/Technique/Completed/Failed are shown via bars
                        _ => {}
                    }

                    // Clean up progress on completion/failure
                    if matches!(
                        &event,
                        PipelineEvent::PipelineCompleted { .. }
                            | PipelineEvent::PipelineFailed { .. }
                    ) {
                        progress = None;
                    }
                } else {
                    // No active scan — fall back to plain-text ExternalPrinter
                    let line = renderer::render_event(&event);
                    let mut p = printer_clone.lock().await;
                    let _ = p.print(format!("{}\n", line));
                }
            }
        });

        // Main readline loop
        loop {
            // If a scan is running, yield the terminal to the indicatif
            // MultiProgress bars instead of showing a readline prompt.
            // Readline's raw-mode terminal control conflicts with MultiProgress
            // redraws, causing frozen/garbled output.
            {
                let is_running = state.lock().await.scan_running;
                if is_running {
                    loop {
                        tokio::select! {
                            _ = tokio::time::sleep(std::time::Duration::from_millis(200)) => {
                                if !state.lock().await.scan_running {
                                    break;
                                }
                            }
                            result = tokio::signal::ctrl_c() => {
                                if result.is_ok() {
                                    let s = state.lock().await;
                                    if s.scan_running {
                                        if let Some(ref token) = s.cancel_token {
                                            if token.is_cancelled() {
                                                // Already cancelled — force exit wait
                                                drop(s);
                                                break;
                                            }
                                            token.cancel();
                                        }
                                    } else {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    // Small pause to let progress bars finish drawing
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            }

            let readline = {
                // rustyline is blocking, so use spawn_blocking
                let result = tokio::task::spawn_blocking({
                    move || {
                        let term_w = console::Term::stdout().size().1 as usize;
                        let sep = format!("{}", style("─".repeat(term_w)).dim());
                        let prompt = format!("{}\n{} ", sep, style("sekura>").cyan().bold());
                        let result = editor.readline(&prompt);
                        (editor, result)
                    }
                })
                .await
                .map_err(|e| SekuraError::Internal(format!("Readline task failed: {}", e)))?;

                editor = result.0;
                result.1
            };

            match readline {
                Ok(line) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }

                    // Bottom separator — printed after rustyline fully releases the terminal
                    let term_w = console::Term::stdout().size().1 as usize;
                    println!("{}", style("─".repeat(term_w)).dim());

                    match commands::parse_command(trimmed) {
                        Ok(cmd) => {
                            let should_exit = self
                                .handle_command(cmd, &state, &event_tx)
                                .await;
                            if should_exit {
                                break;
                            }
                        }
                        Err(msg) => {
                            println!("{}", renderer::render_error(&msg));
                        }
                    }
                }
                Err(ReadlineError::Interrupted) => {
                    println!();
                    break;
                }
                Err(ReadlineError::Eof) => {
                    println!();
                    break;
                }
                Err(err) => {
                    println!("{}", renderer::render_error(&format!("Input error: {}", err)));
                    break;
                }
            }
        }

        // Clean up
        drop(event_tx);
        let _ = event_task.await;

        println!("{}", renderer::render_info("Goodbye."));
        Ok(())
    }

    async fn handle_command(
        &self,
        cmd: SlashCommand,
        state: &Arc<tokio::sync::Mutex<SessionState>>,
        event_tx: &mpsc::UnboundedSender<PipelineEvent>,
    ) -> bool {
        match cmd {
            SlashCommand::Exit => return true,

            SlashCommand::Clear => {
                print!("\x1B[2J\x1B[1;1H");
            }

            SlashCommand::Init => {
                self.handle_init(state).await;
            }

            SlashCommand::Model { action } => {
                self.handle_model(action, state).await;
            }

            SlashCommand::Help { command } => {
                println!("{}", renderer::render_help(command.as_deref()));
            }

            SlashCommand::Version => {
                println!("{}", renderer::render_version());
            }

            SlashCommand::Agents => {
                let s = state.lock().await;
                if let Some(ref ps) = s.pipeline_state {
                    let ps = ps.read().await;
                    println!(
                        "{}",
                        renderer::render_agents(
                            &ps.current_agents,
                            &ps.completed_agents,
                            &ps.failed_agents,
                        )
                    );
                } else {
                    println!(
                        "{}",
                        renderer::render_agents(&[], &[], &[])
                    );
                }
            }

            SlashCommand::Status => {
                let s = state.lock().await;
                if let Some(ref ps) = s.pipeline_state {
                    let ps = ps.read().await;
                    let status_str = match ps.status {
                        PipelineStatus::Queued => "queued",
                        PipelineStatus::Running => "running",
                        PipelineStatus::Completed => "completed",
                        PipelineStatus::Failed => "failed",
                    };
                    let phase_str = ps.current_phase.as_ref().map(|p| renderer::phase_display_name(p));
                    let elapsed = chrono::Utc::now()
                        .signed_duration_since(ps.start_time)
                        .num_milliseconds()
                        .max(0) as u64;
                    let cost: f64 = ps.agent_metrics.values().filter_map(|m| m.cost_usd).sum();
                    let findings = s.findings.len();
                    println!(
                        "{}",
                        renderer::render_status(status_str, phase_str, elapsed, cost, findings)
                    );
                } else {
                    println!("{}", renderer::render_info("No scan has been started."));
                }
            }

            SlashCommand::Stop => {
                let s = state.lock().await;
                if s.scan_running {
                    if let Some(ref token) = s.cancel_token {
                        token.cancel();
                        println!("{}", renderer::render_success("Cancellation requested."));
                    }
                } else {
                    println!("{}", renderer::render_info("No scan is currently running."));
                }
            }

            SlashCommand::Findings { severity_filter } => {
                let s = state.lock().await;
                let filtered: Vec<_> = if let Some(ref filter) = severity_filter {
                    s.findings
                        .iter()
                        .filter(|(_, sev, _)| {
                            let sev_str = match sev {
                                Severity::Critical => "critical",
                                Severity::High => "high",
                                Severity::Medium => "medium",
                                Severity::Low => "low",
                                Severity::Info => "info",
                            };
                            sev_str == filter.to_lowercase()
                        })
                        .cloned()
                        .collect()
                } else {
                    s.findings.clone()
                };
                println!("{}", renderer::render_findings(&filtered));
            }

            SlashCommand::Config { key, value } => {
                let mut s = state.lock().await;
                match (key, value) {
                    (None, _) => {
                        println!("\n{}\n", style("Configuration defaults:").white().bold());
                        for (k, v) in &s.defaults {
                            println!(
                                "  {} = {}",
                                style(k).cyan(),
                                style(v).white(),
                            );
                        }
                        println!();
                    }
                    (Some(k), None) => {
                        if let Some(v) = s.defaults.get(&k) {
                            println!("  {} = {}", style(&k).cyan(), style(v).white());
                        } else {
                            println!("{}", renderer::render_error(&format!("Unknown config key: {}", k)));
                        }
                    }
                    (Some(k), Some(v)) => {
                        let valid_keys = ["provider", "model", "intensity", "output", "base_url"];
                        if valid_keys.contains(&k.as_str()) {
                            s.defaults.insert(k.clone(), v.clone());
                            println!(
                                "{} {} = {}",
                                renderer::render_success("Set"),
                                style(&k).cyan(),
                                style(&v).white(),
                            );
                        } else {
                            println!(
                                "{}",
                                renderer::render_error(&format!(
                                    "Unknown config key: {}. Valid keys: {}",
                                    k,
                                    valid_keys.join(", ")
                                ))
                            );
                        }
                    }
                }
            }

            SlashCommand::History => {
                let s = state.lock().await;
                if s.history.is_empty() {
                    println!("{}", renderer::render_info("No scan history."));
                } else {
                    println!("\n{}\n", style("Scan history:").white().bold());
                    for (scan_id, target, status, findings) in &s.history {
                        let status_styled = match status.as_str() {
                            "completed" => style(status).green().to_string(),
                            s if s.starts_with("failed") => style(status).red().to_string(),
                            "running" => style(status).yellow().to_string(),
                            _ => status.clone(),
                        };
                        println!(
                            "  {} {} → {} ({} findings)",
                            style(scan_id).cyan(),
                            style(target).dim(),
                            status_styled,
                            findings,
                        );
                    }
                    println!();
                }
            }

            SlashCommand::Report { scan_id, action } => {
                let s = state.lock().await;
                let output_dir = PathBuf::from(
                    s.defaults.get("output").map(|s| s.as_str()).unwrap_or("./results"),
                );
                drop(s); // release lock before I/O

                // Resolve which scan to operate on
                let id = if let Some(explicit) = scan_id {
                    // Explicit scan_id provided via positional arg or --scan
                    explicit
                } else if matches!(action, ReportAction::Summary) {
                    // No scan_id + Summary → show picker of all scans
                    let scans = list_all_scans(&output_dir).await;
                    if scans.is_empty() {
                        println!("{}", renderer::render_info(
                            "No scan results found. Run a scan first.",
                        ));
                        return false;
                    }
                    if scans.len() == 1 {
                        // Only one scan — skip the picker
                        scans[0].scan_id.clone()
                    } else {
                        // Print the picker, read input
                        print!("{}", renderer::render_scan_picker(&scans));
                        let _ = std::io::Write::flush(&mut std::io::stdout());

                        let term = console::Term::stdout();
                        let choice = term.read_line().unwrap_or_default().trim().to_string();

                        if choice.is_empty() {
                            // Default: most recent (first in list, sorted newest-first)
                            scans[0].scan_id.clone()
                        } else if let Ok(n) = choice.parse::<usize>() {
                            if n >= 1 && n <= scans.len() {
                                scans[n - 1].scan_id.clone()
                            } else {
                                println!("{}", renderer::render_error(&format!(
                                    "Invalid choice. Enter 1-{}.", scans.len()
                                )));
                                return false;
                            }
                        } else {
                            // Treat as scan_id directly
                            choice
                        }
                    }
                } else {
                    // Non-Summary sub-command with no scan_id → auto-pick most recent
                    let s = state.lock().await;
                    let id = s.history.last().map(|(id, ..)| id.clone())
                        .or_else(|| find_most_recent_scan(&output_dir));
                    drop(s);
                    match id {
                        Some(id) => id,
                        None => {
                            println!("{}", renderer::render_info(
                                "No scans found. Run /report to list available scans.",
                            ));
                            return false;
                        }
                    }
                };

                let deliverables_dir = output_dir.join(&id).join("deliverables");
                if !deliverables_dir.is_dir() {
                    println!("{}", renderer::render_error(&format!("Deliverables not found for scan: {}", id)));
                    return false;
                }

                // Load findings.json (used by most sub-commands)
                let findings = load_findings(&deliverables_dir).await;

                match action {
                    ReportAction::Summary => {
                        // Load session metrics for target/duration/cost
                        let (target, duration_ms, cost_usd) = load_session_metrics(&deliverables_dir).await;

                        // Build deliverable availability list
                        let deliverables = build_deliverable_list(&deliverables_dir, &findings);

                        println!("{}", renderer::render_report_summary(
                            &id,
                            &target,
                            duration_ms,
                            cost_usd,
                            &findings,
                            &deliverables,
                        ));
                    }
                    ReportAction::Findings { severity_filter } => {
                        println!("{}", renderer::render_report_findings_table(
                            &findings,
                            severity_filter.as_deref(),
                        ));
                    }
                    ReportAction::Finding(n) => {
                        if findings.is_empty() {
                            println!("{}", renderer::render_info("No findings loaded."));
                        } else if n > findings.len() {
                            println!("{}", renderer::render_error(&format!(
                                "Finding #{} does not exist. There are {} findings (1-{}).",
                                n, findings.len(), findings.len()
                            )));
                        } else {
                            println!("{}", renderer::render_report_finding_detail(n, &findings[n - 1]));
                        }
                    }
                    ReportAction::Executive => {
                        if findings.is_empty() {
                            println!("{}", renderer::render_info("No findings loaded."));
                        } else {
                            let summary = crate::reporting::formatter::format_executive_summary(&findings);
                            println!("\n{}", summary);
                        }
                    }
                    ReportAction::Evidence(category) => {
                        let filename = format!("{}_exploitation_evidence.md", category);
                        let path = deliverables_dir.join(&filename);
                        if path.exists() {
                            match tokio::fs::read_to_string(&path).await {
                                Ok(content) => {
                                    println!("\n{}\n", style(format!("Evidence: {}", category)).white().bold());
                                    println!("{}", content);
                                }
                                Err(e) => {
                                    println!("{}", renderer::render_error(&format!("Failed to read {}: {}", filename, e)));
                                }
                            }
                        } else {
                            println!("{}", renderer::render_info(&format!(
                                "No {} evidence file found. The exploitation phase may not have run for this category.", category
                            )));
                        }
                    }
                    ReportAction::Full => {
                        let report_path = deliverables_dir.join("comprehensive_security_assessment_report.md");
                        if report_path.exists() {
                            match tokio::fs::read_to_string(&report_path).await {
                                Ok(content) => {
                                    println!("\n{}\n", style(format!("Report for {}:", id)).white().bold());
                                    println!("{}", content);
                                }
                                Err(e) => {
                                    println!("{}", renderer::render_error(&format!("Failed to read report: {}", e)));
                                }
                            }
                        } else {
                            println!("{}", renderer::render_error("Full report not found. The reporting phase may not have completed."));
                        }
                    }
                    ReportAction::Html => {
                        let html_path = deliverables_dir.join("report.html");
                        if html_path.exists() {
                            let path_str = html_path.display().to_string();
                            #[cfg(target_os = "macos")]
                            let cmd = "open";
                            #[cfg(target_os = "linux")]
                            let cmd = "xdg-open";
                            #[cfg(target_os = "windows")]
                            let cmd = "start";
                            #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
                            let cmd = "open";

                            match std::process::Command::new(cmd).arg(&path_str).spawn() {
                                Ok(_) => {
                                    println!("{}", renderer::render_success(&format!("Opened {} in browser", path_str)));
                                }
                                Err(e) => {
                                    println!("{}", renderer::render_error(&format!("Failed to open browser: {}", e)));
                                    println!("{}", renderer::render_info(&format!("File: {}", path_str)));
                                }
                            }
                        } else {
                            println!("{}", renderer::render_error("HTML report not found. The reporting phase may not have completed."));
                        }
                    }
                }
            }

            SlashCommand::Container { action } => {
                match self.handle_container(action).await {
                    Ok(()) => {}
                    Err(e) => {
                        println!("{}", renderer::render_error(&e.to_string()));
                    }
                }
            }

            SlashCommand::Serve { port } => {
                let port = port.unwrap_or(8080);
                println!(
                    "{}",
                    renderer::render_info(&format!("Starting API server on port {}...", port))
                );
                let args = crate::cli::commands::ServeArgs {
                    port,
                    host: "0.0.0.0".into(),
                    db: "./data/sekura.db".into(),
                    workers: 3,
                };
                tokio::spawn(async move {
                    if let Err(e) = crate::cli::serve::handle_serve(args).await {
                        eprintln!("{}", renderer::render_error(&format!("Server error: {}", e)));
                    }
                });
                println!(
                    "{}",
                    renderer::render_success(&format!("API server started on port {}", port))
                );
            }

            SlashCommand::Scan {
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
            } => {
                // Check if scan is already running
                {
                    let s = state.lock().await;
                    if s.scan_running {
                        println!(
                            "{}",
                            renderer::render_error("A scan is already running. Use /stop first.")
                        );
                        return false;
                    }
                }

                // Load --file JSON if provided (CLI flags override file values)
                let file_config = if let Some(ref path) = file {
                    match load_scan_file(path) {
                        Ok(fc) => Some(fc),
                        Err(e) => {
                            println!("{}", renderer::render_error(&format!("Failed to load --file {}: {}", path, e)));
                            return false;
                        }
                    }
                } else {
                    None
                };

                // Resolve target: CLI flag > file > error
                let target = target
                    .or_else(|| file_config.as_ref().and_then(|f| f.target.clone()));
                let target = match target {
                    Some(t) => t,
                    None => {
                        println!(
                            "{}",
                            renderer::render_error("--target is required. Usage: /scan --target <url> [--repo <path>] [--file <path.json>]")
                        );
                        return false;
                    }
                };

                // Resolve other fields: CLI flag > file > default
                let repo = repo.or_else(|| file_config.as_ref().and_then(|f| f.repo.clone()));
                let no_repo = repo.is_none();
                let repo = repo.unwrap_or_default();
                let auth = auth.or_else(|| file_config.as_ref().and_then(|f| f.auth.clone()));
                let intensity = intensity.or_else(|| file_config.as_ref().and_then(|f| f.intensity.clone()));
                let provider = provider.or_else(|| file_config.as_ref().and_then(|f| f.provider.clone()));
                let model = model.or_else(|| file_config.as_ref().and_then(|f| f.model.clone()));
                let fc_username = file_config.as_ref().and_then(|f| f.username.clone());
                let fc_password = file_config.as_ref().and_then(|f| f.password.clone());
                let fc_login_url = file_config.as_ref().and_then(|f| f.login_url.clone());
                let fc_rules_avoid = file_config.as_ref().and_then(|f| f.rules_avoid.clone());
                let fc_rules_focus = file_config.as_ref().and_then(|f| f.rules_focus.clone());

                let scan_id = uuid::Uuid::new_v4().to_string();

                // Lock state to read defaults and set up scan
                let (pipeline_config, cancel_token) = {
                    let mut s = state.lock().await;
                    let prov = provider
                        .unwrap_or_else(|| s.defaults.get("provider").cloned().unwrap_or("anthropic".into()));
                    let int = intensity
                        .unwrap_or_else(|| s.defaults.get("intensity").cloned().unwrap_or("standard".into()));
                    let output = s.defaults.get("output").cloned().unwrap_or("./results".into());

                    let api_key = crate::cli::start::resolve_api_key_from_env(&prov)
                        .or_else(|| s.defaults.get("api_key").cloned())
                        .unwrap_or_default();

                    let intensity_val = match int.as_str() {
                        "quick" => Intensity::Quick,
                        "thorough" => Intensity::Thorough,
                        _ => Intensity::Standard,
                    };

                    println!(
                        "  {} Using provider: {}",
                        style("i").cyan(),
                        style(&prov).cyan().bold(),
                    );

                    let config = PipelineConfig {
                        scan_id: scan_id.clone(),
                        target: target.clone(),
                        repo_path: PathBuf::from(&repo),
                        output_dir: PathBuf::from(&output),
                        intensity: intensity_val,
                        provider: prov,
                        model,
                        api_key,
                        base_url: s.defaults.get("base_url")
                            .cloned()
                            .unwrap_or("http://localhost:11434/v1".into()),
                        skip_whitebox: skip_whitebox || no_repo,
                        skip_blackbox,
                        skip_exploit,
                        blackbox_only: false,
                        whitebox_only: false,
                        layers: None,
                        username: fc_username,
                        password: fc_password,
                        cookie: auth,
                        login_url: fc_login_url,
                        no_auth: false,
                        pipeline_testing: false,
                        rebuild: false,
                        max_retries: 5,
                        max_agent_iterations: 5,
                        container_config: ContainerConfig::default(),
                        rules_avoid: fc_rules_avoid,
                        rules_focus: fc_rules_focus,
                        auth_context: None,
                        max_cost: None,
                    };

                    s.scan_running = true;
                    s.findings.clear();
                    s.history.push((scan_id.clone(), target.clone(), "running".into(), 0));

                    let token = CancellationToken::new();
                    (config, token)
                };

                // Spawn the pipeline in a background task
                let event_tx = event_tx.clone();
                let state_clone = state.clone();

                // Store cancel token and pipeline state.
                // Clone the token so we can pass it to the orchestrator while
                // the session keeps the original for /stop.
                let pipeline_token = cancel_token.clone();
                {
                    let mut s = state.lock().await;
                    s.cancel_token = Some(cancel_token);
                }

                tokio::spawn(async move {
                    // Emit start event
                    let _ = event_tx.send(PipelineEvent::PipelineStarted {
                        scan_id: pipeline_config.scan_id.clone(),
                        target: pipeline_config.target.clone(),
                    });

                    match PipelineOrchestrator::new(pipeline_config).await {
                        Ok(orchestrator) => {
                            // Store the pipeline state reference
                            {
                                let mut s = state_clone.lock().await;
                                s.pipeline_state = Some(orchestrator.state());
                            }

                            // Wire the session's cancel token + event channel into the orchestrator
                            let orch_ready = orchestrator
                                .with_cancel_token(pipeline_token)
                                .with_event_channel(event_tx.clone());

                            match orch_ready.run().await {
                                Ok(_summary) => {
                                    // PipelineCompleted event is already emitted by the orchestrator
                                }
                                Err(e) => {
                                    let _ = event_tx.send(PipelineEvent::PipelineFailed {
                                        error: e.to_string(),
                                    });
                                }
                            }
                        }
                        Err(e) => {
                            let _ = event_tx.send(PipelineEvent::PipelineFailed {
                                error: e.to_string(),
                            });
                            let mut s = state_clone.lock().await;
                            s.scan_running = false;
                        }
                    }

                    // Mark scan as no longer running regardless of outcome
                    let mut s = state_clone.lock().await;
                    s.scan_running = false;
                });
            }
        }

        false
    }

    async fn handle_container(&self, action: ContainerAction) -> Result<(), SekuraError> {
        let config = ContainerConfig::default();
        let manager = ContainerManager::new(&config).await?;

        match action {
            ContainerAction::Status => {
                let status = manager.status().await;
                let status_str = match status {
                    crate::container::manager::ContainerStatus::Running => "running",
                    crate::container::manager::ContainerStatus::Stopped => "stopped",
                    crate::container::manager::ContainerStatus::NotFound => "not_found",
                };
                println!("{}", renderer::render_container_status(status_str));
            }
            ContainerAction::Start => {
                println!("{}", renderer::render_info("Starting container..."));
                manager.ensure_running().await?;
                println!("{}", renderer::render_success("Container started."));
            }
            ContainerAction::Stop => {
                println!("{}", renderer::render_info("Stopping container..."));
                manager.stop(false).await?;
                println!("{}", renderer::render_success("Container stopped."));
            }
            ContainerAction::Rebuild => {
                println!("{}", renderer::render_info("Rebuilding container..."));
                manager.stop(true).await?;
                manager.ensure_running().await?;
                println!("{}", renderer::render_success("Container rebuilt and started."));
            }
        }
        Ok(())
    }

    async fn handle_model(
        &self,
        action: ModelAction,
        state: &Arc<tokio::sync::Mutex<SessionState>>,
    ) {
        use crate::llm::catalog::{self, PROVIDERS};

        match action {
            ModelAction::Show => {
                let s = state.lock().await;
                let provider = s.defaults.get("provider").cloned().unwrap_or("anthropic".into());
                let model = s.defaults.get("model").cloned()
                    .unwrap_or_else(|| catalog::get_default_model(&provider).to_string());
                let has_key = if provider == "local" {
                    true
                } else {
                    crate::cli::start::resolve_api_key_from_env(&provider).is_some()
                        || s.defaults.get("api_key").map_or(false, |k| !k.is_empty())
                };
                println!("{}", renderer::render_model_status(&provider, &model, has_key));
            }

            ModelAction::Set => {
                let term = console::Term::stdout();

                // Build provider list with key status
                let provider_items: Vec<(&str, &str, &str, bool)> = PROVIDERS.iter().map(|p| {
                    let has_key = if p.env_var.is_empty() {
                        true
                    } else {
                        std::env::var(p.env_var).is_ok()
                    };
                    (p.id, p.name, p.env_var, has_key)
                }).collect();

                print!("{}", renderer::render_provider_picker(&provider_items));
                println!();
                print!("  {} ", style(format!("Enter choice [1-{}]:", provider_items.len())).white());
                let _ = std::io::Write::flush(&mut std::io::stdout());
                let choice = term.read_line().unwrap_or_default().trim().to_string();

                let idx = match choice.parse::<usize>() {
                    Ok(n) if n >= 1 && n <= PROVIDERS.len() => n - 1,
                    _ if choice.is_empty() => {
                        // Default: keep current provider
                        let s = state.lock().await;
                        let current = s.defaults.get("provider").cloned().unwrap_or("anthropic".into());
                        drop(s);
                        match PROVIDERS.iter().position(|p| p.id == current) {
                            Some(i) => i,
                            None => 0,
                        }
                    }
                    _ => {
                        println!("  {} Invalid choice.", style("!").yellow());
                        return;
                    }
                };

                let provider = &PROVIDERS[idx];

                // Model picker
                let model_items: Vec<(&str, &str, &str, bool)> = provider.models.iter().map(|m| {
                    (m.id, m.label, m.context_window, m.recommended)
                }).collect();

                print!("{}", renderer::render_model_picker(provider.name, &model_items));

                if provider.id == "local" {
                    println!("    {}", style("Tip: Enter a custom model ID if yours is not listed.").dim());
                }
                println!();
                print!("  {} ", style(format!(
                    "Enter choice [1-{}] or model ID (Enter = recommended):",
                    model_items.len()
                )).white());
                let _ = std::io::Write::flush(&mut std::io::stdout());
                let model_choice = term.read_line().unwrap_or_default().trim().to_string();

                let model_id = if model_choice.is_empty() {
                    catalog::get_default_model(provider.id).to_string()
                } else if let Ok(n) = model_choice.parse::<usize>() {
                    if n >= 1 && n <= provider.models.len() {
                        provider.models[n - 1].id.to_string()
                    } else {
                        println!("  {} Invalid choice, using recommended model.", style("!").yellow());
                        catalog::get_default_model(provider.id).to_string()
                    }
                } else {
                    // Treat as a custom model ID
                    model_choice
                };

                // API key check / prompt
                if !provider.env_var.is_empty() {
                    match std::env::var(provider.env_var) {
                        Ok(_) => {
                            println!(
                                "  {} API key found ({})",
                                style("~").green(),
                                style(provider.env_var).dim(),
                            );
                        }
                        Err(_) => {
                            println!();
                            print!(
                                "  {} ",
                                style(format!("Enter your {} (or press Enter to skip):", provider.env_var)).white(),
                            );
                            let _ = std::io::Write::flush(&mut std::io::stdout());
                            let key_input = term.read_line().unwrap_or_default().trim().to_string();
                            if !key_input.is_empty() {
                                std::env::set_var(provider.env_var, &key_input);
                                let mut s = state.lock().await;
                                s.defaults.insert("api_key".into(), key_input);
                                s.save_defaults();
                                println!(
                                    "  {} API key saved ({})",
                                    style("~").green(),
                                    style(provider.env_var).dim(),
                                );
                            } else {
                                println!(
                                    "  {} No API key provided. Set {} before scanning.",
                                    style("!").yellow(),
                                    style(provider.env_var).cyan(),
                                );
                            }
                        }
                    }
                }

                // Save provider + model
                {
                    let mut s = state.lock().await;
                    s.defaults.insert("provider".into(), provider.id.into());
                    s.defaults.insert("model".into(), model_id.clone());
                    s.save_defaults();
                }

                println!(
                    "\n  {} Provider set to {}, model {}",
                    style("~").green(),
                    style(provider.name).cyan().bold(),
                    style(&model_id).white().bold(),
                );

                // Connection test
                println!("  {} Testing connection...", style("~").yellow());
                let s = state.lock().await;
                let api_key = crate::cli::start::resolve_api_key_from_env(provider.id)
                    .or_else(|| s.defaults.get("api_key").cloned())
                    .unwrap_or_default();
                let base_url = s.defaults.get("base_url").cloned()
                    .unwrap_or_else(|| "http://localhost:11434/v1".into());
                drop(s);

                let (success, latency_ms) = Self::test_model_connection(
                    provider.id, &model_id, &api_key, &base_url,
                ).await;
                println!("  {}", renderer::render_model_test_result(
                    success, provider.name, &model_id, latency_ms,
                ));
            }

            ModelAction::Test => {
                let s = state.lock().await;
                let provider_id = s.defaults.get("provider").cloned().unwrap_or("anthropic".into());
                let model = s.defaults.get("model").cloned()
                    .unwrap_or_else(|| catalog::get_default_model(&provider_id).to_string());
                let api_key = crate::cli::start::resolve_api_key_from_env(&provider_id)
                    .or_else(|| s.defaults.get("api_key").cloned())
                    .unwrap_or_default();
                let base_url = s.defaults.get("base_url").cloned()
                    .unwrap_or_else(|| "http://localhost:11434/v1".into());
                let provider_name = catalog::get_provider(&provider_id)
                    .map(|p| p.name)
                    .unwrap_or(&provider_id);
                drop(s);

                println!("  {} Testing {} / {}...", style("~").yellow(), provider_name, &model);
                let (success, latency_ms) = Self::test_model_connection(
                    &provider_id, &model, &api_key, &base_url,
                ).await;
                println!("  {}", renderer::render_model_test_result(
                    success, provider_name, &model, latency_ms,
                ));
            }
        }
    }

    async fn test_model_connection(
        provider_id: &str,
        model: &str,
        api_key: &str,
        base_url: &str,
    ) -> (bool, u64) {
        let start = std::time::Instant::now();
        match crate::llm::create_provider(provider_id, api_key, Some(model), Some(base_url)) {
            Ok(llm) => {
                match llm.complete("Respond with OK", None).await {
                    Ok(_) => (true, start.elapsed().as_millis() as u64),
                    Err(_) => (false, start.elapsed().as_millis() as u64),
                }
            }
            Err(_) => (false, start.elapsed().as_millis() as u64),
        }
    }

    async fn handle_init(&self, state: &Arc<tokio::sync::Mutex<SessionState>>) {
        use crate::container::manager::ContainerStatus;

        let term = console::Term::stdout();

        println!("\n{}\n", style("Initializing Sekura...").white().bold());
        let mut all_ok = true;

        // ── Step 1: Docker daemon ──────────────────────────────────────
        print!("  {} Checking Docker daemon... ", style("⏳").yellow());
        let config = ContainerConfig::default();
        let manager = match ContainerManager::new(&config).await {
            Ok(m) => {
                println!("{}", style("connected").green());
                Some(m)
            }
            Err(e) => {
                println!("{}", style("failed").red());
                println!("    {}", style(format!("Cannot connect to Docker: {}", e)).red().dim());
                println!("    {}", style("Make sure Docker Desktop is running.").dim());
                all_ok = false;
                None
            }
        };

        // ── Step 2: Kali Docker image ──────────────────────────────────
        if let Some(ref mgr) = manager {
            print!("  {} Checking Kali image... ", style("⏳").yellow());
            let docker = mgr.docker();
            let image_name = config.image.as_deref().unwrap_or("sekura-kali:latest");
            match docker.inspect_image(image_name).await {
                Ok(_) => {
                    println!("{}", style("found").green());
                }
                Err(_) => {
                    println!("{}", style("not found — building").yellow());
                    println!("    {}", style("This may take several minutes on first run...").dim());

                    let dockerfile_dir = Self::find_docker_dir();
                    if let Some(docker_dir) = dockerfile_dir {
                        let build_cmd = format!(
                            "docker build -t {} -f {}/Dockerfile.kali {}",
                            image_name,
                            docker_dir.display(),
                            docker_dir.display(),
                        );
                        println!("    {}", style(format!("Running: {}", build_cmd)).dim());

                        let status = tokio::process::Command::new("docker")
                            .args(["build", "-t", image_name, "-f",
                                &format!("{}/Dockerfile.kali", docker_dir.display()),
                                &docker_dir.display().to_string()])
                            .stdout(std::process::Stdio::inherit())
                            .stderr(std::process::Stdio::inherit())
                            .status()
                            .await;

                        match status {
                            Ok(s) if s.success() => {
                                println!("  {} Kali image {}", style("✓").green(), style("built successfully").green());
                            }
                            Ok(s) => {
                                println!("  {} Build failed with exit code {}", style("✗").red(), s.code().unwrap_or(-1));
                                all_ok = false;
                            }
                            Err(e) => {
                                println!("  {} Build failed: {}", style("✗").red(), e);
                                all_ok = false;
                            }
                        }
                    } else {
                        println!("  {} {}", style("✗").red(), style("docker/Dockerfile.kali not found").red());
                        println!("    {}", style("Run from the project root, or build manually:").dim());
                        println!("    {}", style(format!("docker build -t {} -f docker/Dockerfile.kali docker/", image_name)).dim());
                        all_ok = false;
                    }
                }
            }
        }

        // ── Step 3: Start container ────────────────────────────────────
        if let Some(ref mgr) = manager {
            print!("  {} Checking container... ", style("⏳").yellow());
            match mgr.status().await {
                ContainerStatus::Running => {
                    println!("{}", style("running").green());
                }
                ContainerStatus::Stopped => {
                    println!("{}", style("stopped — starting").yellow());
                    match mgr.ensure_running().await {
                        Ok(()) => println!("  {} Container {}", style("✓").green(), style("started").green()),
                        Err(e) => {
                            println!("  {} Failed to start container: {}", style("✗").red(), e);
                            all_ok = false;
                        }
                    }
                }
                ContainerStatus::NotFound => {
                    println!("{}", style("not found — creating").yellow());
                    match mgr.ensure_running().await {
                        Ok(()) => println!("  {} Container {}", style("✓").green(), style("created and started").green()),
                        Err(e) => {
                            println!("  {} Failed to create container: {}", style("✗").red(), e);
                            all_ok = false;
                        }
                    }
                }
            }
        }

        // ── Step 4: LLM provider selection ─────────────────────────────
        println!();
        println!("  {}", style("LLM Configuration").white().bold());
        println!();
        println!("  Select a provider:");
        println!();
        let providers = [
            ("1", "anthropic",   "Anthropic (Claude)",      "ANTHROPIC_API_KEY"),
            ("2", "openai",      "OpenAI (GPT-4o)",         "OPENAI_API_KEY"),
            ("3", "gemini",      "Google Gemini",           "GEMINI_API_KEY"),
            ("4", "openrouter",  "OpenRouter",              "OPENROUTER_API_KEY"),
            ("5", "local",       "Local / Ollama (no key)", ""),
        ];
        for (num, _, label, env_var) in &providers {
            let has_key = if env_var.is_empty() {
                true
            } else {
                std::env::var(env_var).is_ok()
            };
            let key_hint = if env_var.is_empty() {
                String::new()
            } else if has_key {
                format!(" {}", style("✓ key found").green())
            } else {
                format!(" {}", style("no key").dim())
            };
            println!(
                "    {}  {}{}",
                style(format!("[{}]", num)).cyan().bold(),
                style(label).white(),
                key_hint,
            );
        }
        println!();

        // Read provider choice
        print!("  {} ", style("Enter choice [1-5]:").white());
        let _ = std::io::Write::flush(&mut std::io::stdout());
        let choice = term.read_line().unwrap_or_default().trim().to_string();

        let selected = match choice.as_str() {
            "1" => Some(providers[0]),
            "2" => Some(providers[1]),
            "3" => Some(providers[2]),
            "4" => Some(providers[3]),
            "5" => Some(providers[4]),
            "" => {
                // Default: keep current
                let s = state.lock().await;
                let current = s.defaults.get("provider").cloned().unwrap_or("anthropic".into());
                drop(s);
                providers.iter().find(|(_, id, _, _)| *id == current).copied()
            }
            _ => {
                println!("  {} Invalid choice, keeping current provider.", style("!").yellow());
                None
            }
        };

        if let Some((_, provider_id, provider_label, env_var)) = selected {
            // Update session default
            {
                let mut s = state.lock().await;
                s.defaults.insert("provider".into(), provider_id.into());
                s.save_defaults();
            }
            println!(
                "  {} Provider set to {}",
                style("✓").green(),
                style(provider_label).cyan().bold(),
            );

            // Check/request API key (skip for local)
            if !env_var.is_empty() {
                match std::env::var(env_var) {
                    Ok(_) => {
                        println!(
                            "  {} API key found ({})",
                            style("✓").green(),
                            style(env_var).dim(),
                        );
                    }
                    Err(_) => {
                        println!();
                        print!(
                            "  {} ",
                            style(format!("Enter your {} (or press Enter to skip):", env_var)).white(),
                        );
                        let _ = std::io::Write::flush(&mut std::io::stdout());
                        let key_input = term.read_line().unwrap_or_default().trim().to_string();
                        if key_input.is_empty() {
                            println!(
                                "  {} No API key provided. Set {} before scanning.",
                                style("!").yellow(),
                                style(env_var).cyan(),
                            );
                            all_ok = false;
                        } else {
                            // Set for current process
                            std::env::set_var(env_var, &key_input);
                            // Persist API key so it survives restarts
                            {
                                let mut s = state.lock().await;
                                s.defaults.insert("api_key".into(), key_input.clone());
                                s.save_defaults();
                            }
                            println!(
                                "  {} API key set and saved ({})",
                                style("✓").green(),
                                style(env_var).dim(),
                            );
                        }
                    }
                }
            } else {
                // Local provider — check base_url
                let s = state.lock().await;
                let base_url = s.defaults.get("base_url")
                    .cloned()
                    .unwrap_or("http://localhost:11434/v1".into());
                drop(s);
                println!(
                    "  {} Endpoint: {}",
                    style("i").cyan(),
                    style(&base_url).white(),
                );
                println!(
                    "    {}",
                    style("Use /config base_url <url> to change").dim(),
                );
            }
        }

        // ── Step 5: Techniques directory ───────────────────────────────
        println!();
        println!("  {} Loading techniques...", style("⏳").yellow());
        let techniques_dir = std::env::current_dir()
            .map(|d| d.join("techniques"))
            .unwrap_or_else(|_| PathBuf::from("./techniques"));
        match crate::techniques::TechniqueLibrary::load(&techniques_dir) {
            Ok(lib) => {
                let total = lib.total_techniques();
                let layers = lib.available_layers();
                if total > 0 {
                    println!("  {} {}", style("✓").green(), style(format!("{} techniques across {} layers", total, layers.len())).green());
                } else {
                    println!("  {} {}", style("!").yellow(), style("no techniques found").yellow());
                    println!("    {}", style(format!("Add YAML files to {}", techniques_dir.display())).dim());
                }
            }
            Err(e) => {
                println!("  {} {}", style("✗").red(), style(format!("error: {}", e)).red());
                all_ok = false;
            }
        }

        // ── Step 6: Output directory ───────────────────────────────────
        print!("  {} Checking output directory... ", style("⏳").yellow());
        let output_dir = PathBuf::from("./results");
        match std::fs::create_dir_all(&output_dir) {
            Ok(()) => println!("{}", style(format!("{}", output_dir.display())).green()),
            Err(e) => {
                println!("{}", style(format!("failed: {}", e)).red());
                all_ok = false;
            }
        }

        // ── Summary ────────────────────────────────────────────────────
        println!();
        if all_ok {
            println!(
                "  {} {}\n",
                style("✓").green().bold(),
                style("Sekura is ready. Run /scan --target <url> to begin.").green().bold(),
            );
        } else {
            println!(
                "  {} {}\n",
                style("!").yellow().bold(),
                style("Some checks failed. Fix the issues above and run /init again.").yellow(),
            );
        }
    }

    /// Search common locations for the docker/ directory containing Dockerfile.kali.
    /// Prefers the sekura-rs local docker/ dir over the legacy project-root one.
    fn find_docker_dir() -> Option<PathBuf> {
        // Locate the cargo manifest dir (sekura-rs/) at compile time
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let mut candidates = vec![
            // sekura-rs/docker/ (Rust project's own Dockerfile)
            manifest_dir.join("docker"),
            // CWD/docker/
            PathBuf::from("docker"),
        ];
        // Also check parent dir for legacy layout
        if let Some(parent) = manifest_dir.parent() {
            candidates.push(parent.join("docker"));
        }
        for candidate in &candidates {
            if candidate.join("Dockerfile.kali").exists() {
                return Some(candidate.clone());
            }
        }
        None
    }
}

/// Find the most recent scan directory in the output dir by modification time.
fn find_most_recent_scan(output_dir: &std::path::Path) -> Option<String> {
    let entries = std::fs::read_dir(output_dir).ok()?;
    let mut best: Option<(String, std::time::SystemTime)> = None;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() { continue; }
        // Check if this scan dir has a deliverables subdirectory
        if !path.join("deliverables").is_dir() { continue; }
        let name = entry.file_name().to_string_lossy().to_string();
        if let Ok(meta) = entry.metadata() {
            if let Ok(modified) = meta.modified() {
                if best.as_ref().map_or(true, |(_, t)| modified > *t) {
                    best = Some((name, modified));
                }
            }
        }
    }
    best.map(|(name, _)| name)
}

/// JSON structure for --file scan configuration.
#[derive(serde::Deserialize)]
struct ScanFileConfig {
    target: Option<String>,
    repo: Option<String>,
    intensity: Option<String>,
    provider: Option<String>,
    model: Option<String>,
    auth: Option<String>,
    username: Option<String>,
    password: Option<String>,
    login_url: Option<String>,
    rules_avoid: Option<String>,
    rules_focus: Option<String>,
}

/// Load and parse a scan config JSON file.
fn load_scan_file(path: &str) -> Result<ScanFileConfig, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Cannot read file: {}", e))?;
    serde_json::from_str(&content)
        .map_err(|e| format!("Invalid JSON: {}", e))
}

/// Discover all scan results in the output directory, sorted newest-first.
async fn list_all_scans(output_dir: &std::path::Path) -> Vec<renderer::ScanEntry> {
    let entries = match std::fs::read_dir(output_dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut scans: Vec<(renderer::ScanEntry, std::time::SystemTime)> = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let deliverables = path.join("deliverables");
        if !deliverables.is_dir() {
            continue;
        }

        let scan_id = entry.file_name().to_string_lossy().to_string();
        let modified = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .unwrap_or(std::time::UNIX_EPOCH);

        // Load lightweight metadata
        let (target, duration_ms, cost_usd) = load_session_metrics(&deliverables).await;

        let findings_count = match tokio::fs::read_to_string(deliverables.join("findings.json")).await {
            Ok(json) => serde_json::from_str::<Vec<serde_json::Value>>(&json)
                .map(|v| v.len())
                .unwrap_or(0),
            Err(_) => 0,
        };

        scans.push((
            renderer::ScanEntry {
                scan_id,
                target,
                findings_count,
                cost_usd,
                duration_ms,
            },
            modified,
        ));
    }

    // Sort newest first
    scans.sort_by(|a, b| b.1.cmp(&a.1));
    scans.into_iter().map(|(entry, _)| entry).collect()
}

/// Load findings.json from the deliverables directory.
async fn load_findings(deliverables_dir: &std::path::Path) -> Vec<Finding> {
    let path = deliverables_dir.join("findings.json");
    if !path.exists() {
        return Vec::new();
    }
    match tokio::fs::read_to_string(&path).await {
        Ok(json) => serde_json::from_str(&json).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Load session_metrics.json and extract target, duration, cost.
async fn load_session_metrics(
    deliverables_dir: &std::path::Path,
) -> (String, Option<u64>, Option<f64>) {
    let path = deliverables_dir.join("session_metrics.json");
    if !path.exists() {
        return ("unknown".into(), None, None);
    }
    match tokio::fs::read_to_string(&path).await {
        Ok(json) => {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) {
                let target = v["target"].as_str().unwrap_or("unknown").to_string();
                let duration_ms = v["total_duration_ms"].as_u64();
                let cost_usd = v["total_cost_usd"].as_f64();
                (target, duration_ms, cost_usd)
            } else {
                ("unknown".into(), None, None)
            }
        }
        Err(_) => ("unknown".into(), None, None),
    }
}

/// Build a list of deliverables and whether they exist.
fn build_deliverable_list(
    deliverables_dir: &std::path::Path,
    findings: &[Finding],
) -> Vec<renderer::DeliverableInfo> {
    let mut list = Vec::new();

    list.push(renderer::DeliverableInfo {
        label: "findings",
        description: format!("{} findings loaded", findings.len()),
        exists: deliverables_dir.join("findings.json").exists(),
    });
    list.push(renderer::DeliverableInfo {
        label: "executive",
        description: "Executive summary".into(),
        exists: !findings.is_empty(),
    });

    let evidence_categories = [
        ("evidence/injection", "injection", "Injection exploitation evidence"),
        ("evidence/xss", "xss", "XSS exploitation evidence"),
        ("evidence/auth", "auth", "Auth exploitation evidence"),
        ("evidence/ssrf", "ssrf", "SSRF exploitation evidence"),
        ("evidence/authz", "authz", "AuthZ exploitation evidence"),
    ];
    for (label, cat, desc) in &evidence_categories {
        let filename = format!("{}_exploitation_evidence.md", cat);
        list.push(renderer::DeliverableInfo {
            label,
            description: desc.to_string(),
            exists: deliverables_dir.join(&filename).exists(),
        });
    }

    list.push(renderer::DeliverableInfo {
        label: "full",
        description: "Comprehensive report (markdown)".into(),
        exists: deliverables_dir
            .join("comprehensive_security_assessment_report.md")
            .exists(),
    });
    list.push(renderer::DeliverableInfo {
        label: "html",
        description: "HTML report".into(),
        exists: deliverables_dir.join("report.html").exists(),
    });

    list
}
