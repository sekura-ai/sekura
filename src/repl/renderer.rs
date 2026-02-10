use console::style;

use crate::models::finding::Severity;
use crate::pipeline::state::PhaseName;
use crate::repl::commands::{COMMAND_HELP, CommandHelp};
use crate::repl::events::PipelineEvent;
use crate::utils::formatting::{format_cost, format_duration};

/// Render a pipeline event as styled terminal output, returning the formatted line.
pub fn render_event(event: &PipelineEvent) -> String {
    match event {
        PipelineEvent::PipelineStarted { scan_id, target } => {
            format!(
                "\n{} Starting scan {} against {}",
                style("▶").green().bold(),
                style(scan_id).cyan(),
                style(target).white().bold(),
            )
        }
        PipelineEvent::PhaseStarted { display_name, .. } => {
            format!(
                "\n{} {} {}",
                style("---").cyan().bold(),
                style(display_name).cyan().bold(),
                style("---").cyan().bold(),
            )
        }
        PipelineEvent::PhaseCompleted { display_name, .. } => {
            format!(
                "  {} {} complete",
                style("✓").green(),
                style(display_name).green(),
            )
        }
        PipelineEvent::AgentStarted { agent_name } => {
            format!(
                "  {} {}",
                style("⏳").yellow(),
                style(agent_name).yellow(),
            )
        }
        PipelineEvent::AgentCompleted {
            agent_name,
            duration_ms,
            cost_usd,
        } => {
            let cost_str = cost_usd
                .map(|c| format!(" | {}", format_cost(c)))
                .unwrap_or_default();
            format!(
                "  {} {} ({}{})",
                style("✓").green(),
                style(agent_name).green(),
                format_duration(*duration_ms),
                cost_str,
            )
        }
        PipelineEvent::AgentFailed { agent_name, error } => {
            format!(
                "  {} {} ({})",
                style("✗").red(),
                style(agent_name).red(),
                style(error).red().dim(),
            )
        }
        PipelineEvent::FindingDiscovered {
            title,
            severity,
            category,
        } => {
            format!(
                "  {} {} [{}] {}",
                style("⚑").white().bold(),
                render_severity_badge(severity),
                style(category).dim(),
                title,
            )
        }
        PipelineEvent::TechniqueRunning {
            technique_name,
            layer,
        } => {
            format!(
                "  {} {} ({})",
                style("⏳").yellow(),
                style(technique_name).yellow(),
                style(layer).dim(),
            )
        }
        PipelineEvent::TechniqueCompleted {
            technique_name,
            findings_count,
        } => {
            let findings_str = if *findings_count > 0 {
                format!(" → {} findings", findings_count)
            } else {
                String::new()
            };
            format!(
                "  {} {}{}",
                style("✓").green(),
                style(technique_name).green(),
                style(findings_str).dim(),
            )
        }
        PipelineEvent::PipelineCompleted {
            total_findings,
            total_cost_usd,
            total_duration_ms,
        } => {
            format!(
                "\n{} {} | {} | {}\n",
                style("✓ Scan complete:").green().bold(),
                style(format!("{} findings", total_findings)).white().bold(),
                format_cost(*total_cost_usd),
                format_duration(*total_duration_ms),
            )
        }
        PipelineEvent::PipelineFailed { error } => {
            format!(
                "\n{} {}\n",
                style("✗ Scan failed:").red().bold(),
                style(error).red(),
            )
        }
        PipelineEvent::CostWarning { current_usd, max_usd } => {
            let pct = (current_usd / max_usd) * 100.0;
            format!(
                "\n  {} Cost warning: ${:.4} / ${:.4} ({:.0}% of budget)\n",
                style("⚠").yellow().bold(),
                current_usd, max_usd, pct
            )
        }
        PipelineEvent::Log { message } => {
            format!("  {}", style(message).dim())
        }
    }
}

/// Render a severity badge with appropriate colors.
pub fn render_severity_badge(severity: &Severity) -> String {
    match severity {
        Severity::Critical => style(" CRITICAL ").on_red().white().bold().to_string(),
        Severity::High => style(" HIGH ").red().bold().to_string(),
        Severity::Medium => style(" MEDIUM ").yellow().bold().to_string(),
        Severity::Low => style(" LOW ").blue().to_string(),
        Severity::Info => style(" INFO ").dim().to_string(),
    }
}

/// Render the help listing for all commands.
pub fn render_help(specific_command: Option<&str>) -> String {
    if let Some(cmd_name) = specific_command {
        if let Some(cmd) = COMMAND_HELP.iter().find(|c| c.name == cmd_name) {
            return format_command_detail(cmd);
        } else {
            return format!("{} Unknown command: /{}", style("✗").red(), cmd_name);
        }
    }

    let mut out = String::new();
    out.push_str(&format!("\n{}\n\n", style("Available commands:").white().bold()));
    for cmd in COMMAND_HELP {
        out.push_str(&format!(
            "  {:<16} {}\n",
            style(format!("/{}", cmd.name)).cyan().bold(),
            style(cmd.description).dim(),
        ));
    }
    out
}

fn format_command_detail(cmd: &CommandHelp) -> String {
    format!(
        "\n{}\n  {}\n\n  {}\n",
        style(format!("/{}", cmd.name)).cyan().bold(),
        style(cmd.description).dim(),
        style(cmd.usage).white(),
    )
}

/// Render the version info.
pub fn render_version() -> String {
    let version = env!("CARGO_PKG_VERSION");
    let git_hash = option_env!("GIT_HASH").unwrap_or("dev");
    let build_ts = option_env!("BUILD_TIMESTAMP").unwrap_or("unknown");

    format!(
        "\n  {} {}\n  {} {}\n  {} {}\n",
        style("Version:").dim(),
        style(version).white().bold(),
        style("Commit:").dim(),
        style(git_hash).white(),
        style("Built:").dim(),
        style(build_ts).white(),
    )
}

/// Render agent list with status.
pub fn render_agents(
    current: &[String],
    completed: &[String],
    failed: &[String],
) -> String {
    let mut out = String::new();
    out.push_str(&format!("\n{}\n\n", style("Agents:").white().bold()));

    for name in current {
        out.push_str(&format!(
            "  {} {}\n",
            style("⏳").yellow(),
            style(name).yellow(),
        ));
    }
    for name in completed {
        out.push_str(&format!(
            "  {} {}\n",
            style("✓").green(),
            style(name).green(),
        ));
    }
    for name in failed {
        out.push_str(&format!(
            "  {} {}\n",
            style("✗").red(),
            style(name).red(),
        ));
    }
    if current.is_empty() && completed.is_empty() && failed.is_empty() {
        out.push_str(&format!("  {}\n", style("No agents have run yet.").dim()));
    }
    out
}

/// Render pipeline status summary.
pub fn render_status(
    status: &str,
    phase: Option<&str>,
    elapsed_ms: u64,
    total_cost: f64,
    findings_count: usize,
) -> String {
    format!(
        "\n  {} {}\n  {} {}\n  {} {}\n  {} {}\n  {} {}\n",
        style("Status:").dim(),
        match status {
            "running" => style(status).green().bold().to_string(),
            "completed" => style(status).cyan().to_string(),
            "failed" => style(status).red().to_string(),
            _ => style(status).white().to_string(),
        },
        style("Phase:").dim(),
        style(phase.unwrap_or("none")).white(),
        style("Elapsed:").dim(),
        style(format_duration(elapsed_ms)).white(),
        style("Cost:").dim(),
        style(format_cost(total_cost)).white(),
        style("Findings:").dim(),
        style(findings_count.to_string()).white().bold(),
    )
}

/// Render the status line shown after events during a scan.
pub fn render_status_line(elapsed_ms: u64, cost_usd: f64, findings: usize) -> String {
    format!(
        "{}",
        style(format!(
            "Session: {} | Cost: {} | Findings: {}",
            format_duration(elapsed_ms),
            format_cost(cost_usd),
            findings,
        ))
        .dim(),
    )
}

/// Render container status.
pub fn render_container_status(status: &str) -> String {
    let styled_status = match status {
        "running" => style("Running").green().bold().to_string(),
        "stopped" => style("Stopped").yellow().to_string(),
        "not_found" => style("Not Found").red().to_string(),
        other => other.to_string(),
    };
    format!(
        "\n  {} {}\n",
        style("Container:").dim(),
        styled_status,
    )
}

/// Print an error message to the REPL.
pub fn render_error(msg: &str) -> String {
    format!("{} {}", style("✗").red(), style(msg).red())
}

/// Print a success message.
pub fn render_success(msg: &str) -> String {
    format!("{} {}", style("✓").green(), msg)
}

/// Print an info message.
pub fn render_info(msg: &str) -> String {
    format!("{}", style(msg).dim())
}

/// Render a findings list.
pub fn render_findings(
    findings: &[(String, Severity, String)],
) -> String {
    if findings.is_empty() {
        return format!("\n  {}\n", style("No findings recorded.").dim());
    }

    let mut out = String::new();
    out.push_str(&format!(
        "\n{}\n\n",
        style(format!("Findings ({}):", findings.len())).white().bold(),
    ));
    for (title, severity, category) in findings {
        out.push_str(&format!(
            "  {} [{}] {}\n",
            render_severity_badge(severity),
            style(category).dim(),
            title,
        ));
    }
    out
}

/// Render a phase name for display.
pub fn phase_display_name(phase: &PhaseName) -> &'static str {
    match phase {
        PhaseName::WhiteboxAnalysis => "White-Box Analysis",
        PhaseName::Reconnaissance => "Reconnaissance",
        PhaseName::VulnerabilityAnalysis => "Vulnerability Analysis",
        PhaseName::Exploitation => "Exploitation",
        PhaseName::Reporting => "Reporting",
    }
}
