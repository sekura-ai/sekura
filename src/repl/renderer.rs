use console::style;

use crate::models::finding::{Finding, Severity};
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

/// Summary info for a scan result in the picker list.
pub struct ScanEntry {
    pub scan_id: String,
    pub target: String,
    pub findings_count: usize,
    pub cost_usd: Option<f64>,
    pub duration_ms: Option<u64>,
}

/// Render the scan picker — a numbered list of available scan results.
pub fn render_scan_picker(scans: &[ScanEntry]) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "\n  {}\n\n",
        style("Available scan results:").white().bold(),
    ));

    for (i, scan) in scans.iter().enumerate() {
        let num = i + 1;
        let mut meta = format!("{} findings", scan.findings_count);
        if let Some(cost) = scan.cost_usd {
            meta.push_str(&format!(" | {}", format_cost(cost)));
        }
        if let Some(ms) = scan.duration_ms {
            meta.push_str(&format!(" | {}", format_duration(ms)));
        }
        out.push_str(&format!(
            "    {} {}  {} ({})\n",
            style(format!("[{}]", num)).cyan().bold(),
            style(&scan.target).white().bold(),
            style(&scan.scan_id).dim(),
            style(meta).dim(),
        ));
    }

    out.push_str(&format!(
        "\n  {} ",
        style("Enter number (or press Enter for most recent):").white(),
    ));

    out
}

/// Metadata about a deliverable available for display in the summary dashboard.
pub struct DeliverableInfo {
    pub label: &'static str,
    pub description: String,
    pub exists: bool,
}

/// Render the report summary dashboard.
pub fn render_report_summary(
    scan_id: &str,
    target: &str,
    duration_ms: Option<u64>,
    cost_usd: Option<f64>,
    findings: &[Finding],
    deliverables: &[DeliverableInfo],
) -> String {
    let mut out = String::new();

    // Header box
    let w = 60;
    out.push_str(&format!("\n  {}\n", style("╭".to_string() + &"─".repeat(w - 2) + "╮").cyan()));
    out.push_str(&format!("  {} {:<width$} {}\n",
        style("│").cyan(),
        style("SECURITY ASSESSMENT REPORT").white().bold(),
        style("│").cyan(),
        width = w - 4,
    ));
    out.push_str(&format!("  {} {:<width$} {}\n",
        style("│").cyan(),
        format!("Target:   {}", style(target).white().bold()),
        style("│").cyan(),
        width = w - 4,
    ));
    out.push_str(&format!("  {} {:<width$} {}\n",
        style("│").cyan(),
        format!("Scan:     {}", style(scan_id).cyan()),
        style("│").cyan(),
        width = w - 4,
    ));

    let mut meta_parts = Vec::new();
    if let Some(ms) = duration_ms {
        meta_parts.push(format!("Duration: {}", format_duration(ms)));
    }
    if let Some(cost) = cost_usd {
        meta_parts.push(format!("Cost: {}", format_cost(cost)));
    }
    if !meta_parts.is_empty() {
        out.push_str(&format!("  {} {:<width$} {}\n",
            style("│").cyan(),
            meta_parts.join("   "),
            style("│").cyan(),
            width = w - 4,
        ));
    }
    out.push_str(&format!("  {}\n", style("╰".to_string() + &"─".repeat(w - 2) + "╯").cyan()));

    // Severity breakdown
    let mut counts: [usize; 5] = [0; 5];
    for f in findings {
        match f.severity {
            Severity::Critical => counts[0] += 1,
            Severity::High => counts[1] += 1,
            Severity::Medium => counts[2] += 1,
            Severity::Low => counts[3] += 1,
            Severity::Info => counts[4] += 1,
        }
    }
    let max_count = *counts.iter().max().unwrap_or(&1).max(&1);

    out.push_str(&format!("\n  {}\n", style("Findings by Severity").white().bold()));
    out.push_str(&format!("  {}\n", style("─".repeat(42)).dim()));

    let labels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
    let colors: Vec<Box<dyn Fn(&str) -> String>> = vec![
        Box::new(|s: &str| style(s).red().bold().to_string()),
        Box::new(|s: &str| style(s).red().to_string()),
        Box::new(|s: &str| style(s).yellow().to_string()),
        Box::new(|s: &str| style(s).blue().to_string()),
        Box::new(|s: &str| style(s).dim().to_string()),
    ];

    for i in 0..5 {
        let bar_len = if max_count > 0 {
            (counts[i] as f64 / max_count as f64 * 20.0).ceil() as usize
        } else {
            0
        };
        let bar = "█".repeat(bar_len);
        out.push_str(&format!(
            "   {:<12} {:>2}  {}\n",
            (colors[i])(labels[i]),
            counts[i],
            (colors[i])(&bar),
        ));
    }

    out.push_str(&format!("  {}\n", style("─".repeat(42)).dim()));
    out.push_str(&format!(
        "   {:<12} {:>2}\n",
        style("Total").white().bold(),
        findings.len(),
    ));

    // Available deliverables
    let available: Vec<_> = deliverables.iter().filter(|d| d.exists).collect();
    if !available.is_empty() {
        out.push_str(&format!("\n  {}\n", style("Available Deliverables").white().bold()));
        out.push_str(&format!("  {}\n", style("─".repeat(42)).dim()));

        for d in &available {
            out.push_str(&format!(
                "    {:<20} {}\n",
                style(d.label).cyan(),
                style(&d.description).dim(),
            ));
        }
    }

    // Navigation hint
    out.push_str(&format!(
        "\n  {} {}\n",
        style("Navigate:").dim(),
        style("/report findings · /report finding 1 · /report evidence injection").dim(),
    ));

    out
}

/// Render a numbered findings table with severity, CWE, and CVSS.
pub fn render_report_findings_table(
    findings: &[Finding],
    severity_filter: Option<&str>,
) -> String {
    let filtered: Vec<(usize, &Finding)> = findings
        .iter()
        .enumerate()
        .filter(|(_, f)| {
            if let Some(filter) = severity_filter {
                let sev_str = match f.severity {
                    Severity::Critical => "critical",
                    Severity::High => "high",
                    Severity::Medium => "medium",
                    Severity::Low => "low",
                    Severity::Info => "info",
                };
                sev_str == filter.to_lowercase()
            } else {
                true
            }
        })
        .collect();

    if filtered.is_empty() {
        let msg = if severity_filter.is_some() {
            "No findings match the severity filter."
        } else {
            "No findings recorded."
        };
        return format!("\n  {}\n", style(msg).dim());
    }

    let mut out = String::new();
    out.push_str(&format!(
        "\n{}\n\n",
        style(format!("Findings ({}):", filtered.len())).white().bold(),
    ));

    for (idx, finding) in &filtered {
        let num = idx + 1; // 1-indexed
        let cwe = finding
            .cwe_id
            .as_deref()
            .map(|c| format!("[{}]", c))
            .unwrap_or_default();
        let cvss = finding
            .cvss_score
            .map(|s| format!("CVSS {:.1}", s))
            .unwrap_or_default();
        let meta = [cwe, cvss]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        let meta_str = if meta.is_empty() {
            String::new()
        } else {
            format!(" {} ", style(meta).dim())
        };

        out.push_str(&format!(
            "  {} {} {}{}\n",
            style(format!("[{:>2}]", num)).dim(),
            render_severity_badge(&finding.severity),
            meta_str,
            finding.title,
        ));
    }
    out
}

/// Render a detailed view of a single finding.
pub fn render_report_finding_detail(index: usize, finding: &Finding) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "\n  {} {}\n\n",
        style(format!("Finding #{}", index)).white().bold(),
        render_severity_badge(&finding.severity),
    ));
    out.push_str(&format!(
        "  {:<16} {}\n",
        style("Title:").dim(),
        style(&finding.title).white().bold(),
    ));
    out.push_str(&format!(
        "  {:<16} {}\n",
        style("Category:").dim(),
        style(format!("{:?}", finding.category)).white(),
    ));
    if let Some(ref cwe) = finding.cwe_id {
        out.push_str(&format!(
            "  {:<16} {}\n",
            style("CWE:").dim(),
            style(cwe).white(),
        ));
    }
    if let Some(cvss) = finding.cvss_score {
        let cvss_str = if let Some(ref vec) = finding.cvss_vector {
            format!("{:.1} ({})", cvss, vec)
        } else {
            format!("{:.1}", cvss)
        };
        out.push_str(&format!(
            "  {:<16} {}\n",
            style("CVSS:").dim(),
            style(cvss_str).white(),
        ));
    }
    out.push_str(&format!(
        "  {:<16} {}\n",
        style("Source:").dim(),
        style(format!("{:?}", finding.source)).white(),
    ));
    out.push_str(&format!(
        "  {:<16} {}\n",
        style("Tool:").dim(),
        style(&finding.tool).white(),
    ));
    out.push_str(&format!(
        "  {:<16} {}\n",
        style("Technique:").dim(),
        style(&finding.technique).white(),
    ));
    if let Some(ref verdict) = finding.verdict {
        out.push_str(&format!(
            "  {:<16} {}\n",
            style("Verdict:").dim(),
            style(format!("{:?}", verdict)).white(),
        ));
    }

    out.push_str(&format!(
        "\n  {}\n  {}\n",
        style("Description").white().bold(),
        &finding.description,
    ));

    let evidence_display = if finding.evidence.len() > 500 {
        format!("{}...", &finding.evidence[..500])
    } else {
        finding.evidence.clone()
    };
    out.push_str(&format!(
        "\n  {}\n  {}\n",
        style("Evidence").white().bold(),
        evidence_display,
    ));

    out.push_str(&format!(
        "\n  {}\n  {}\n",
        style("Recommendation").white().bold(),
        &finding.recommendation,
    ));

    if let Some(ref proof) = finding.proof_of_exploit {
        let proof_display = if proof.len() > 500 {
            format!("{}...", &proof[..500])
        } else {
            proof.clone()
        };
        out.push_str(&format!(
            "\n  {}\n  {}\n",
            style("Proof of Exploit").white().bold(),
            proof_display,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::finding::{Finding, FindingSource, VulnCategory};
    use crate::models::verdict::Verdict;

    fn make_test_finding(title: &str, severity: Severity) -> Finding {
        Finding {
            title: title.to_string(),
            severity,
            category: VulnCategory::Injection,
            description: "Test description".to_string(),
            evidence: "Test evidence".to_string(),
            recommendation: "Use parameterized queries".to_string(),
            tool: "sqlmap".to_string(),
            technique: "sql-injection-scan".to_string(),
            source: FindingSource::Blackbox,
            verdict: Some(Verdict::Exploited),
            proof_of_exploit: None,
            cwe_id: Some("CWE-89".to_string()),
            cvss_score: Some(9.8),
            cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string()),
        }
    }

    #[test]
    fn test_render_severity_badge_critical() {
        let badge = render_severity_badge(&Severity::Critical);
        assert!(badge.contains("CRITICAL"));
    }

    #[test]
    fn test_render_severity_badge_high() {
        let badge = render_severity_badge(&Severity::High);
        assert!(badge.contains("HIGH"));
    }

    #[test]
    fn test_render_severity_badge_medium() {
        let badge = render_severity_badge(&Severity::Medium);
        assert!(badge.contains("MEDIUM"));
    }

    #[test]
    fn test_render_severity_badge_low() {
        let badge = render_severity_badge(&Severity::Low);
        assert!(badge.contains("LOW"));
    }

    #[test]
    fn test_render_severity_badge_info() {
        let badge = render_severity_badge(&Severity::Info);
        assert!(badge.contains("INFO"));
    }

    #[test]
    fn test_render_report_summary_contains_target() {
        let output = render_report_summary(
            "scan-abc",
            "http://example.com",
            Some(60000),
            Some(0.05),
            &[],
            &[],
        );
        assert!(output.contains("example.com"));
    }

    #[test]
    fn test_render_report_summary_contains_scan_id() {
        let output = render_report_summary(
            "scan-abc",
            "http://example.com",
            None,
            None,
            &[],
            &[],
        );
        assert!(output.contains("scan-abc"));
    }

    #[test]
    fn test_render_report_summary_severity_counts() {
        let findings = vec![
            make_test_finding("Critical SQLi", Severity::Critical),
            make_test_finding("High XSS", Severity::High),
            make_test_finding("Medium SSRF", Severity::Medium),
        ];
        let output = render_report_summary(
            "scan-1",
            "http://example.com",
            None,
            None,
            &findings,
            &[],
        );
        // Total should show 3
        assert!(output.contains("3"));
        assert!(output.contains("CRITICAL"));
    }

    #[test]
    fn test_render_report_summary_no_findings() {
        let output = render_report_summary(
            "scan-1",
            "http://example.com",
            None,
            None,
            &[],
            &[],
        );
        // Total should show 0
        assert!(output.contains(" 0"));
    }

    #[test]
    fn test_render_report_findings_table_numbered() {
        let findings = vec![
            make_test_finding("First", Severity::Critical),
            make_test_finding("Second", Severity::High),
        ];
        let output = render_report_findings_table(&findings, None);
        assert!(output.contains("["));
        assert!(output.contains("1"));
        assert!(output.contains("2"));
        assert!(output.contains("First"));
        assert!(output.contains("Second"));
    }

    #[test]
    fn test_render_report_findings_table_severity_filter() {
        let findings = vec![
            make_test_finding("Critical one", Severity::Critical),
            make_test_finding("High one", Severity::High),
        ];
        let output = render_report_findings_table(&findings, Some("critical"));
        assert!(output.contains("Critical one"));
        assert!(!output.contains("High one"));
    }

    #[test]
    fn test_render_report_findings_table_empty() {
        let output = render_report_findings_table(&[], None);
        assert!(output.contains("No findings"));
    }

    #[test]
    fn test_render_report_finding_detail_all_fields() {
        let finding = make_test_finding("SQLi in /api", Severity::Critical);
        let output = render_report_finding_detail(1, &finding);
        assert!(output.contains("SQLi in /api"));
        assert!(output.contains("CWE-89"));
        assert!(output.contains("9.8"));
        assert!(output.contains("sqlmap"));
        assert!(output.contains("Injection"));
    }

    #[test]
    fn test_render_report_finding_detail_truncates_evidence() {
        let mut finding = make_test_finding("Test", Severity::High);
        finding.evidence = "A".repeat(600);
        let output = render_report_finding_detail(1, &finding);
        assert!(output.contains("..."));
        // Should be truncated to 500 + "..."
        assert!(!output.contains(&"A".repeat(600)));
    }

    #[test]
    fn test_render_scan_picker() {
        let scans = vec![
            ScanEntry {
                scan_id: "scan-1".to_string(),
                target: "http://example.com".to_string(),
                findings_count: 5,
                cost_usd: Some(0.12),
                duration_ms: Some(120000),
            },
            ScanEntry {
                scan_id: "scan-2".to_string(),
                target: "http://test.com".to_string(),
                findings_count: 2,
                cost_usd: None,
                duration_ms: None,
            },
        ];
        let output = render_scan_picker(&scans);
        assert!(output.contains("[1]"));
        assert!(output.contains("[2]"));
        assert!(output.contains("example.com"));
        assert!(output.contains("test.com"));
    }

    #[test]
    fn test_render_help_all_commands() {
        let output = render_help(None);
        assert!(output.contains("/scan"));
        assert!(output.contains("/report"));
        assert!(output.contains("/exit"));
    }

    #[test]
    fn test_render_help_specific_command() {
        let output = render_help(Some("scan"));
        assert!(output.contains("scan"));
        assert!(output.contains("--target"));
    }

    #[test]
    fn test_render_help_unknown_command() {
        let output = render_help(Some("nonexistent"));
        assert!(output.contains("Unknown command"));
    }

    #[test]
    fn test_render_error() {
        let output = render_error("something went wrong");
        assert!(output.contains("something went wrong"));
    }

    #[test]
    fn test_render_success() {
        let output = render_success("done");
        assert!(output.contains("done"));
    }

    #[test]
    fn test_render_findings_empty() {
        let output = render_findings(&[]);
        assert!(output.contains("No findings"));
    }

    #[test]
    fn test_render_findings_with_entries() {
        let items = vec![
            ("SQLi".to_string(), Severity::Critical, "injection".to_string()),
        ];
        let output = render_findings(&items);
        assert!(output.contains("SQLi"));
        assert!(output.contains("CRITICAL"));
    }

    #[test]
    fn test_phase_display_names() {
        assert_eq!(phase_display_name(&PhaseName::WhiteboxAnalysis), "White-Box Analysis");
        assert_eq!(phase_display_name(&PhaseName::Reconnaissance), "Reconnaissance");
        assert_eq!(phase_display_name(&PhaseName::VulnerabilityAnalysis), "Vulnerability Analysis");
        assert_eq!(phase_display_name(&PhaseName::Exploitation), "Exploitation");
        assert_eq!(phase_display_name(&PhaseName::Reporting), "Reporting");
    }
}
