use std::path::Path;
use crate::errors::SekuraError;
use crate::llm::provider::LLMProvider;
use crate::models::finding::Finding;
use crate::prompts::{PromptLoader, PromptVariables};
use crate::reporting::formatter::{format_executive_summary, format_finding_markdown};
use tracing::{info, warn};

pub async fn assemble_final_report(
    deliverables_dir: &Path,
    llm: &dyn LLMProvider,
    prompt_loader: &PromptLoader,
    target: &str,
) -> Result<String, SekuraError> {
    let evidence_files = [
        "injection_exploitation_evidence.md",
        "xss_exploitation_evidence.md",
        "auth_exploitation_evidence.md",
        "ssrf_exploitation_evidence.md",
        "authz_exploitation_evidence.md",
    ];

    let mut sections = Vec::new();
    for file in &evidence_files {
        let path = deliverables_dir.join(file);
        if path.exists() {
            let content = tokio::fs::read_to_string(&path).await?;
            if !content.trim().is_empty() {
                sections.push(content);
            }
        }
    }

    // Fallback: if no per-category evidence files exist, generate from findings.json
    if sections.is_empty() {
        let findings_path = deliverables_dir.join("findings.json");
        if findings_path.exists() {
            let json = tokio::fs::read_to_string(&findings_path).await?;
            if let Ok(findings) = serde_json::from_str::<Vec<Finding>>(&json) {
                if !findings.is_empty() {
                    let mut report = String::new();
                    report.push_str("# Security Assessment Report\n\n");
                    report.push_str(&format_executive_summary(&findings));
                    report.push_str("\n\n---\n\n");
                    for finding in &findings {
                        report.push_str(&format_finding_markdown(finding));
                        report.push_str("\n---\n\n");
                    }
                    sections.push(report);
                    info!(count = findings.len(), "Generated report from findings.json fallback");
                }
            }
        }
    }

    let assembled = if sections.is_empty() {
        "# Security Assessment Report\n\nNo exploitable vulnerabilities were found during this assessment.\n".to_string()
    } else {
        sections.join("\n\n---\n\n")
    };

    let tool_report_path = deliverables_dir.join("tool_findings_report.md");
    let mut full_report = assembled;
    if tool_report_path.exists() {
        let tool_findings = tokio::fs::read_to_string(&tool_report_path).await?;
        full_report = format!("{}\n\n---\n\n## Infrastructure Findings\n\n{}", full_report, tool_findings);
    }

    // Refine with LLM using report-executive prompt
    let refined = refine_with_llm(&full_report, llm, prompt_loader, target).await;
    let final_report = refined.unwrap_or(full_report);

    let output_path = deliverables_dir.join("comprehensive_security_assessment_report.md");
    tokio::fs::write(&output_path, &final_report).await?;
    info!(path = %output_path.display(), "Final report assembled");

    // Also write HTML report
    let findings_path = deliverables_dir.join("findings.json");
    if findings_path.exists() {
        let json = tokio::fs::read_to_string(&findings_path).await?;
        if let Ok(findings) = serde_json::from_str::<Vec<Finding>>(&json) {
            let scan_id = deliverables_dir.parent()
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");
            let html = crate::reporting::formatter::format_html_report(&findings, target, scan_id);
            let html_path = deliverables_dir.join("report.html");
            tokio::fs::write(&html_path, &html).await?;
            info!(path = %html_path.display(), "HTML report generated");
        }
    }

    Ok(final_report)
}

/// Use the LLM with the report-executive prompt to refine the raw assembled report.
async fn refine_with_llm(
    raw_report: &str,
    llm: &dyn LLMProvider,
    prompt_loader: &PromptLoader,
    target: &str,
) -> Option<String> {
    let template = match prompt_loader.load("report-executive") {
        Ok(t) => t,
        Err(e) => {
            warn!(error = %e, "Failed to load report-executive prompt, skipping LLM refinement");
            return None;
        }
    };

    let vars = PromptVariables {
        target_url: target.to_string(),
        ..Default::default()
    };
    let system = prompt_loader.interpolate(&template, &vars);

    // Truncate raw report for LLM context
    let truncated = if raw_report.len() > 15000 {
        &raw_report[..15000]
    } else {
        raw_report
    };

    let prompt = format!(
        "Refine the following raw security assessment into a professional executive report for target {}.\n\n## Raw Assessment\n{}\n",
        target, truncated
    );

    match llm.complete(&prompt, Some(&system)).await {
        Ok(response) => {
            info!("Report refined with LLM");
            Some(response.content)
        }
        Err(e) => {
            warn!(error = %e, "LLM report refinement failed, using raw report");
            None
        }
    }
}
