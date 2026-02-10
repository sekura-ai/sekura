use std::path::Path;
use crate::errors::SekuraError;
use crate::models::finding::Finding;
use crate::reporting::formatter::{format_executive_summary, format_finding_markdown};
use tracing::info;

pub async fn assemble_final_report(
    deliverables_dir: &Path,
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

    let output_path = deliverables_dir.join("comprehensive_security_assessment_report.md");
    tokio::fs::write(&output_path, &full_report).await?;
    info!(path = %output_path.display(), "Final report assembled");

    Ok(full_report)
}
