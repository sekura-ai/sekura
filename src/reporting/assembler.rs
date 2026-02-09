use std::path::Path;
use crate::errors::SekuraError;
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
