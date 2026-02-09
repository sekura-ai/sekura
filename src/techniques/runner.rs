use std::collections::HashMap;
use std::sync::Arc;
use crate::container::ContainerManager;
use crate::errors::SekuraError;
use crate::models::finding::Finding;
use crate::pipeline::state::ScanContext;
use super::loader::TechniqueDefinition;
use super::resolver::{resolve_command, has_unresolved};
use super::sorter::topological_sort;
use super::dedup::deduplicate_findings;
use crate::auth::cookie_injector::inject_cookies;
use tracing::{info, debug, warn};

pub struct TechniqueRunner {
    container: Arc<ContainerManager>,
    context: ScanContext,
}

impl TechniqueRunner {
    pub fn new(container: Arc<ContainerManager>, context: ScanContext) -> Self {
        Self { container, context }
    }

    pub async fn run_techniques(
        &self,
        techniques: &[TechniqueDefinition],
    ) -> Result<(Vec<Finding>, HashMap<String, String>), SekuraError> {
        let sorted = topological_sort(techniques)?;
        let mut findings = Vec::new();
        let mut raw_outputs = HashMap::new();

        for technique in &sorted {
            // Check port dependencies
            if let Some(required_ports) = &technique.depends_on_ports {
                if !required_ports.iter().any(|p| self.context.open_ports.contains(p)) {
                    debug!(technique = %technique.name, "Skipping — required ports not open");
                    continue;
                }
            }

            // Check technique dependencies
            if let Some(dep) = &technique.depends_on {
                if !raw_outputs.contains_key(dep.as_str()) {
                    debug!(technique = %technique.name, depends_on = %dep, "Skipping — dependency not met");
                    continue;
                }
            }

            // Resolve command template
            let command = resolve_command(&technique.command, &self.context);
            if has_unresolved(&command) {
                debug!(technique = %technique.name, "Skipping — unresolved placeholders");
                continue;
            }

            // Inject cookies if authenticated
            let command = if self.context.authenticated {
                inject_cookies(&command, &technique.tool, &self.context)
            } else {
                command
            };

            info!(technique = %technique.name, tool = %technique.tool, "Running technique");

            // Execute in Kali container
            match self.container.exec(&command, technique.timeout).await {
                Ok(output) => {
                    raw_outputs.insert(technique.name.clone(), output.clone());

                    // Parse findings from output based on parse hints
                    if let Some(hint) = &technique.parse_hint {
                        let parsed = parse_tool_output(&output, &technique.tool, hint);
                        findings.extend(parsed);
                    }
                }
                Err(e) => {
                    warn!(technique = %technique.name, error = %e, "Technique execution failed");
                    raw_outputs.insert(
                        technique.name.clone(),
                        format!("[ERROR] {}", e),
                    );
                }
            }
        }

        let findings = deduplicate_findings(findings);
        Ok((findings, raw_outputs))
    }
}

fn parse_tool_output(output: &str, tool: &str, _hint: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Basic output parsing — extract findings from common tool output patterns
    match tool {
        "nmap" => {
            // Look for open ports with service info
            for line in output.lines() {
                if line.contains("/tcp") && line.contains("open") {
                    findings.push(Finding {
                        title: format!("Open port: {}", line.trim()),
                        severity: crate::models::finding::Severity::Info,
                        category: crate::models::finding::VulnCategory::Infrastructure,
                        description: line.trim().to_string(),
                        evidence: line.trim().to_string(),
                        recommendation: "Review if this port should be exposed".to_string(),
                        tool: "nmap".to_string(),
                        technique: "port-scan".to_string(),
                        source: crate::models::finding::FindingSource::Blackbox,
                        verdict: None,
                        proof_of_exploit: None,
                    });
                }
            }
        }
        _ => {
            // Generic: if output contains common vulnerability indicators
            let vuln_indicators = ["VULNERABLE", "vulnerability", "CVE-", "CRITICAL"];
            for indicator in &vuln_indicators {
                if output.contains(indicator) {
                    findings.push(Finding {
                        title: format!("{} finding from {}", indicator, tool),
                        severity: crate::models::finding::Severity::Medium,
                        category: crate::models::finding::VulnCategory::Infrastructure,
                        description: format!("Tool {} detected potential vulnerability", tool),
                        evidence: output[..output.len().min(500)].to_string(),
                        recommendation: "Investigate and validate finding".to_string(),
                        tool: tool.to_string(),
                        technique: tool.to_string(),
                        source: crate::models::finding::FindingSource::Blackbox,
                        verdict: None,
                        proof_of_exploit: None,
                    });
                    break;
                }
            }
        }
    }

    findings
}
