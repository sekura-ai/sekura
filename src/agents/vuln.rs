use std::sync::Arc;
use crate::container::ContainerManager;
use crate::errors::SekuraError;
use crate::llm::provider::LLMProvider;
use crate::models::finding::{Finding, Severity, VulnCategory, FindingSource};
use crate::pipeline::state::{PipelineConfig, ScanContext};
use crate::prompts::{PromptLoader, PromptVariables};
use crate::queue::{ExploitationQueue, VulnType};
use tracing::{info, warn, debug};

/// Runs the LLM-based vulnerability analysis for a single vuln category.
/// Returns the parsed exploitation queue and any findings extracted during analysis.
pub async fn run_vuln_analysis(
    vuln_type: VulnType,
    llm: Arc<dyn LLMProvider>,
    prompt_loader: Arc<PromptLoader>,
    config: &PipelineConfig,
    context: &ScanContext,
) -> Result<(ExploitationQueue, Vec<Finding>), SekuraError> {
    let deliverables_dir = config.deliverables_dir();
    let prompt_name = format!("vuln-{}", vuln_type.as_str());

    // Load and interpolate the vuln prompt template
    let system = match prompt_loader.load(&prompt_name) {
        Ok(template) => {
            let vars = build_vuln_variables(vuln_type, config, context, &deliverables_dir).await;
            prompt_loader.interpolate(&template, &vars)
        }
        Err(e) => {
            warn!(vuln_type = %vuln_type.as_str(), error = %e, "Failed to load vuln prompt, using fallback");
            format!(
                "You are a {} vulnerability analysis specialist. Analyze the target for {} vulnerabilities.",
                vuln_type.as_str(), vuln_type.as_str()
            )
        }
    };

    // Build the user prompt with all available context
    let mut prompt = format!(
        "Analyze the target {} for {} vulnerabilities.\n\n",
        config.target, vuln_type.as_str()
    );

    // Feed whitebox deliverables
    if let Some(content) = read_deliverable(&deliverables_dir, "code_analysis_deliverable.md", 8000).await {
        prompt.push_str("## Source Code Analysis\n");
        prompt.push_str(&content);
        prompt.push_str("\n\n");
    }

    // Feed recon deliverables
    if let Some(content) = read_deliverable(&deliverables_dir, "recon_deliverable.md", 8000).await {
        prompt.push_str("## Reconnaissance Data\n");
        prompt.push_str(&content);
        prompt.push_str("\n\n");
    }

    // Feed tool findings
    if let Some(content) = read_deliverable(&deliverables_dir, "tool_findings_report.md", 8000).await {
        prompt.push_str("## Tool Findings\n");
        prompt.push_str(&content);
        prompt.push_str("\n\n");
    }

    prompt.push_str(
        "Produce two outputs:\n\
         1. A detailed analysis report in markdown\n\
         2. An exploitation queue as a JSON block with the following structure:\n\
         ```json\n\
         {\"vulnerabilities\": [{\"id\": \"...\", \"vulnerability_type\": \"...\", \"source\": \"...\", \
         \"path\": \"...\", \"sink_call\": \"...\", \"slot_type\": \"...\", \"sanitization_observed\": \"...\", \
         \"verdict\": \"EXPLOITABLE|LIKELY|POTENTIAL|FALSE_POSITIVE\", \"confidence\": \"high|medium|low\", \
         \"witness_payload\": \"...\", \"exploitation_hypothesis\": \"...\", \
         \"suggested_exploit_technique\": \"...\", \"externally_exploitable\": true, \"notes\": \"...\"}]}\n\
         ```\n\
         If no vulnerabilities are found, return {\"vulnerabilities\": []}.\n"
    );

    info!(vuln_type = %vuln_type.as_str(), "Running LLM vulnerability analysis");
    let response = llm.complete(&prompt, Some(&system)).await?;

    // Write the analysis deliverable
    let analysis_filename = vuln_type.analysis_filename();
    tokio::fs::write(deliverables_dir.join(&analysis_filename), &response.content).await?;
    info!(file = %analysis_filename, "Wrote vuln analysis deliverable");

    // Parse the exploitation queue from the LLM response
    let queue = extract_exploitation_queue(&response.content, vuln_type);

    // Write the exploitation queue JSON
    let queue_filename = vuln_type.queue_filename();
    let queue_json = serde_json::to_string_pretty(&queue)
        .map_err(|e| SekuraError::Internal(format!("Failed to serialize queue: {}", e)))?;
    tokio::fs::write(deliverables_dir.join(&queue_filename), &queue_json).await?;
    info!(
        file = %queue_filename,
        vulns = queue.vulnerabilities.len(),
        "Wrote exploitation queue"
    );

    // Extract findings from the analysis for the accumulator
    let findings = queue_to_findings(&queue, vuln_type);

    Ok((queue, findings))
}

/// Build prompt variables with all available deliverable contents.
async fn build_vuln_variables(
    vuln_type: VulnType,
    config: &PipelineConfig,
    context: &ScanContext,
    deliverables_dir: &std::path::Path,
) -> PromptVariables {
    let code_analysis = read_deliverable(deliverables_dir, "code_analysis_deliverable.md", 8000).await;
    let recon_data = read_deliverable(deliverables_dir, "recon_deliverable.md", 8000).await;
    let tool_findings = read_deliverable(deliverables_dir, "tool_findings_report.md", 8000).await;

    let open_ports = if !context.open_ports.is_empty() {
        Some(context.open_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", "))
    } else {
        None
    };

    PromptVariables {
        target_url: config.target.clone(),
        repo_path: if config.has_repo() {
            Some(config.repo_path.display().to_string())
        } else {
            None
        },
        intensity: format!("{:?}", config.intensity),
        code_analysis,
        recon_data,
        tool_findings,
        exploitation_queue: None,
        vuln_type: Some(vuln_type.as_str().to_string()),
        rules_avoid: config.rules_avoid.clone(),
        rules_focus: config.rules_focus.clone(),
        login_instructions: None,
        open_ports,
        cookie_string: config.cookie.clone(),
        auth_context: config.auth_context.clone(),
    }
}

/// Extract an ExploitationQueue from LLM response text by finding the JSON block.
fn extract_exploitation_queue(response: &str, vuln_type: VulnType) -> ExploitationQueue {
    // Try to find a JSON block in the response
    let json_candidates = [
        // Look for ```json ... ``` blocks
        extract_json_block(response),
        // Look for raw JSON starting with {"vulnerabilities"
        extract_raw_json(response),
    ];

    for candidate in json_candidates.into_iter().flatten() {
        match serde_json::from_str::<ExploitationQueue>(&candidate) {
            Ok(queue) => {
                debug!(vuln_type = %vuln_type.as_str(), count = queue.vulnerabilities.len(), "Parsed exploitation queue");
                return queue;
            }
            Err(e) => {
                debug!(vuln_type = %vuln_type.as_str(), error = %e, "Failed to parse JSON candidate");
            }
        }
    }

    warn!(vuln_type = %vuln_type.as_str(), "No valid exploitation queue found in LLM response, returning empty");
    ExploitationQueue { vulnerabilities: Vec::new() }
}

/// Extract a JSON code block delimited by ```json ... ```
fn extract_json_block(text: &str) -> Option<String> {
    let start_markers = ["```json\n", "```json\r\n", "```JSON\n"];
    for marker in start_markers {
        if let Some(start) = text.find(marker) {
            let json_start = start + marker.len();
            if let Some(end) = text[json_start..].find("```") {
                return Some(text[json_start..json_start + end].trim().to_string());
            }
        }
    }
    None
}

/// Extract raw JSON that starts with {"vulnerabilities"
fn extract_raw_json(text: &str) -> Option<String> {
    if let Some(start) = text.find("{\"vulnerabilities\"") {
        // Find the matching closing brace
        let mut depth = 0;
        for (i, ch) in text[start..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(text[start..start + i + 1].to_string());
                    }
                }
                _ => {}
            }
        }
    }
    None
}

/// Convert exploitation queue entries into Finding structs for the accumulator.
fn queue_to_findings(queue: &ExploitationQueue, vuln_type: VulnType) -> Vec<Finding> {
    let category = match vuln_type {
        VulnType::Injection => VulnCategory::Injection,
        VulnType::Xss => VulnCategory::Xss,
        VulnType::Auth => VulnCategory::Auth,
        VulnType::Ssrf => VulnCategory::Ssrf,
        VulnType::Authz => VulnCategory::Authz,
    };

    queue.vulnerabilities.iter().filter_map(|entry| {
        // Only create findings for entries with exploitable verdicts
        let verdict_lower = entry.verdict.to_lowercase();
        if verdict_lower.contains("false_positive") {
            return None;
        }

        let severity = match entry.confidence {
            crate::queue::Confidence::High => {
                if verdict_lower.contains("exploitable") { Severity::High } else { Severity::Medium }
            }
            crate::queue::Confidence::Medium => Severity::Medium,
            crate::queue::Confidence::Low => Severity::Low,
        };

        Some(Finding {
            title: format!("{}: {} at {}", vuln_type.as_str().to_uppercase(), entry.vulnerability_type, entry.path),
            severity,
            category: category.clone(),
            description: entry.exploitation_hypothesis.clone().unwrap_or_else(|| entry.vulnerability_type.clone()),
            evidence: format!(
                "Source: {}\nPath: {}\nSink: {}\nVerdict: {} ({})",
                entry.source,
                entry.path,
                entry.sink_call.as_deref().unwrap_or("N/A"),
                entry.verdict,
                format!("{:?}", entry.confidence).to_lowercase(),
            ),
            recommendation: entry.suggested_exploit_technique.clone().unwrap_or_else(|| "Validate and remediate".to_string()),
            tool: "llm-analysis".to_string(),
            technique: format!("vuln-{}", vuln_type.as_str()),
            source: FindingSource::Combined,
            verdict: None,
            proof_of_exploit: None,
            cwe_id: None,
            cvss_score: None,
            cvss_vector: None,
        })
    }).collect()
}

/// Read a deliverable file, truncated to max_len.
async fn read_deliverable(dir: &std::path::Path, filename: &str, max_len: usize) -> Option<String> {
    let path = dir.join(filename);
    match tokio::fs::read_to_string(&path).await {
        Ok(content) if !content.trim().is_empty() => {
            Some(content[..content.len().min(max_len)].to_string())
        }
        _ => None,
    }
}
