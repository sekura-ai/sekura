use std::collections::HashMap;
use std::sync::Arc;
use crate::container::ContainerManager;
use crate::errors::SekuraError;
use crate::llm::provider::LLMProvider;
use crate::models::finding::{Finding, Severity, VulnCategory, FindingSource};
use crate::pipeline::state::ScanContext;
use crate::prompts::{PromptLoader, PromptVariables};
use super::loader::TechniqueDefinition;
use super::resolver::{resolve_command, has_unresolved};
use super::sorter::topological_sort;
use super::dedup::deduplicate_findings;
use crate::auth::cookie_injector::inject_cookies;
use tracing::{info, debug, warn};

pub struct TechniqueRunner {
    container: Arc<ContainerManager>,
    context: ScanContext,
    llm: Arc<dyn LLMProvider>,
    prompt_loader: Arc<PromptLoader>,
}

impl TechniqueRunner {
    pub fn new(
        container: Arc<ContainerManager>,
        context: ScanContext,
        llm: Arc<dyn LLMProvider>,
        prompt_loader: Arc<PromptLoader>,
    ) -> Self {
        Self { container, context, llm, prompt_loader }
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

                    // Analyze output using LLM (with regex fallback)
                    let hint = technique.parse_hint.as_deref().unwrap_or("");
                    let parsed = self.analyze_output(
                        &output,
                        &technique.tool,
                        &technique.name,
                        hint,
                    ).await;
                    findings.extend(parsed);
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

    /// Analyze tool output using LLM structured extraction, with regex fallback.
    async fn analyze_output(
        &self,
        output: &str,
        tool: &str,
        technique_name: &str,
        hint: &str,
    ) -> Vec<Finding> {
        // Gate: skip empty or trivial output
        if output.trim().is_empty() || output.lines().count() < 2 {
            return Vec::new();
        }

        // Nmap fast path: always extract open ports via regex (cheap, needed for context)
        let mut nmap_findings = Vec::new();
        if tool == "nmap" {
            nmap_findings = parse_nmap_ports(output);
        }

        // LLM call for deeper analysis
        let llm_findings = match self.llm_analyze(output, tool, technique_name, hint).await {
            Ok(f) => f,
            Err(e) => {
                warn!(tool, technique = technique_name, error = %e, "LLM analysis failed, using regex fallback");
                parse_tool_output_fallback(output, tool, technique_name)
            }
        };

        // Merge: nmap port findings + LLM findings
        let mut all = nmap_findings;
        all.extend(llm_findings);
        all
    }

    /// Call the LLM with a structured schema to extract findings from tool output.
    async fn llm_analyze(
        &self,
        output: &str,
        tool: &str,
        technique_name: &str,
        hint: &str,
    ) -> Result<Vec<Finding>, SekuraError> {
        let system = match self.prompt_loader.load("tool-output-analyzer") {
            Ok(template) => {
                let vars = PromptVariables {
                    target_url: self.context.target_url.clone().unwrap_or_else(|| self.context.target.clone()),
                    intensity: format!("{:?}", self.context.intensity),
                    ..Default::default()
                };
                self.prompt_loader.interpolate(&template, &vars)
            }
            Err(e) => {
                debug!(error = %e, "Failed to load tool-output-analyzer prompt, using fallback");
                "You are a penetration testing output analyzer. Analyze the following tool output and extract security findings. Rules: Do NOT fabricate findings. Only report what is evidenced in the output. Each finding must cite specific output lines as evidence.".to_string()
            }
        };

        let truncated = if output.len() > 4000 { &output[..4000] } else { output };

        let prompt = format!(
            "Analyze this {} output from technique '{}'.\n\
             Parse hint: {}\n\n\
             Tool output:\n```\n{}\n```\n\n\
             Extract all security findings. For each finding provide:\n\
             - title: concise vulnerability title\n\
             - severity: one of critical, high, medium, low, info\n\
             - category: one of injection, xss, auth, ssrf, authz, infrastructure\n\
             - description: what the vulnerability is and why it matters\n\
             - evidence: exact lines from the output proving the finding\n\
             - recommendation: how to remediate\n\n\
             If no security findings exist in this output, return an empty findings array.",
            tool, technique_name, hint, truncated
        );

        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "findings": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "title": { "type": "string" },
                            "severity": { "type": "string", "enum": ["critical", "high", "medium", "low", "info"] },
                            "category": { "type": "string", "enum": ["injection", "xss", "auth", "ssrf", "authz", "infrastructure"] },
                            "description": { "type": "string" },
                            "evidence": { "type": "string" },
                            "recommendation": { "type": "string" }
                        },
                        "required": ["title", "severity", "category", "description", "evidence", "recommendation"]
                    }
                }
            },
            "required": ["findings"]
        });

        let result = self.llm.complete_structured(&prompt, &schema, Some(&system)).await?;

        let findings_array = result.get("findings")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let mut findings = Vec::new();
        for item in &findings_array {
            let title = item.get("title").and_then(|v| v.as_str()).unwrap_or("Unknown finding").to_string();
            let severity = match item.get("severity").and_then(|v| v.as_str()).unwrap_or("info") {
                "critical" => Severity::Critical,
                "high" => Severity::High,
                "medium" => Severity::Medium,
                "low" => Severity::Low,
                _ => Severity::Info,
            };
            let category = match item.get("category").and_then(|v| v.as_str()).unwrap_or("infrastructure") {
                "injection" => VulnCategory::Injection,
                "xss" => VulnCategory::Xss,
                "auth" => VulnCategory::Auth,
                "ssrf" => VulnCategory::Ssrf,
                "authz" => VulnCategory::Authz,
                _ => VulnCategory::Infrastructure,
            };
            let description = item.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let evidence = item.get("evidence").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let recommendation = item.get("recommendation").and_then(|v| v.as_str()).unwrap_or("").to_string();

            findings.push(Finding {
                title,
                severity,
                category,
                description,
                evidence,
                recommendation,
                tool: tool.to_string(),
                technique: technique_name.to_string(),
                source: FindingSource::Blackbox,
                verdict: None,
                proof_of_exploit: None,
            });
        }

        Ok(findings)
    }
}

/// Extract open port findings from nmap output via regex.
fn parse_nmap_ports(output: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for line in output.lines() {
        if line.contains("/tcp") && line.contains("open") {
            findings.push(Finding {
                title: format!("Open port: {}", line.trim()),
                severity: Severity::Info,
                category: VulnCategory::Infrastructure,
                description: line.trim().to_string(),
                evidence: line.trim().to_string(),
                recommendation: "Review if this port should be exposed".to_string(),
                tool: "nmap".to_string(),
                technique: "port-scan".to_string(),
                source: FindingSource::Blackbox,
                verdict: None,
                proof_of_exploit: None,
            });
        }
    }
    findings
}

/// Regex fallback when LLM analysis fails. Scans for common vulnerability indicators.
fn parse_tool_output_fallback(output: &str, tool: &str, technique_name: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let vuln_indicators = [
        ("VULNERABLE", Severity::High),
        ("vulnerability", Severity::Medium),
        ("CVE-", Severity::Medium),
        ("CRITICAL", Severity::High),
        ("SQL injection", Severity::Critical),
        ("XSS", Severity::High),
        ("Remote Code Execution", Severity::Critical),
        ("command injection", Severity::Critical),
        ("directory traversal", Severity::High),
        ("authentication bypass", Severity::Critical),
        ("open redirect", Severity::Medium),
        ("information disclosure", Severity::Medium),
        ("SSRF", Severity::High),
    ];

    for (indicator, severity) in &vuln_indicators {
        if output.to_lowercase().contains(&indicator.to_lowercase()) {
            // Extract context around the match
            let evidence = output.lines()
                .filter(|line| line.to_lowercase().contains(&indicator.to_lowercase()))
                .take(5)
                .collect::<Vec<_>>()
                .join("\n");

            findings.push(Finding {
                title: format!("{} detected by {}", indicator, tool),
                severity: severity.clone(),
                category: categorize_indicator(indicator),
                description: format!("Tool {} detected potential vulnerability: {}", tool, indicator),
                evidence: if evidence.is_empty() {
                    output[..output.len().min(500)].to_string()
                } else {
                    evidence
                },
                recommendation: "Investigate and validate finding".to_string(),
                tool: tool.to_string(),
                technique: technique_name.to_string(),
                source: FindingSource::Blackbox,
                verdict: None,
                proof_of_exploit: None,
            });
        }
    }

    findings
}

/// Map a vulnerability indicator keyword to the most likely VulnCategory.
fn categorize_indicator(indicator: &str) -> VulnCategory {
    let lower = indicator.to_lowercase();
    if lower.contains("sql") || lower.contains("injection") || lower.contains("command") {
        VulnCategory::Injection
    } else if lower.contains("xss") {
        VulnCategory::Xss
    } else if lower.contains("auth") {
        VulnCategory::Auth
    } else if lower.contains("ssrf") {
        VulnCategory::Ssrf
    } else if lower.contains("authz") || lower.contains("authorization") {
        VulnCategory::Authz
    } else {
        VulnCategory::Infrastructure
    }
}
