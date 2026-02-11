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
use crate::audit::AuditSession;
use crate::auth::cookie_injector::inject_cookies;
use crate::repl::events::PipelineEvent;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{info, debug, warn};

/// Scope enforcement rules parsed from config avoid/focus strings.
#[derive(Debug, Clone, Default)]
pub struct ScopeRules {
    /// Paths/patterns that must NOT be targeted by any technique.
    pub avoid_patterns: Vec<String>,
    /// Paths/patterns that restrict scanning to only these targets (if non-empty).
    pub focus_patterns: Vec<String>,
}

impl ScopeRules {
    /// Parse scope rules from the optional config strings.
    /// Format: comma-separated patterns, e.g. "/admin,/internal,*.staging.example.com"
    pub fn from_config(rules_avoid: Option<&str>, rules_focus: Option<&str>) -> Self {
        let avoid_patterns = rules_avoid
            .map(|s| s.split(',').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect())
            .unwrap_or_default();
        let focus_patterns = rules_focus
            .map(|s| s.split(',').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect())
            .unwrap_or_default();
        Self { avoid_patterns, focus_patterns }
    }

    /// Check whether a resolved command violates scope rules.
    /// Returns Some(reason) if blocked, None if allowed.
    pub fn check_command(&self, command: &str, technique_name: &str) -> Option<String> {
        let cmd_lower = command.to_lowercase();

        // Check avoid patterns
        for pattern in &self.avoid_patterns {
            let pat_lower = pattern.to_lowercase();
            if cmd_lower.contains(&pat_lower) {
                return Some(format!(
                    "Technique '{}' targets avoided scope '{}' — skipping",
                    technique_name, pattern
                ));
            }
        }

        // Check focus patterns: if focus is set, command must match at least one
        if !self.focus_patterns.is_empty() {
            let matches_focus = self.focus_patterns.iter().any(|pattern| {
                cmd_lower.contains(&pattern.to_lowercase())
            });
            if !matches_focus {
                return Some(format!(
                    "Technique '{}' does not match any focus scope — skipping",
                    technique_name
                ));
            }
        }

        None
    }

    pub fn has_rules(&self) -> bool {
        !self.avoid_patterns.is_empty() || !self.focus_patterns.is_empty()
    }
}

pub struct TechniqueRunner {
    container: Arc<ContainerManager>,
    context: ScanContext,
    llm: Arc<dyn LLMProvider>,
    prompt_loader: Arc<PromptLoader>,
    scope: ScopeRules,
    dry_run: bool,
    audit: Option<Arc<AuditSession>>,
    cancel_token: CancellationToken,
    event_tx: Option<mpsc::UnboundedSender<PipelineEvent>>,
}

impl TechniqueRunner {
    pub fn new(
        container: Arc<ContainerManager>,
        context: ScanContext,
        llm: Arc<dyn LLMProvider>,
        prompt_loader: Arc<PromptLoader>,
    ) -> Self {
        Self {
            container, context, llm, prompt_loader,
            scope: ScopeRules::default(), dry_run: false, audit: None,
            cancel_token: CancellationToken::new(),
            event_tx: None,
        }
    }

    /// Set scope enforcement rules (avoid/focus patterns).
    pub fn with_scope(mut self, scope: ScopeRules) -> Self {
        self.scope = scope;
        self
    }

    /// Enable dry-run mode: logs all planned techniques without executing.
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    /// Attach audit session for container execution logging.
    pub fn with_audit(mut self, audit: Arc<AuditSession>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Attach a cancellation token so techniques can be interrupted mid-execution.
    pub fn with_cancel_token(mut self, token: CancellationToken) -> Self {
        self.cancel_token = token;
        self
    }

    /// Attach an event channel for per-technique progress reporting.
    pub fn with_event_channel(mut self, tx: mpsc::UnboundedSender<PipelineEvent>) -> Self {
        self.event_tx = Some(tx);
        self
    }

    /// Update the runner's scan context (e.g. after port discovery).
    pub fn update_context(&mut self, context: &ScanContext) {
        self.context = context.clone();
    }

    pub async fn run_techniques(
        &mut self,
        techniques: &[TechniqueDefinition],
        layer: &str,
    ) -> Result<(Vec<Finding>, HashMap<String, String>), SekuraError> {
        let sorted = topological_sort(techniques)?;
        let mut findings = Vec::new();
        let mut raw_outputs = HashMap::new();

        if self.scope.has_rules() {
            info!(
                avoid = ?self.scope.avoid_patterns,
                focus = ?self.scope.focus_patterns,
                "Scope enforcement active"
            );
        }

        for technique in &sorted {
            // Check cancellation before each technique
            if self.cancel_token.is_cancelled() {
                info!("Scan cancelled — stopping technique execution");
                break;
            }

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

            // Scope enforcement: check avoid/focus rules
            if let Some(reason) = self.scope.check_command(&command, &technique.name) {
                warn!(technique = %technique.name, reason = %reason, "Blocked by scope rules");
                continue;
            }

            // Dry-run mode: log the technique without executing
            if self.dry_run {
                info!(
                    technique = %technique.name,
                    tool = %technique.tool,
                    command = %command,
                    "[DRY RUN] Would execute technique"
                );
                raw_outputs.insert(technique.name.clone(), "[DRY RUN] Not executed".to_string());
                continue;
            }

            info!(technique = %technique.name, tool = %technique.tool, "Running technique");

            // Emit per-technique progress event
            if let Some(ref tx) = self.event_tx {
                let _ = tx.send(PipelineEvent::TechniqueRunning {
                    technique_name: technique.name.clone(),
                    layer: layer.to_string(),
                });
            }

            // Execute in Kali container with audit logging.
            // Race against the cancellation token so /stop interrupts long-running commands.
            let exec_start = std::time::Instant::now();
            let exec_future = self.container.exec(&command, technique.timeout);
            let cancel_future = self.cancel_token.cancelled();

            let exec_result = tokio::select! {
                result = exec_future => result,
                _ = cancel_future => {
                    let duration_ms = exec_start.elapsed().as_millis() as u64;
                    if let Some(ref audit) = self.audit {
                        audit.record_container_exec(&command, -2, duration_ms, 0).await;
                    }
                    info!(technique = %technique.name, "Technique cancelled by user");
                    raw_outputs.insert(technique.name.clone(), "[CANCELLED]".to_string());
                    break;
                }
            };

            let findings_before = findings.len();

            match exec_result {
                Ok(output) => {
                    let duration_ms = exec_start.elapsed().as_millis() as u64;
                    if let Some(ref audit) = self.audit {
                        audit.record_container_exec(&command, 0, duration_ms, output.len()).await;
                    }
                    raw_outputs.insert(technique.name.clone(), output.clone());

                    // Propagate discovered ports within the same layer so subsequent
                    // techniques (e.g. Service Version Detection) can resolve {open_ports}
                    self.context.extract_open_ports(&output);

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
                    let duration_ms = exec_start.elapsed().as_millis() as u64;
                    if let Some(ref audit) = self.audit {
                        audit.record_container_exec(&command, -1, duration_ms, 0).await;
                    }
                    warn!(technique = %technique.name, error = %e, "Technique execution failed");
                    raw_outputs.insert(
                        technique.name.clone(),
                        format!("[ERROR] {}", e),
                    );
                }
            }

            // Emit per-technique completion
            if let Some(ref tx) = self.event_tx {
                let _ = tx.send(PipelineEvent::TechniqueCompleted {
                    technique_name: technique.name.clone(),
                    findings_count: findings.len() - findings_before,
                });
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
                cwe_id: None,
                cvss_score: None,
                cvss_vector: None,
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
                cwe_id: None,
                cvss_score: None,
                cvss_vector: None,
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
                cwe_id: None,
                cvss_score: None,
                cvss_vector: None,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_rules_empty() {
        let scope = ScopeRules::from_config(None, None);
        assert!(!scope.has_rules());
        assert!(scope.check_command("nmap -sT 192.168.1.1", "port-scan").is_none());
    }

    #[test]
    fn test_scope_rules_avoid_blocks() {
        let scope = ScopeRules::from_config(Some("/admin,/internal"), None);
        assert!(scope.has_rules());
        let result = scope.check_command("nikto -h http://target.com/admin", "nikto-scan");
        assert!(result.is_some());
        assert!(result.unwrap().contains("avoided scope"));
    }

    #[test]
    fn test_scope_rules_avoid_allows() {
        let scope = ScopeRules::from_config(Some("/admin"), None);
        let result = scope.check_command("nmap -sT 192.168.1.1 -p 80", "port-scan");
        assert!(result.is_none());
    }

    #[test]
    fn test_scope_rules_focus_blocks_non_matching() {
        let scope = ScopeRules::from_config(None, Some("/api,/v2"));
        assert!(scope.has_rules());
        let result = scope.check_command("gobuster dir -u http://target.com/docs", "dir-brute");
        assert!(result.is_some());
        assert!(result.unwrap().contains("focus scope"));
    }

    #[test]
    fn test_scope_rules_focus_allows_matching() {
        let scope = ScopeRules::from_config(None, Some("/api,/v2"));
        let result = scope.check_command("nikto -h http://target.com/api/users", "nikto-scan");
        assert!(result.is_none());
    }

    #[test]
    fn test_scope_rules_avoid_case_insensitive() {
        let scope = ScopeRules::from_config(Some("/Admin"), None);
        let result = scope.check_command("nikto -h http://target.com/admin", "nikto-scan");
        assert!(result.is_some());
    }

    #[test]
    fn test_scope_rules_combined_avoid_and_focus() {
        let scope = ScopeRules::from_config(Some("/internal"), Some("/api"));
        // Matches focus but hits avoid
        let result = scope.check_command("curl http://target.com/internal/api", "curl-test");
        assert!(result.is_some()); // avoid takes priority
    }

    #[test]
    fn test_categorize_indicator() {
        assert_eq!(categorize_indicator("SQL injection"), VulnCategory::Injection);
        assert_eq!(categorize_indicator("XSS"), VulnCategory::Xss);
        assert_eq!(categorize_indicator("authentication bypass"), VulnCategory::Auth);
        assert_eq!(categorize_indicator("SSRF"), VulnCategory::Ssrf);
        assert_eq!(categorize_indicator("VULNERABLE"), VulnCategory::Infrastructure);
    }

    #[test]
    fn test_parse_nmap_ports() {
        let output = "22/tcp   open  ssh\n80/tcp   open  http\n443/tcp  closed https\n";
        let findings = parse_nmap_ports(output);
        assert_eq!(findings.len(), 2);
        assert!(findings[0].title.contains("22/tcp"));
        assert!(findings[1].title.contains("80/tcp"));
    }

    #[test]
    fn test_parse_tool_output_fallback_detects_vuln() {
        let output = "Found SQL injection in /api/users\nParameter: id\n";
        let findings = parse_tool_output_fallback(output, "sqlmap", "sqli-scan");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.category == VulnCategory::Injection));
    }

    #[test]
    fn test_parse_tool_output_fallback_empty() {
        let output = "All checks passed. No issues found.\n";
        let findings = parse_tool_output_fallback(output, "nikto", "nikto-scan");
        assert!(findings.is_empty());
    }
}
