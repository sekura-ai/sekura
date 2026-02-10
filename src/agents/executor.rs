use std::sync::Arc;
use std::time::Instant;
use crate::container::ContainerManager;
use crate::errors::SekuraError;
use crate::llm::provider::LLMProvider;
use crate::models::scan_result::ScanResult;
use crate::pipeline::state::{PipelineConfig, ScanContext};
use crate::prompts::{PromptLoader, PromptVariables};
use super::registry::{AgentDefinition, AgentType};
use tracing::{info, warn, debug};

pub struct AgentExecutor {
    agent_def: &'static AgentDefinition,
    llm: Arc<dyn LLMProvider>,
    container: Arc<ContainerManager>,
    config: Arc<PipelineConfig>,
    context: ScanContext,
    prompt_loader: Arc<PromptLoader>,
}

impl AgentExecutor {
    pub fn new(
        agent_def: &'static AgentDefinition,
        llm: Arc<dyn LLMProvider>,
        container: Arc<ContainerManager>,
        config: Arc<PipelineConfig>,
        context: ScanContext,
        prompt_loader: Arc<PromptLoader>,
    ) -> Self {
        Self { agent_def, llm, container, config, context, prompt_loader }
    }

    pub async fn execute(&self) -> Result<ScanResult, SekuraError> {
        let max_retries = self.config.max_retries;
        let mut attempt = 0u32;

        loop {
            attempt += 1;
            let start = Instant::now();
            info!(agent = %self.agent_def.display_name, attempt, "Starting agent execution");

            match self.execute_single_attempt().await {
                Ok(result) => {
                    if self.validate_output().await? {
                        info!(
                            agent = %self.agent_def.display_name,
                            duration_ms = start.elapsed().as_millis() as u64,
                            findings = result.total_findings(),
                            "Agent completed successfully"
                        );
                        return Ok(result);
                    } else {
                        if attempt >= 3 {
                            return Err(SekuraError::OutputValidation(
                                format!("{}: missing deliverables after {} attempts",
                                    self.agent_def.display_name, attempt)
                            ));
                        }
                        warn!(agent = %self.agent_def.display_name, "Output validation failed, retrying");
                        continue;
                    }
                }
                Err(e) => {
                    let classification = e.classify();
                    if !classification.retryable || attempt >= max_retries {
                        return Err(e);
                    }

                    let delay = classification.retry_delay(attempt);
                    warn!(
                        agent = %self.agent_def.display_name,
                        attempt, delay_secs = delay.as_secs(),
                        error = %e,
                        "Retrying after transient error"
                    );
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    async fn execute_single_attempt(&self) -> Result<ScanResult, SekuraError> {
        let start = Instant::now();
        let result = match self.agent_def.agent_type {
            AgentType::Whitebox => self.run_whitebox().await,
            AgentType::ToolRunner => self.run_tools().await,
            AgentType::BrowserAgent => self.run_browser_agent().await,
            AgentType::VulnAnalyzer => self.run_vuln_analyzer().await,
            AgentType::Exploiter => self.run_exploiter().await,
            AgentType::Reporter => self.run_reporter().await,
        };

        result.map(|mut r| {
            r.duration_ms = start.elapsed().as_millis() as u64;
            r
        })
    }

    async fn run_whitebox(&self) -> Result<ScanResult, SekuraError> {
        let system = self.load_agent_prompt()?;
        let prompt = format!(
            "Analyze the source code at {} for security vulnerabilities. Target: {}",
            self.config.repo_path.display(),
            self.config.target
        );
        let response = self.llm.complete(&prompt, Some(&system)).await?;

        // Save deliverable
        let deliverables_dir = self.config.deliverables_dir();
        tokio::fs::write(
            deliverables_dir.join("code_analysis_deliverable.md"),
            &response.content,
        ).await?;

        Ok(ScanResult {
            agent_name: self.agent_def.display_name.to_string(),
            phase: self.agent_def.phase,
            findings: Vec::new(),
            raw_outputs: std::collections::HashMap::new(),
            duration_ms: 0,
            techniques_run: 0,
            cost_usd: response.cost_usd,
            turns: Some(1),
            model: Some(response.model),
        })
    }

    async fn run_tools(&self) -> Result<ScanResult, SekuraError> {
        Ok(ScanResult {
            agent_name: self.agent_def.display_name.to_string(),
            phase: self.agent_def.phase,
            findings: Vec::new(),
            raw_outputs: std::collections::HashMap::new(),
            duration_ms: 0,
            techniques_run: 0,
            cost_usd: None,
            turns: None,
            model: None,
        })
    }

    async fn run_browser_agent(&self) -> Result<ScanResult, SekuraError> {
        Ok(ScanResult {
            agent_name: self.agent_def.display_name.to_string(),
            phase: self.agent_def.phase,
            findings: Vec::new(),
            raw_outputs: std::collections::HashMap::new(),
            duration_ms: 0,
            techniques_run: 0,
            cost_usd: None,
            turns: None,
            model: None,
        })
    }

    async fn run_vuln_analyzer(&self) -> Result<ScanResult, SekuraError> {
        let system = self.load_agent_prompt()?;
        let prompt = self.build_vuln_prompt()?;
        let response = self.llm.complete(&prompt, Some(&system)).await?;

        // Save analysis deliverable
        let deliverables_dir = self.config.deliverables_dir();
        for deliverable in self.agent_def.required_deliverables {
            let filename = deliverable.filename();
            if filename.ends_with(".md") {
                tokio::fs::write(deliverables_dir.join(filename), &response.content).await?;
            } else if filename.ends_with(".json") {
                // Create empty queue if no vulnerabilities found
                let empty_queue = serde_json::json!({"vulnerabilities": []});
                tokio::fs::write(
                    deliverables_dir.join(filename),
                    serde_json::to_string_pretty(&empty_queue)?,
                ).await?;
            }
        }

        Ok(ScanResult {
            agent_name: self.agent_def.display_name.to_string(),
            phase: self.agent_def.phase,
            findings: Vec::new(),
            raw_outputs: std::collections::HashMap::new(),
            duration_ms: 0,
            techniques_run: 0,
            cost_usd: response.cost_usd,
            turns: Some(1),
            model: Some(response.model),
        })
    }

    async fn run_exploiter(&self) -> Result<ScanResult, SekuraError> {
        let deliverables_dir = self.config.deliverables_dir();

        // Try to load the exploitation queue for this vuln type
        let queue_content = self.load_exploitation_queue().await;
        let has_vulns = queue_content.as_ref()
            .map(|q| !q.contains("\"vulnerabilities\": []") && q.contains("\"vulnerabilities\""))
            .unwrap_or(false);

        if has_vulns {
            // Load the exploit prompt template and call LLM
            let system = self.load_agent_prompt()?;
            let _vars = self.build_prompt_variables().await;
            let prompt = format!(
                "Exploit the vulnerabilities in the following queue against target {}.\n\n## Exploitation Queue\n{}\n",
                self.config.target,
                queue_content.unwrap_or_default()
            );
            let response = self.llm.complete(&prompt, Some(&system)).await?;

            // Write evidence deliverable
            for deliverable in self.agent_def.required_deliverables {
                let filename = deliverable.filename();
                tokio::fs::write(deliverables_dir.join(filename), &response.content).await?;
            }

            return Ok(ScanResult {
                agent_name: self.agent_def.display_name.to_string(),
                phase: self.agent_def.phase,
                findings: Vec::new(),
                raw_outputs: std::collections::HashMap::new(),
                duration_ms: 0,
                techniques_run: 0,
                cost_usd: response.cost_usd,
                turns: Some(1),
                model: Some(response.model),
            });
        }

        // No vulnerabilities to exploit — write placeholder evidence files
        for deliverable in self.agent_def.required_deliverables {
            let filename = deliverable.filename();
            if !deliverables_dir.join(filename).exists() {
                tokio::fs::write(
                    deliverables_dir.join(filename),
                    "# Exploitation Evidence\n\nNo exploitable vulnerabilities found.\n",
                ).await?;
            }
        }

        Ok(ScanResult {
            agent_name: self.agent_def.display_name.to_string(),
            phase: self.agent_def.phase,
            findings: Vec::new(),
            raw_outputs: std::collections::HashMap::new(),
            duration_ms: 0,
            techniques_run: 0,
            cost_usd: None,
            turns: None,
            model: None,
        })
    }

    async fn run_reporter(&self) -> Result<ScanResult, SekuraError> {
        crate::reporting::assembler::assemble_final_report(
            &self.config.deliverables_dir(),
            self.llm.as_ref(),
            &self.prompt_loader,
            &self.config.target,
        ).await?;

        Ok(ScanResult {
            agent_name: self.agent_def.display_name.to_string(),
            phase: self.agent_def.phase,
            findings: Vec::new(),
            raw_outputs: std::collections::HashMap::new(),
            duration_ms: 0,
            techniques_run: 0,
            cost_usd: None,
            turns: None,
            model: None,
        })
    }

    fn build_vuln_prompt(&self) -> Result<String, SekuraError> {
        let mut prompt = format!(
            "Analyze the target {} for {} vulnerabilities.\n",
            self.config.target,
            self.agent_def.prompt_file.replace("vuln-", ""),
        );

        // Include code analysis if available
        if let Some(code_path) = &self.context.code_analysis {
            if code_path.exists() {
                if let Ok(content) = std::fs::read_to_string(code_path) {
                    prompt.push_str(&format!("\n## Code Analysis\n{}\n", &content[..content.len().min(5000)]));
                }
            }
        }

        // Include recon data if available
        if let Some(recon_path) = &self.context.recon_data {
            if recon_path.exists() {
                if let Ok(content) = std::fs::read_to_string(recon_path) {
                    prompt.push_str(&format!("\n## Recon Data\n{}\n", &content[..content.len().min(5000)]));
                }
            }
        }

        Ok(prompt)
    }

    /// Load the system prompt for this agent from the prompt template file.
    fn load_agent_prompt(&self) -> Result<String, SekuraError> {
        match self.prompt_loader.load(self.agent_def.prompt_file) {
            Ok(template) => {
                let vars = PromptVariables {
                    target_url: self.config.target.clone(),
                    repo_path: if self.config.has_repo() {
                        Some(self.config.repo_path.display().to_string())
                    } else {
                        None
                    },
                    intensity: format!("{:?}", self.config.intensity),
                    rules_avoid: self.config.rules_avoid.clone(),
                    rules_focus: self.config.rules_focus.clone(),
                    cookie_string: self.config.cookie.clone(),
                    auth_context: self.config.auth_context.clone(),
                    ..Default::default()
                };
                Ok(self.prompt_loader.interpolate(&template, &vars))
            }
            Err(e) => {
                debug!(
                    agent = %self.agent_def.display_name,
                    prompt_file = %self.agent_def.prompt_file,
                    error = %e,
                    "Failed to load prompt template, using fallback"
                );
                Ok(format!("You are a {}.", self.agent_def.display_name))
            }
        }
    }

    /// Build prompt variables with deliverable contents loaded from disk.
    async fn build_prompt_variables(&self) -> PromptVariables {
        let deliverables_dir = self.config.deliverables_dir();

        let code_analysis = Self::read_deliverable_content(
            &deliverables_dir, "code_analysis_deliverable.md", 8000
        ).await;
        let recon_data = Self::read_deliverable_content(
            &deliverables_dir, "recon_deliverable.md", 8000
        ).await;
        let tool_findings = Self::read_deliverable_content(
            &deliverables_dir, "tool_findings_report.md", 8000
        ).await;

        // Determine vuln type from prompt_file name
        let vuln_type = self.agent_def.prompt_file
            .replace("vuln-", "")
            .replace("exploit-", "");

        // Try to load the exploitation queue for the vuln type
        let queue_filename = format!("{}_exploitation_queue.json", vuln_type);
        let exploitation_queue = Self::read_deliverable_content(
            &deliverables_dir, &queue_filename, 10000
        ).await;

        let open_ports = if !self.context.open_ports.is_empty() {
            Some(self.context.open_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", "))
        } else {
            None
        };

        PromptVariables {
            target_url: self.config.target.clone(),
            repo_path: if self.config.has_repo() {
                Some(self.config.repo_path.display().to_string())
            } else {
                None
            },
            intensity: format!("{:?}", self.config.intensity),
            code_analysis,
            recon_data,
            tool_findings,
            exploitation_queue,
            vuln_type: Some(vuln_type),
            rules_avoid: self.config.rules_avoid.clone(),
            rules_focus: self.config.rules_focus.clone(),
            login_instructions: None,
            open_ports,
            cookie_string: self.config.cookie.clone(),
            auth_context: self.config.auth_context.clone(),
        }
    }

    /// Load the exploitation queue JSON for this agent's vuln type.
    async fn load_exploitation_queue(&self) -> Option<String> {
        let vuln_type = self.agent_def.prompt_file
            .replace("exploit-", "");
        let filename = format!("{}_exploitation_queue.json", vuln_type);
        let path = self.config.deliverables_dir().join(&filename);
        match tokio::fs::read_to_string(&path).await {
            Ok(content) => {
                debug!(path = %path.display(), "Loaded exploitation queue");
                Some(content)
            }
            Err(_) => {
                debug!(path = %path.display(), "No exploitation queue found");
                None
            }
        }
    }

    /// Read a deliverable file's content, truncated to max_len.
    async fn read_deliverable_content(dir: &std::path::Path, filename: &str, max_len: usize) -> Option<String> {
        let path = dir.join(filename);
        match tokio::fs::read_to_string(&path).await {
            Ok(content) if !content.trim().is_empty() => {
                Some(content[..content.len().min(max_len)].to_string())
            }
            _ => None,
        }
    }

    async fn validate_output(&self) -> Result<bool, SekuraError> {
        let deliverables_dir = self.config.deliverables_dir();
        for deliverable in self.agent_def.required_deliverables {
            let path = deliverables_dir.join(deliverable.filename());
            if !path.exists() {
                warn!(file = %path.display(), "Missing required deliverable");
                return Ok(false);
            }
            if deliverable.is_queue() {
                let content = tokio::fs::read_to_string(&path).await?;
                if serde_json::from_str::<crate::queue::ExploitationQueue>(&content).is_err() {
                    warn!(file = %path.display(), "Invalid queue JSON");
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}
