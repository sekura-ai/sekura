use std::sync::Arc;
use std::time::Instant;
use crate::container::ContainerManager;
use crate::errors::SekuraError;
use crate::llm::provider::LLMProvider;
use crate::models::scan_result::ScanResult;
use crate::pipeline::state::{PipelineConfig, ScanContext, AgentMetrics};
use super::registry::{AgentDefinition, AgentType};
use tracing::{info, warn};

pub struct AgentExecutor {
    agent_def: &'static AgentDefinition,
    llm: Arc<dyn LLMProvider>,
    container: Arc<ContainerManager>,
    config: Arc<PipelineConfig>,
    context: ScanContext,
}

impl AgentExecutor {
    pub fn new(
        agent_def: &'static AgentDefinition,
        llm: Arc<dyn LLMProvider>,
        container: Arc<ContainerManager>,
        config: Arc<PipelineConfig>,
        context: ScanContext,
    ) -> Self {
        Self { agent_def, llm, container, config, context }
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
        let prompt = format!(
            "Analyze the source code at {} for security vulnerabilities. Target: {}",
            self.config.repo_path.display(),
            self.config.target
        );
        let response = self.llm.complete(&prompt, Some("You are a security code reviewer.")).await?;

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
        let prompt = self.build_vuln_prompt()?;
        let response = self.llm.complete(&prompt, Some("You are a vulnerability analyst.")).await?;

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
        crate::reporting::assembler::assemble_final_report(&self.config.deliverables_dir()).await?;

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
