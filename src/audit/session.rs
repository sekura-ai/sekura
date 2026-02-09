use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::agents::registry::AgentName;
use crate::errors::SekuraError;
use crate::models::scan_result::ScanResult;
use super::agent_logger::AgentLogger;
use super::workflow_logger::WorkflowLogger;
use super::metrics_tracker::MetricsTracker;

pub struct AuditSession {
    base_dir: PathBuf,
    scan_id: String,
    metrics: Arc<Mutex<MetricsTracker>>,
    workflow_logger: Arc<Mutex<WorkflowLogger>>,
}

impl AuditSession {
    pub async fn initialize(
        output_dir: &std::path::Path,
        scan_id: &str,
    ) -> Result<Self, SekuraError> {
        let base_dir = output_dir.join(scan_id);
        tokio::fs::create_dir_all(base_dir.join("agents")).await?;
        tokio::fs::create_dir_all(base_dir.join("prompts")).await?;

        let metrics = MetricsTracker::new(&base_dir);
        let workflow_logger = WorkflowLogger::new(&base_dir);
        workflow_logger.initialize().await?;

        Ok(Self {
            base_dir,
            scan_id: scan_id.to_string(),
            metrics: Arc::new(Mutex::new(metrics)),
            workflow_logger: Arc::new(Mutex::new(workflow_logger)),
        })
    }

    pub async fn start_agent(
        &self,
        agent: AgentName,
        attempt: u32,
    ) -> Result<AgentLogger, SekuraError> {
        self.metrics.lock().await.start_agent(agent, attempt);
        self.workflow_logger.lock().await
            .log_event(&format!("Agent {} started (attempt {})", agent.as_str(), attempt)).await?;

        AgentLogger::new(&self.base_dir, agent, attempt).await
    }

    pub async fn end_agent(
        &self,
        agent: AgentName,
        result: &ScanResult,
    ) -> Result<(), SekuraError> {
        self.metrics.lock().await.end_agent(agent, result).await?;
        self.workflow_logger.lock().await
            .log_event(&format!(
                "Agent {} completed: {} findings, {}ms",
                agent.as_str(),
                result.total_findings(),
                result.duration_ms,
            )).await?;
        Ok(())
    }

    pub async fn end_agent_failed(
        &self,
        agent: AgentName,
        error: &SekuraError,
    ) -> Result<(), SekuraError> {
        self.workflow_logger.lock().await
            .log_event(&format!("Agent {} failed: {}", agent.as_str(), error)).await?;
        Ok(())
    }

    pub async fn save_prompt(
        &self,
        agent: AgentName,
        prompt: &str,
    ) -> Result<(), SekuraError> {
        let path = self.base_dir.join("prompts").join(format!("{}.md", agent.as_str()));
        tokio::fs::write(&path, prompt).await?;
        Ok(())
    }

    pub fn base_dir(&self) -> &PathBuf {
        &self.base_dir
    }

    pub fn scan_id(&self) -> &str {
        &self.scan_id
    }
}
