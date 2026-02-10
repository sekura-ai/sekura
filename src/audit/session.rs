use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::io::AsyncWriteExt;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use crate::agents::registry::AgentName;
use crate::errors::SekuraError;
use crate::models::scan_result::ScanResult;
use super::agent_logger::AgentLogger;
use super::workflow_logger::WorkflowLogger;
use super::metrics_tracker::MetricsTracker;
use tracing::warn;

/// Structured audit event types for the append-only JSONL log.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub enum AuditEvent {
    ScanStarted {
        scan_id: String,
        target: String,
        intensity: String,
        provider: String,
    },
    PhaseStarted {
        phase: String,
    },
    PhaseCompleted {
        phase: String,
        duration_ms: u64,
    },
    AgentStarted {
        agent: String,
        attempt: u32,
    },
    AgentCompleted {
        agent: String,
        findings: usize,
        duration_ms: u64,
        cost_usd: Option<f64>,
    },
    AgentFailed {
        agent: String,
        error: String,
        retryable: bool,
    },
    TechniqueExecuted {
        technique: String,
        layer: String,
        duration_ms: u64,
        findings: usize,
    },
    ContainerExec {
        command_preview: String,
        exit_status: i64,
        duration_ms: u64,
        output_bytes: usize,
    },
    FindingDiscovered {
        title: String,
        severity: String,
        category: String,
    },
    CostUpdate {
        cumulative_usd: f64,
        agent: String,
        increment_usd: f64,
    },
    PromptSnapshot {
        agent: String,
        prompt_hash: String,
        prompt_length: usize,
    },
    ScanCompleted {
        total_findings: usize,
        total_cost_usd: f64,
        total_duration_ms: u64,
    },
    ScanFailed {
        error: String,
    },
    Warning {
        message: String,
    },
}

/// Crash-safe audit session that writes all events to an append-only JSONL file.
///
/// The JSONL format ensures that even if the process crashes mid-write, all
/// previously written events are preserved. The session.json file is updated
/// atomically via write-to-temp-then-rename.
pub struct AuditSession {
    base_dir: PathBuf,
    scan_id: String,
    metrics: Arc<Mutex<MetricsTracker>>,
    workflow_logger: Arc<Mutex<WorkflowLogger>>,
    /// Append-only JSONL event log, crash-safe.
    event_log: Arc<Mutex<tokio::fs::File>>,
    /// Cumulative cost tracking
    cumulative_cost: Arc<Mutex<f64>>,
}

impl AuditSession {
    pub async fn initialize(
        output_dir: &Path,
        scan_id: &str,
    ) -> Result<Self, SekuraError> {
        let base_dir = output_dir.join(scan_id);
        tokio::fs::create_dir_all(base_dir.join("agents")).await?;
        tokio::fs::create_dir_all(base_dir.join("prompts")).await?;

        let metrics = MetricsTracker::new(&base_dir);
        let workflow_logger = WorkflowLogger::new(&base_dir);
        workflow_logger.initialize().await?;

        // Create append-only JSONL audit log
        let event_log_path = base_dir.join("audit_events.jsonl");
        let event_log = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&event_log_path)
            .await?;

        Ok(Self {
            base_dir,
            scan_id: scan_id.to_string(),
            metrics: Arc::new(Mutex::new(metrics)),
            workflow_logger: Arc::new(Mutex::new(workflow_logger)),
            event_log: Arc::new(Mutex::new(event_log)),
            cumulative_cost: Arc::new(Mutex::new(0.0)),
        })
    }

    /// Record a structured audit event to the append-only JSONL log.
    /// This is crash-safe: each event is flushed immediately.
    pub async fn record_event(&self, event: AuditEvent) {
        let entry = serde_json::json!({
            "timestamp": Utc::now().to_rfc3339(),
            "scan_id": self.scan_id,
            "event": event,
        });
        if let Ok(mut line) = serde_json::to_string(&entry) {
            line.push('\n');
            let mut log = self.event_log.lock().await;
            if let Err(e) = log.write_all(line.as_bytes()).await {
                warn!(error = %e, "Failed to write audit event");
                return;
            }
            let _ = log.flush().await;
        }
    }

    /// Record scan start event with full configuration context.
    pub async fn record_scan_started(
        &self,
        target: &str,
        intensity: &str,
        provider: &str,
    ) {
        self.record_event(AuditEvent::ScanStarted {
            scan_id: self.scan_id.clone(),
            target: target.to_string(),
            intensity: intensity.to_string(),
            provider: provider.to_string(),
        }).await;
    }

    /// Record a container execution for auditing.
    /// Command is redacted to mask password arguments before logging.
    pub async fn record_container_exec(
        &self,
        command: &str,
        exit_status: i64,
        duration_ms: u64,
        output_bytes: usize,
    ) {
        // Redact sensitive arguments before logging
        let redacted = crate::config::redact_command(command);
        // Truncate command preview for audit log
        let preview = if redacted.len() > 200 {
            format!("{}...", &redacted[..200])
        } else {
            redacted
        };
        self.record_event(AuditEvent::ContainerExec {
            command_preview: preview,
            exit_status,
            duration_ms,
            output_bytes,
        }).await;
    }

    /// Record a cost increment and update cumulative total.
    pub async fn record_cost(&self, agent: &str, increment_usd: f64) {
        let mut total = self.cumulative_cost.lock().await;
        *total += increment_usd;
        self.record_event(AuditEvent::CostUpdate {
            cumulative_usd: *total,
            agent: agent.to_string(),
            increment_usd,
        }).await;
    }

    /// Get cumulative cost so far.
    pub async fn cumulative_cost(&self) -> f64 {
        *self.cumulative_cost.lock().await
    }

    pub async fn start_agent(
        &self,
        agent: AgentName,
        attempt: u32,
    ) -> Result<AgentLogger, SekuraError> {
        self.metrics.lock().await.start_agent(agent, attempt);
        self.workflow_logger.lock().await
            .log_event(&format!("Agent {} started (attempt {})", agent.as_str(), attempt)).await?;

        self.record_event(AuditEvent::AgentStarted {
            agent: agent.as_str().to_string(),
            attempt,
        }).await;

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

        self.record_event(AuditEvent::AgentCompleted {
            agent: agent.as_str().to_string(),
            findings: result.total_findings(),
            duration_ms: result.duration_ms,
            cost_usd: result.cost_usd,
        }).await;

        if let Some(cost) = result.cost_usd {
            self.record_cost(agent.as_str(), cost).await;
        }

        Ok(())
    }

    pub async fn end_agent_failed(
        &self,
        agent: AgentName,
        error: &SekuraError,
    ) -> Result<(), SekuraError> {
        let classification = error.classify();
        self.workflow_logger.lock().await
            .log_event(&format!("Agent {} failed: {}", agent.as_str(), error)).await?;

        self.record_event(AuditEvent::AgentFailed {
            agent: agent.as_str().to_string(),
            error: format!("{}", error),
            retryable: classification.retryable,
        }).await;

        Ok(())
    }

    pub async fn save_prompt(
        &self,
        agent: AgentName,
        prompt: &str,
    ) -> Result<(), SekuraError> {
        let path = self.base_dir.join("prompts").join(format!("{}.md", agent.as_str()));
        tokio::fs::write(&path, prompt).await?;

        // Record snapshot event with hash for traceability
        let hash = format!("{:x}", md5_hash(prompt));
        self.record_event(AuditEvent::PromptSnapshot {
            agent: agent.as_str().to_string(),
            prompt_hash: hash,
            prompt_length: prompt.len(),
        }).await;

        Ok(())
    }

    pub fn base_dir(&self) -> &PathBuf {
        &self.base_dir
    }

    pub fn scan_id(&self) -> &str {
        &self.scan_id
    }
}

/// Simple hash for prompt change tracking (not cryptographic).
fn md5_hash(input: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    input.hash(&mut hasher);
    hasher.finish()
}
