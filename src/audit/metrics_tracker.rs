use std::path::{Path, PathBuf};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::agents::registry::AgentName;
use crate::errors::SekuraError;
use crate::models::scan_result::ScanResult;
use chrono::Utc;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SessionData {
    pub scan_id: String,
    pub started_at: String,
    pub agents: HashMap<String, AgentSessionData>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentSessionData {
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub attempt: u32,
    pub duration_ms: Option<u64>,
    pub findings: Option<usize>,
    pub cost_usd: Option<f64>,
    pub model: Option<String>,
    pub status: String,
}

pub struct MetricsTracker {
    path: PathBuf,
    data: SessionData,
}

impl MetricsTracker {
    pub fn new(base_dir: &Path) -> Self {
        Self {
            path: base_dir.join("session.json"),
            data: SessionData {
                started_at: Utc::now().to_rfc3339(),
                ..Default::default()
            },
        }
    }

    pub fn start_agent(&mut self, agent: AgentName, attempt: u32) {
        self.data.agents.insert(agent.as_str().to_string(), AgentSessionData {
            started_at: Some(Utc::now().to_rfc3339()),
            completed_at: None,
            attempt,
            duration_ms: None,
            findings: None,
            cost_usd: None,
            model: None,
            status: "running".to_string(),
        });
    }

    pub async fn end_agent(&mut self, agent: AgentName, result: &ScanResult) -> Result<(), SekuraError> {
        if let Some(entry) = self.data.agents.get_mut(agent.as_str()) {
            entry.completed_at = Some(Utc::now().to_rfc3339());
            entry.duration_ms = Some(result.duration_ms);
            entry.findings = Some(result.total_findings());
            entry.cost_usd = result.cost_usd;
            entry.model = result.model.clone();
            entry.status = "completed".to_string();
        }
        self.save().await
    }

    pub async fn save(&self) -> Result<(), SekuraError> {
        let tmp = self.path.with_extension("json.tmp");
        let json = serde_json::to_string_pretty(&self.data)?;
        tokio::fs::write(&tmp, &json).await?;
        tokio::fs::rename(&tmp, &self.path).await?;
        Ok(())
    }
}
