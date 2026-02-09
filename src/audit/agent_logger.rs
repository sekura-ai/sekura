use std::path::Path;
use chrono::Utc;
use tokio::io::AsyncWriteExt;
use crate::agents::registry::AgentName;
use crate::errors::SekuraError;

pub struct AgentLogger {
    file: tokio::fs::File,
}

impl AgentLogger {
    pub async fn new(
        base_dir: &Path,
        agent: AgentName,
        attempt: u32,
    ) -> Result<Self, SekuraError> {
        let filename = format!("{}_{}_attempt{}.jsonl",
            Utc::now().format("%Y%m%d_%H%M%S"),
            agent.as_str(),
            attempt,
        );
        let path = base_dir.join("agents").join(&filename);
        let file = tokio::fs::OpenOptions::new()
            .create(true).append(true).open(&path).await?;
        Ok(Self { file })
    }

    pub async fn log_event(
        &mut self,
        event_type: &str,
        data: &serde_json::Value,
    ) -> Result<(), SekuraError> {
        let entry = serde_json::json!({
            "timestamp": Utc::now().to_rfc3339(),
            "event": event_type,
            "data": data,
        });
        let mut line = serde_json::to_string(&entry)?;
        line.push('\n');
        self.file.write_all(line.as_bytes()).await?;
        self.file.flush().await?;
        Ok(())
    }
}
