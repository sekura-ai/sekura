use std::path::{Path, PathBuf};
use chrono::Utc;
use tokio::io::AsyncWriteExt;
use crate::errors::SekuraError;

pub struct WorkflowLogger {
    path: PathBuf,
}

impl WorkflowLogger {
    pub fn new(base_dir: &Path) -> Self {
        Self { path: base_dir.join("workflow.log") }
    }

    pub async fn initialize(&self) -> Result<(), SekuraError> {
        let header = format!("# Sekura Workflow Log\n# Started: {}\n\n", Utc::now().to_rfc3339());
        tokio::fs::write(&self.path, &header).await?;
        Ok(())
    }

    pub async fn log_event(&self, message: &str) -> Result<(), SekuraError> {
        let line = format!("[{}] {}\n", Utc::now().format("%H:%M:%S"), message);
        let mut file = tokio::fs::OpenOptions::new()
            .create(true).append(true).open(&self.path).await?;
        file.write_all(line.as_bytes()).await?;
        Ok(())
    }
}
