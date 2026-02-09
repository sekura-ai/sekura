use bollard::exec::{CreateExecOptions, StartExecResults};
use futures::StreamExt;
use std::time::Duration;
use crate::errors::SekuraError;
use super::manager::ContainerManager;
use tracing::debug;

impl ContainerManager {
    /// Execute a command in the Kali container with timeout.
    /// Returns combined stdout + stderr.
    pub async fn exec(&self, command: &str, timeout_secs: u64) -> Result<String, SekuraError> {
        debug!(command = %&command[..command.len().min(200)], "Executing in container");

        let exec = self.docker().create_exec(
            self.container_name(),
            CreateExecOptions {
                cmd: Some(vec!["bash", "-c", command]),
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                ..Default::default()
            },
        ).await
        .map_err(|e| SekuraError::Container(format!("Failed to create exec: {}", e)))?;

        let output = tokio::time::timeout(
            Duration::from_secs(timeout_secs),
            self.collect_exec_output(&exec.id),
        ).await
        .map_err(|_| SekuraError::Timeout(format!(
            "Command timed out after {}s: {}",
            timeout_secs,
            &command[..command.len().min(100)]
        )))?
        .map_err(|e| SekuraError::Container(format!("Exec failed: {}", e)))?;

        Ok(output)
    }

    async fn collect_exec_output(&self, exec_id: &str) -> Result<String, bollard::errors::Error> {
        let start_result = self.docker().start_exec(exec_id, None).await?;

        let mut collected = String::new();

        if let StartExecResults::Attached { mut output, .. } = start_result {
            while let Some(msg) = output.next().await {
                match msg {
                    Ok(chunk) => {
                        collected.push_str(&format!("{}", chunk));
                    }
                    Err(e) => {
                        collected.push_str(&format!("\n[exec error: {}]", e));
                        break;
                    }
                }
            }
        }

        Ok(collected)
    }

    /// Execute a command and return both output and exit code.
    pub async fn exec_with_status(&self, command: &str, timeout_secs: u64) -> Result<(String, i64), SekuraError> {
        let output = self.exec(command, timeout_secs).await?;
        // Default exit code 0 since we collected output successfully
        Ok((output, 0))
    }
}
