use std::path::Path;
use crate::errors::SekuraError;
use super::{ExploitationQueue, ExploitationDecision, VulnType};

pub async fn validate_queue_and_deliverable(
    vuln_type: VulnType,
    deliverables_dir: &Path,
) -> Result<ExploitationDecision, SekuraError> {
    let analysis_file = deliverables_dir.join(vuln_type.analysis_filename());
    let queue_file = deliverables_dir.join(vuln_type.queue_filename());

    let analysis_exists = analysis_file.exists();
    let queue_exists = queue_file.exists();

    match (analysis_exists, queue_exists) {
        (false, false) => {
            Ok(ExploitationDecision {
                should_exploit: false,
                vulnerability_count: 0,
                vuln_type,
            })
        }
        (true, false) => {
            Ok(ExploitationDecision {
                should_exploit: false,
                vulnerability_count: 0,
                vuln_type,
            })
        }
        (false, true) => {
            Err(SekuraError::OutputValidation(
                "Queue exists but deliverable file missing".into()
            ))
        }
        (true, true) => {
            let content = tokio::fs::read_to_string(&queue_file).await?;
            let queue: ExploitationQueue = serde_json::from_str(&content)
                .map_err(|e| SekuraError::OutputValidation(
                    format!("Invalid queue JSON: {}", e)
                ))?;

            Ok(ExploitationDecision {
                should_exploit: !queue.vulnerabilities.is_empty(),
                vulnerability_count: queue.vulnerabilities.len(),
                vuln_type,
            })
        }
    }
}
