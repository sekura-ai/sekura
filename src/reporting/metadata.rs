use std::path::Path;
use std::collections::BTreeSet;
use crate::errors::SekuraError;
use crate::audit::metrics_tracker::SessionData;

pub async fn inject_model_metadata(
    report_path: &Path,
    audit_dir: &Path,
) -> Result<(), SekuraError> {
    let session_path = audit_dir.join("session.json");
    if !session_path.exists() { return Ok(()); }

    let session: SessionData = serde_json::from_str(
        &tokio::fs::read_to_string(&session_path).await?
    )?;

    let models: BTreeSet<String> = session.agents.values()
        .filter_map(|a| a.model.clone())
        .collect();

    if models.is_empty() { return Ok(()); }

    let model_str = models.into_iter().collect::<Vec<_>>().join(", ");

    let report = tokio::fs::read_to_string(report_path).await?;
    let updated = report.replace(
        "Assessment Date:",
        &format!("- Model: {}\n- Assessment Date:", model_str),
    );
    tokio::fs::write(report_path, &updated).await?;

    Ok(())
}
