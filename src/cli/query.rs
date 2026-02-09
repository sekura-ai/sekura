use crate::cli::commands::QueryArgs;
use crate::errors::SekuraError;
use tracing::info;

pub async fn handle_query(args: QueryArgs) -> Result<(), SekuraError> {
    info!(scan_id = %args.scan_id, "Querying scan status");

    let client = reqwest::Client::new();
    let base = format!("http://localhost:8080/api/scans/{}/status", args.scan_id);

    loop {
        let resp = client.get(&base).send().await
            .map_err(|e| SekuraError::Network(format!("Failed to query scan: {}", e)))?;

        let status: serde_json::Value = resp.json().await
            .map_err(|e| SekuraError::Network(format!("Invalid response: {}", e)))?;

        if args.json {
            println!("{}", serde_json::to_string_pretty(&status)?);
        } else {
            println!("Status: {}", status["status"].as_str().unwrap_or("unknown"));
            if let Some(phase) = status["current_phase"].as_str() {
                println!("Phase: {}", phase);
            }
            if let Some(agents) = status["completed_agents"].as_array() {
                println!("Completed: {}/{}", agents.len(), status["completed_agents"].as_array().map(|a| a.len()).unwrap_or(0));
            }
        }

        let scan_status = status["status"].as_str().unwrap_or("");
        if !args.follow || scan_status == "completed" || scan_status == "failed" {
            break;
        }

        tokio::time::sleep(std::time::Duration::from_secs(args.interval)).await;
    }

    Ok(())
}
