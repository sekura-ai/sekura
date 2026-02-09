use crate::cli::commands::StopArgs;
use crate::errors::SekuraError;
use crate::container::manager::ContainerManager;
use crate::config::ContainerConfig;
use tracing::info;

pub async fn handle_stop(args: StopArgs) -> Result<(), SekuraError> {
    if let Some(scan_id) = &args.scan_id {
        info!(scan_id = %scan_id, "Stopping scan");
        let client = reqwest::Client::new();
        client.post(format!("http://localhost:8080/api/scans/{}/stop", scan_id))
            .send().await
            .map_err(|e| SekuraError::Network(format!("Failed to stop scan: {}", e)))?;
        println!("Stop signal sent for scan {}", scan_id);
    }

    if args.remove {
        info!("Stopping and removing Kali container");
        let config = ContainerConfig::default();
        let manager = ContainerManager::new(&config).await?;
        manager.stop(true).await?;
        println!("Container removed");
    } else {
        let config = ContainerConfig::default();
        let manager = ContainerManager::new(&config).await?;
        manager.stop(false).await?;
        println!("Container stopped");
    }

    Ok(())
}
