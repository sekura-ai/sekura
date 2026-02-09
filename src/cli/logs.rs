use crate::cli::commands::LogsArgs;
use crate::errors::SekuraError;
use std::path::PathBuf;
use tracing::info;

pub async fn handle_logs(args: LogsArgs) -> Result<(), SekuraError> {
    info!(scan_id = %args.scan_id, "Streaming logs");

    let log_path = PathBuf::from("./results")
        .join(&args.scan_id)
        .join("workflow.log");

    if !log_path.exists() {
        return Err(SekuraError::Config(format!(
            "No logs found for scan {}. Path: {}",
            args.scan_id, log_path.display()
        )));
    }

    let content = tokio::fs::read_to_string(&log_path).await?;
    let lines: Vec<&str> = content.lines().collect();
    let start = if lines.len() > args.lines { lines.len() - args.lines } else { 0 };

    for line in &lines[start..] {
        println!("{}", line);
    }

    if args.follow {
        use tokio::time::{sleep, Duration};
        let mut last_size = content.len();
        loop {
            sleep(Duration::from_secs(1)).await;
            let new_content = tokio::fs::read_to_string(&log_path).await?;
            if new_content.len() > last_size {
                print!("{}", &new_content[last_size..]);
                last_size = new_content.len();
            }
        }
    }

    Ok(())
}
