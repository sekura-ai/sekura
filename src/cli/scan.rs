use crate::cli::commands::StartArgs;
use crate::errors::SekuraError;

pub async fn handle_scan(args: StartArgs) -> Result<(), SekuraError> {
    // Scan is an alias for start in headless mode
    super::start::handle_start(args).await
}
