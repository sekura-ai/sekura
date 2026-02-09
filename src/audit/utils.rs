use std::path::Path;
use crate::errors::SekuraError;

/// Atomic file write: write to temp, then rename
pub async fn atomic_write(path: &Path, content: &str) -> Result<(), SekuraError> {
    let tmp = path.with_extension("tmp");
    tokio::fs::write(&tmp, content).await?;
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}
