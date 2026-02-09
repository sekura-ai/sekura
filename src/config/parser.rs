use std::path::Path;
use crate::errors::SekuraError;
use super::types::SekuraConfig;
use super::security::validate_security_patterns;

pub async fn parse_config(path: &Path) -> Result<SekuraConfig, SekuraError> {
    if !path.exists() {
        return Err(SekuraError::Config(format!("Config file not found: {}", path.display())));
    }

    let metadata = tokio::fs::metadata(path).await?;
    if metadata.len() > 1_048_576 {
        return Err(SekuraError::Config("Config file exceeds 1MB limit".into()));
    }

    let content = tokio::fs::read_to_string(path).await?;
    let yaml: serde_yaml::Value = serde_yaml::from_str(&content)?;

    // Security pattern validation
    validate_security_patterns(&yaml)?;

    // Parse into typed config
    let config: SekuraConfig = serde_yaml::from_value(yaml)?;

    Ok(config)
}
