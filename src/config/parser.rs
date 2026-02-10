use std::path::Path;
use crate::errors::SekuraError;
use super::types::SekuraConfig;
use super::security::validate_security_patterns;
use super::schema::CONFIG_SCHEMA;
use tracing::warn;

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

    // JSON Schema validation
    validate_schema(&yaml)?;

    // Parse into typed config
    let config: SekuraConfig = serde_yaml::from_value(yaml)?;

    // Semantic conflict detection
    validate_conflicts(&config)?;

    Ok(config)
}

/// Validate config against the JSON schema for structural correctness.
fn validate_schema(yaml: &serde_yaml::Value) -> Result<(), SekuraError> {
    // Convert YAML value to JSON for schema validation
    let json_str = serde_json::to_string(yaml)
        .map_err(|e| SekuraError::Config(format!("Config conversion error: {}", e)))?;
    let json_value: serde_json::Value = serde_json::from_str(&json_str)
        .map_err(|e| SekuraError::Config(format!("Config conversion error: {}", e)))?;

    let compiled = jsonschema::JSONSchema::compile(&CONFIG_SCHEMA)
        .map_err(|e| SekuraError::Config(format!("Schema compilation error: {}", e)))?;

    let result = compiled.validate(&json_value);
    if let Err(errors) = result {
        let messages: Vec<String> = errors
            .map(|e| format!("{} at {}", e, e.instance_path))
            .collect();
        if !messages.is_empty() {
            // Warn but don't fail — schema validation is advisory for now
            for msg in &messages {
                warn!(validation_error = %msg, "Config schema warning");
            }
        }
    }

    Ok(())
}

/// Detect semantic conflicts in the parsed configuration.
fn validate_conflicts(config: &SekuraConfig) -> Result<(), SekuraError> {
    // Check avoid/focus rule conflicts
    if let Some(rules) = &config.rules {
        if let (Some(avoid), Some(focus)) = (&rules.avoid, &rules.focus) {
            for a in avoid {
                for f in focus {
                    if a.url_path == f.url_path && a.rule_type == f.rule_type {
                        return Err(SekuraError::Config(format!(
                            "Conflicting rules: path '{}' appears in both avoid and focus lists",
                            a.url_path
                        )));
                    }
                }
            }
        }
    }

    // Warn if auth is configured but credentials are empty
    if let Some(auth) = &config.authentication {
        let has_username = auth.credentials.username.as_ref().map_or(false, |u| !u.is_empty());
        let has_password = auth.credentials.password.as_ref().map_or(false, |p| !p.is_empty());
        if !has_username && !has_password {
            warn!("Authentication configured but no credentials provided");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_conflicts_overlapping_rules() {
        use crate::config::{RulesConfig, Rule, RuleType};
        let config = SekuraConfig {
            rules: Some(RulesConfig {
                avoid: Some(vec![Rule {
                    description: "avoid admin".to_string(),
                    rule_type: RuleType::Path,
                    url_path: "/admin".to_string(),
                }]),
                focus: Some(vec![Rule {
                    description: "focus admin".to_string(),
                    rule_type: RuleType::Path,
                    url_path: "/admin".to_string(),
                }]),
            }),
            ..Default::default()
        };
        assert!(validate_conflicts(&config).is_err());
    }

    #[test]
    fn test_validate_conflicts_no_overlap() {
        use crate::config::{RulesConfig, Rule, RuleType};
        let config = SekuraConfig {
            rules: Some(RulesConfig {
                avoid: Some(vec![Rule {
                    description: "avoid admin".to_string(),
                    rule_type: RuleType::Path,
                    url_path: "/admin".to_string(),
                }]),
                focus: Some(vec![Rule {
                    description: "focus api".to_string(),
                    rule_type: RuleType::Path,
                    url_path: "/api".to_string(),
                }]),
            }),
            ..Default::default()
        };
        assert!(validate_conflicts(&config).is_ok());
    }

    #[test]
    fn test_validate_conflicts_empty_config() {
        let config = SekuraConfig::default();
        assert!(validate_conflicts(&config).is_ok());
    }
}
