use std::path::{Path, PathBuf};
use regex::Regex;
use crate::errors::SekuraError;
use tracing::debug;

/// Variables available for template interpolation in prompt files.
#[derive(Debug, Clone, Default)]
pub struct PromptVariables {
    pub target_url: String,
    pub repo_path: Option<String>,
    pub intensity: String,
    pub code_analysis: Option<String>,
    pub recon_data: Option<String>,
    pub tool_findings: Option<String>,
    pub exploitation_queue: Option<String>,
    pub vuln_type: Option<String>,
    pub rules_avoid: Option<String>,
    pub rules_focus: Option<String>,
    pub login_instructions: Option<String>,
    pub open_ports: Option<String>,
    pub cookie_string: Option<String>,
    pub auth_context: Option<String>,
}

/// Loads and processes prompt template files with include directives and variable interpolation.
pub struct PromptLoader {
    prompts_dir: PathBuf,
}

const MAX_INCLUDE_DEPTH: u8 = 5;

impl PromptLoader {
    pub fn new(prompts_dir: PathBuf) -> Self {
        debug!(dir = %prompts_dir.display(), "PromptLoader initialized");
        Self { prompts_dir }
    }

    /// Load a prompt template by name (without .txt extension), processing @include directives.
    pub fn load(&self, prompt_name: &str) -> Result<String, SekuraError> {
        let file_path = self.prompts_dir.join(format!("{}.txt", prompt_name));
        if !file_path.exists() {
            return Err(SekuraError::Prompt(format!(
                "Prompt file not found: {}",
                file_path.display()
            )));
        }
        let content = std::fs::read_to_string(&file_path).map_err(|e| {
            SekuraError::Prompt(format!("Failed to read prompt {}: {}", file_path.display(), e))
        })?;
        self.process_includes(&content, 0)
    }

    /// Replace {{VARIABLE}} placeholders with values from PromptVariables.
    /// None values become empty string.
    pub fn interpolate(&self, template: &str, vars: &PromptVariables) -> String {
        let mut result = template.to_string();

        let replacements: &[(&str, &str)] = &[
            ("{{TARGET_URL}}", &vars.target_url),
            ("{{WEB_URL}}", &vars.target_url),
            ("{{INTENSITY}}", &vars.intensity),
        ];
        for (placeholder, value) in replacements {
            result = result.replace(placeholder, value);
        }

        let optional_replacements: &[(&str, &Option<String>)] = &[
            ("{{REPO_PATH}}", &vars.repo_path),
            ("{{CODE_ANALYSIS}}", &vars.code_analysis),
            ("{{RECON_DATA}}", &vars.recon_data),
            ("{{TOOL_FINDINGS}}", &vars.tool_findings),
            ("{{EXPLOITATION_QUEUE}}", &vars.exploitation_queue),
            ("{{VULN_TYPE}}", &vars.vuln_type),
            ("{{RULES_AVOID}}", &vars.rules_avoid),
            ("{{RULES_FOCUS}}", &vars.rules_focus),
            ("{{LOGIN_INSTRUCTIONS}}", &vars.login_instructions),
            ("{{OPEN_PORTS}}", &vars.open_ports),
            ("{{COOKIE_STRING}}", &vars.cookie_string),
            ("{{AUTH_CONTEXT}}", &vars.auth_context),
        ];
        for (placeholder, value) in optional_replacements {
            let replacement = value.as_deref().unwrap_or("");
            result = result.replace(placeholder, replacement);
        }

        result
    }

    /// Process @include(path) directives recursively with depth limit.
    fn process_includes(&self, content: &str, depth: u8) -> Result<String, SekuraError> {
        if depth >= MAX_INCLUDE_DEPTH {
            return Err(SekuraError::Prompt(format!(
                "Include depth limit ({}) exceeded — possible circular include",
                MAX_INCLUDE_DEPTH
            )));
        }

        let include_re = Regex::new(r"@include\(([^)]+)\)").unwrap();
        let mut result = content.to_string();

        // Collect matches first to avoid borrow issues
        let matches: Vec<(String, String)> = include_re
            .captures_iter(content)
            .map(|cap| (cap[0].to_string(), cap[1].to_string()))
            .collect();

        for (full_match, include_path) in matches {
            let file_path = self.prompts_dir.join(&include_path);
            if !file_path.exists() {
                return Err(SekuraError::Prompt(format!(
                    "Included file not found: {} (referenced as @include({}))",
                    file_path.display(),
                    include_path
                )));
            }
            let included_content = std::fs::read_to_string(&file_path).map_err(|e| {
                SekuraError::Prompt(format!(
                    "Failed to read included file {}: {}",
                    file_path.display(),
                    e
                ))
            })?;
            let processed = self.process_includes(&included_content, depth + 1)?;
            result = result.replace(&full_match, &processed);
        }

        Ok(result)
    }

    /// Check if a prompt template file exists.
    pub fn has_prompt(&self, prompt_name: &str) -> bool {
        self.prompts_dir.join(format!("{}.txt", prompt_name)).exists()
    }

    /// Return the prompts directory path.
    pub fn prompts_dir(&self) -> &Path {
        &self.prompts_dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup_test_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();

        // Create shared directory
        fs::create_dir_all(dir.path().join("shared")).unwrap();

        // Create a shared partial
        fs::write(
            dir.path().join("shared/_target.txt"),
            "URL: {{TARGET_URL}}",
        )
        .unwrap();

        // Create a main prompt that includes the shared partial
        fs::write(
            dir.path().join("test-prompt.txt"),
            "<target>\n@include(shared/_target.txt)\n</target>\n\nAnalyze {{VULN_TYPE}} for {{TARGET_URL}}.",
        )
        .unwrap();

        // Create a simple prompt without includes
        fs::write(
            dir.path().join("simple.txt"),
            "Hello {{TARGET_URL}}, intensity={{INTENSITY}}.",
        )
        .unwrap();

        dir
    }

    #[test]
    fn test_load_simple_prompt() {
        let dir = setup_test_dir();
        let loader = PromptLoader::new(dir.path().to_path_buf());
        let content = loader.load("simple").unwrap();
        assert_eq!(content, "Hello {{TARGET_URL}}, intensity={{INTENSITY}}.");
    }

    #[test]
    fn test_load_with_includes() {
        let dir = setup_test_dir();
        let loader = PromptLoader::new(dir.path().to_path_buf());
        let content = loader.load("test-prompt").unwrap();
        assert!(content.contains("URL: {{TARGET_URL}}"));
        assert!(!content.contains("@include"));
    }

    #[test]
    fn test_interpolate() {
        let dir = setup_test_dir();
        let loader = PromptLoader::new(dir.path().to_path_buf());
        let vars = PromptVariables {
            target_url: "https://example.com".to_string(),
            intensity: "thorough".to_string(),
            vuln_type: Some("injection".to_string()),
            ..Default::default()
        };
        let template = "Target: {{TARGET_URL}}, Type: {{VULN_TYPE}}, Rules: {{RULES_AVOID}}";
        let result = loader.interpolate(template, &vars);
        assert_eq!(
            result,
            "Target: https://example.com, Type: injection, Rules: "
        );
    }

    #[test]
    fn test_missing_prompt_returns_error() {
        let dir = setup_test_dir();
        let loader = PromptLoader::new(dir.path().to_path_buf());
        assert!(loader.load("nonexistent").is_err());
    }

    #[test]
    fn test_has_prompt() {
        let dir = setup_test_dir();
        let loader = PromptLoader::new(dir.path().to_path_buf());
        assert!(loader.has_prompt("simple"));
        assert!(!loader.has_prompt("nonexistent"));
    }
}
