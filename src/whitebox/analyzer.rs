use std::path::{Path, PathBuf};
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use crate::llm::provider::LLMProvider;
use crate::prompts::{PromptLoader, PromptVariables};
use crate::errors::SekuraError;
use tracing::{info, debug};

#[derive(Debug, Serialize, Deserialize)]
pub struct CodeAnalysis {
    pub architecture: String,
    pub entry_points: Vec<String>,
    pub sinks: Vec<String>,
    pub data_flows: Vec<String>,
    pub auth_mechanisms: Vec<String>,
    pub security_controls: Vec<String>,
    pub attack_surface: Vec<String>,
}

pub struct WhiteboxAnalyzer {
    llm: Arc<dyn LLMProvider>,
    repo_path: PathBuf,
    prompt_loader: Arc<PromptLoader>,
}

impl WhiteboxAnalyzer {
    pub fn new(llm: Arc<dyn LLMProvider>, repo_path: &Path, prompt_loader: Arc<PromptLoader>) -> Self {
        Self {
            llm,
            repo_path: repo_path.to_path_buf(),
            prompt_loader,
        }
    }

    pub async fn analyze(&self) -> Result<CodeAnalysis, SekuraError> {
        info!(repo = %self.repo_path.display(), "Starting white-box analysis");

        let file_manifest = self.scan_files().await?;
        let classified = self.classify_files(&file_manifest);

        // Load the whitebox analysis system prompt from template
        let system_prompt = match self.prompt_loader.load("whitebox-analysis") {
            Ok(template) => {
                let vars = PromptVariables {
                    target_url: String::new(),
                    repo_path: Some(self.repo_path.display().to_string()),
                    ..Default::default()
                };
                self.prompt_loader.interpolate(&template, &vars)
            }
            Err(e) => {
                debug!(error = %e, "Failed to load whitebox-analysis prompt, using fallback");
                "You are an expert security code reviewer. Identify vulnerabilities, sinks, and attack surfaces.".to_string()
            }
        };

        let mut analysis_parts = Vec::new();
        for (group_name, files) in &classified {
            if files.is_empty() { continue; }
            let chunk = self.build_file_chunk(files).await?;
            if chunk.is_empty() { continue; }

            let prompt = format!(
                "Analyze these {} source files for security vulnerabilities.\nIdentify: entry points, dangerous sinks, data flows, auth mechanisms, and attack surface.\n\n{}",
                group_name, chunk
            );

            let response = self.llm.complete(&prompt, Some(&system_prompt)).await?;
            analysis_parts.push(response.content);
        }

        let combined = analysis_parts.join("\n\n---\n\n");

        Ok(CodeAnalysis {
            architecture: combined.clone(),
            entry_points: Vec::new(),
            sinks: Vec::new(),
            data_flows: Vec::new(),
            auth_mechanisms: Vec::new(),
            security_controls: Vec::new(),
            attack_surface: Vec::new(),
        })
    }

    async fn scan_files(&self) -> Result<Vec<FileInfo>, SekuraError> {
        let mut files = Vec::new();
        let exclude_dirs = [".git", "node_modules", "vendor", "dist", "build", "__pycache__", ".venv", "target"];
        let code_extensions = ["rs", "py", "js", "ts", "jsx", "tsx", "go", "java", "php", "rb", "cs", "c", "cpp", "h", "hpp", "sql", "yaml", "yml", "json", "xml", "html", "htm", "conf", "cfg", "ini", "env"];

        self.walk_dir(&self.repo_path, &exclude_dirs, &code_extensions, &mut files)?;
        files.sort_by(|a, b| a.relevance_score().cmp(&b.relevance_score()).reverse());
        Ok(files)
    }

    fn walk_dir(
        &self,
        dir: &Path,
        exclude: &[&str],
        extensions: &[&str],
        files: &mut Vec<FileInfo>,
    ) -> Result<(), SekuraError> {
        if !dir.is_dir() { return Ok(()); }

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            if exclude.iter().any(|e| name == *e) { continue; }

            if path.is_dir() {
                self.walk_dir(&path, exclude, extensions, files)?;
            } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if extensions.contains(&ext) {
                    let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                    if size < 500_000 {
                        files.push(FileInfo {
                            path: path.clone(),
                            extension: ext.to_string(),
                            size,
                        });
                    }
                }
            }
        }
        Ok(())
    }

    fn classify_files<'a>(&self, files: &'a [FileInfo]) -> Vec<(String, Vec<&'a FileInfo>)> {
        let mut groups: Vec<(String, Vec<&FileInfo>)> = vec![
            ("entry_points".into(), Vec::new()),
            ("auth".into(), Vec::new()),
            ("data".into(), Vec::new()),
            ("config".into(), Vec::new()),
            ("templates".into(), Vec::new()),
            ("other".into(), Vec::new()),
        ];

        let route_patterns = ["route", "controller", "handler", "endpoint", "api", "view"];
        let auth_patterns = ["auth", "login", "session", "middleware", "jwt", "token", "passport"];
        let data_patterns = ["model", "schema", "query", "database", "db", "orm", "migration", "repository"];
        let config_patterns = ["config", "setting", "env", ".env"];
        let template_patterns = ["template", "view", "layout", "partial"];

        for file in files {
            let path_lower = file.path.to_string_lossy().to_lowercase();
            let name_lower = file.path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_lowercase();

            if route_patterns.iter().any(|p| path_lower.contains(p) || name_lower.contains(p)) {
                groups[0].1.push(file);
            } else if auth_patterns.iter().any(|p| path_lower.contains(p) || name_lower.contains(p)) {
                groups[1].1.push(file);
            } else if data_patterns.iter().any(|p| path_lower.contains(p) || name_lower.contains(p)) {
                groups[2].1.push(file);
            } else if config_patterns.iter().any(|p| path_lower.contains(p) || name_lower.contains(p)) {
                groups[3].1.push(file);
            } else if template_patterns.iter().any(|p| path_lower.contains(p) || name_lower.contains(p)) {
                groups[4].1.push(file);
            } else {
                groups[5].1.push(file);
            }
        }

        groups
    }

    async fn build_file_chunk(&self, files: &[&FileInfo]) -> Result<String, SekuraError> {
        let mut chunk = String::new();
        let max_chunk_size = 50_000;

        for file in files {
            if chunk.len() > max_chunk_size { break; }
            if let Ok(content) = tokio::fs::read_to_string(&file.path).await {
                let relative = file.path.strip_prefix(&self.repo_path).unwrap_or(&file.path);
                chunk.push_str(&format!("\n### File: {}\n```{}\n{}\n```\n",
                    relative.display(),
                    file.extension,
                    &content[..content.len().min(10_000)]
                ));
            }
        }

        Ok(chunk)
    }
}

#[derive(Debug)]
pub struct FileInfo {
    pub path: PathBuf,
    pub extension: String,
    pub size: u64,
}

impl FileInfo {
    fn relevance_score(&self) -> u32 {
        let path_str = self.path.to_string_lossy().to_lowercase();
        let mut score = 0u32;
        if path_str.contains("route") || path_str.contains("controller") { score += 10; }
        if path_str.contains("auth") || path_str.contains("login") { score += 8; }
        if path_str.contains("model") || path_str.contains("db") { score += 6; }
        if path_str.contains("config") { score += 4; }
        if path_str.contains("test") { score = score.saturating_sub(2); }
        score
    }
}
