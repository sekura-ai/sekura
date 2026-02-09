use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::path::PathBuf;
use crate::config::Intensity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineState {
    pub status: PipelineStatus,
    pub current_phase: Option<PhaseName>,
    pub current_agents: Vec<String>,
    pub completed_agents: Vec<String>,
    pub failed_agents: Vec<String>,
    pub error: Option<String>,
    pub start_time: DateTime<Utc>,
    pub agent_metrics: HashMap<String, AgentMetrics>,
    pub summary: Option<PipelineSummary>,
}

impl PipelineState {
    pub fn new() -> Self {
        Self {
            status: PipelineStatus::Queued,
            current_phase: None,
            current_agents: Vec::new(),
            completed_agents: Vec::new(),
            failed_agents: Vec::new(),
            error: None,
            start_time: Utc::now(),
            agent_metrics: HashMap::new(),
            summary: None,
        }
    }
}

impl Default for PipelineState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PipelineStatus {
    Queued,
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum PhaseName {
    WhiteboxAnalysis,
    Reconnaissance,
    VulnerabilityAnalysis,
    Exploitation,
    Reporting,
}

impl std::fmt::Display for PhaseName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WhiteboxAnalysis => write!(f, "whitebox-analysis"),
            Self::Reconnaissance => write!(f, "reconnaissance"),
            Self::VulnerabilityAnalysis => write!(f, "vulnerability-analysis"),
            Self::Exploitation => write!(f, "exploitation"),
            Self::Reporting => write!(f, "reporting"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMetrics {
    pub duration_ms: u64,
    pub cost_usd: Option<f64>,
    pub turns: Option<u32>,
    pub model: Option<String>,
    pub attempt_count: u32,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineSummary {
    pub total_cost_usd: f64,
    pub total_duration_ms: u64,
    pub total_findings: usize,
    pub finding_counts: HashMap<String, usize>,
    pub agent_count: usize,
    pub phases_completed: usize,
}

impl Default for PipelineSummary {
    fn default() -> Self {
        Self {
            total_cost_usd: 0.0,
            total_duration_ms: 0,
            total_findings: 0,
            finding_counts: HashMap::new(),
            agent_count: 0,
            phases_completed: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PipelineConfig {
    pub scan_id: String,
    pub target: String,
    pub repo_path: PathBuf,
    pub output_dir: PathBuf,
    pub intensity: Intensity,
    pub provider: String,
    pub model: Option<String>,
    pub api_key: String,
    pub base_url: String,
    pub skip_whitebox: bool,
    pub skip_blackbox: bool,
    pub skip_exploit: bool,
    pub blackbox_only: bool,
    pub whitebox_only: bool,
    pub layers: Option<Vec<String>>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub cookie: Option<String>,
    pub login_url: Option<String>,
    pub no_auth: bool,
    pub pipeline_testing: bool,
    pub rebuild: bool,
    pub max_retries: u32,
    pub max_agent_iterations: u32,
    pub container_config: crate::config::ContainerConfig,
}

impl PipelineConfig {
    pub fn has_repo(&self) -> bool {
        self.repo_path.exists() && self.repo_path.is_dir()
    }

    pub fn deliverables_dir(&self) -> PathBuf {
        self.output_dir.join(&self.scan_id).join("deliverables")
    }

    pub fn audit_dir(&self) -> PathBuf {
        self.output_dir.join(&self.scan_id).join("audit-logs")
    }
}

#[derive(Debug, Clone, Default)]
pub struct ScanContext {
    pub target: String,
    pub target_url: Option<String>,
    pub open_ports: Vec<u16>,
    pub web_port: Option<u16>,
    pub cookie_string: Option<String>,
    pub cookie_file: Option<PathBuf>,
    pub authenticated: bool,
    pub code_analysis: Option<PathBuf>,
    pub recon_data: Option<PathBuf>,
    pub intensity: Intensity,
    pub extra: HashMap<String, String>,
}

impl ScanContext {
    pub fn new(target: &str, intensity: Intensity) -> Self {
        Self {
            target: target.to_string(),
            target_url: Some(target.to_string()),
            intensity,
            ..Default::default()
        }
    }

    pub fn update_from_outputs(&mut self, raw_outputs: &HashMap<String, String>) {
        for (key, output) in raw_outputs {
            if key.contains("tcp") || key.contains("nmap") {
                self.extract_open_ports(output);
            }
        }
    }

    fn extract_open_ports(&mut self, nmap_output: &str) {
        let port_regex = regex::Regex::new(r"(\d+)/tcp\s+open").unwrap();
        for cap in port_regex.captures_iter(nmap_output) {
            if let Ok(port) = cap[1].parse::<u16>() {
                if !self.open_ports.contains(&port) {
                    self.open_ports.push(port);
                }
            }
        }
        self.open_ports.sort();

        // Detect web port
        let web_ports = [80, 443, 8080, 8443, 3000, 5000, 8000];
        for &p in &web_ports {
            if self.open_ports.contains(&p) {
                self.web_port = Some(p);
                break;
            }
        }
    }

    pub fn has_open_ports(&self) -> bool {
        !self.open_ports.is_empty()
    }
}
