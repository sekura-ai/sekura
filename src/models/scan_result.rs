use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use super::finding::{Finding, Severity};
use crate::pipeline::state::PhaseName;

/// The result produced by a single agent during a scan phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Name of the agent that produced this result.
    pub agent_name: String,
    /// Pipeline phase this result belongs to.
    pub phase: PhaseName,
    /// Security findings discovered by the agent.
    pub findings: Vec<Finding>,
    /// Raw tool outputs keyed by tool/command name.
    pub raw_outputs: HashMap<String, String>,
    /// Wall-clock duration of the agent run in milliseconds.
    pub duration_ms: u64,
    /// Number of techniques executed by the agent.
    pub techniques_run: usize,
    /// Estimated LLM API cost in USD, if tracked.
    pub cost_usd: Option<f64>,
    /// Number of LLM conversation turns used, if tracked.
    pub turns: Option<u32>,
    /// LLM model identifier used, if applicable.
    pub model: Option<String>,
}

impl ScanResult {
    /// Returns a map of severity level to the count of findings at that severity.
    pub fn finding_counts(&self) -> HashMap<Severity, usize> {
        let mut counts = HashMap::new();
        for finding in &self.findings {
            *counts.entry(finding.severity.clone()).or_insert(0) += 1;
        }
        counts
    }

    /// Returns the total number of findings in this result.
    pub fn total_findings(&self) -> usize {
        self.findings.len()
    }
}
