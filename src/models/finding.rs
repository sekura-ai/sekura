use serde::{Deserialize, Serialize};
use super::verdict::Verdict;

/// Severity level for a security finding, ordered from most to least severe.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    /// Returns a numeric rank where lower values indicate higher severity.
    /// Critical = 0, High = 1, Medium = 2, Low = 3, Info = 4.
    pub fn rank(&self) -> u8 {
        match self {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
            Severity::Info => 4,
        }
    }
}

/// Category of vulnerability identified by the finding.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VulnCategory {
    Injection,
    Xss,
    Auth,
    Ssrf,
    Authz,
    /// Network/transport-level findings
    Infrastructure,
}

/// How the finding was discovered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSource {
    /// Found via source code analysis
    Whitebox,
    /// Found via tool execution
    Blackbox,
    /// Correlated across both whitebox and blackbox
    Combined,
    /// Found or confirmed via browser automation
    BrowserExploit,
}

/// A single security finding produced by an agent during a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub title: String,
    pub severity: Severity,
    pub category: VulnCategory,
    pub description: String,
    pub evidence: String,
    pub recommendation: String,
    /// The tool that produced this finding (e.g. "nmap", "sqlmap", "llm-analysis").
    pub tool: String,
    /// Technique name or agent name that identified this finding.
    pub technique: String,
    /// How this finding was discovered.
    pub source: FindingSource,
    /// Set during exploitation phase to indicate the outcome.
    pub verdict: Option<Verdict>,
    /// Reproduction steps if the vulnerability was exploited.
    pub proof_of_exploit: Option<String>,
}
