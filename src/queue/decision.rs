use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VulnType {
    Injection,
    Xss,
    Auth,
    Ssrf,
    Authz,
}

impl VulnType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Injection => "injection",
            Self::Xss => "xss",
            Self::Auth => "auth",
            Self::Ssrf => "ssrf",
            Self::Authz => "authz",
        }
    }

    pub fn analysis_filename(&self) -> String {
        format!("{}_analysis_deliverable.md", self.as_str())
    }

    pub fn queue_filename(&self) -> String {
        format!("{}_exploitation_queue.json", self.as_str())
    }

    pub fn evidence_filename(&self) -> String {
        format!("{}_exploitation_evidence.md", self.as_str())
    }
}

pub struct ExploitationDecision {
    pub should_exploit: bool,
    pub vulnerability_count: usize,
    pub vuln_type: VulnType,
}
