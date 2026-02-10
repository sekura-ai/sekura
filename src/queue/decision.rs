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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vuln_type_as_str() {
        assert_eq!(VulnType::Injection.as_str(), "injection");
        assert_eq!(VulnType::Xss.as_str(), "xss");
        assert_eq!(VulnType::Auth.as_str(), "auth");
        assert_eq!(VulnType::Ssrf.as_str(), "ssrf");
        assert_eq!(VulnType::Authz.as_str(), "authz");
    }

    #[test]
    fn test_analysis_filename() {
        assert_eq!(VulnType::Injection.analysis_filename(), "injection_analysis_deliverable.md");
        assert_eq!(VulnType::Xss.analysis_filename(), "xss_analysis_deliverable.md");
    }

    #[test]
    fn test_queue_filename() {
        assert_eq!(VulnType::Auth.queue_filename(), "auth_exploitation_queue.json");
    }

    #[test]
    fn test_evidence_filename() {
        assert_eq!(VulnType::Ssrf.evidence_filename(), "ssrf_exploitation_evidence.md");
    }
}
