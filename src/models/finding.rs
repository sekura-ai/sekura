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
    /// CWE identifier (e.g. "CWE-89" for SQL injection).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwe_id: Option<String>,
    /// CVSS v3.1 base score (0.0 - 10.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss_score: Option<f64>,
    /// CVSS v3.1 vector string (e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss_vector: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_rank_ordering() {
        assert!(Severity::Critical.rank() < Severity::High.rank());
        assert!(Severity::High.rank() < Severity::Medium.rank());
        assert!(Severity::Medium.rank() < Severity::Low.rank());
        assert!(Severity::Low.rank() < Severity::Info.rank());
    }

    #[test]
    fn test_severity_serialization() {
        let json = serde_json::to_string(&Severity::Critical).unwrap();
        assert_eq!(json, "\"critical\"");
        let parsed: Severity = serde_json::from_str("\"high\"").unwrap();
        assert_eq!(parsed, Severity::High);
    }

    #[test]
    fn test_vuln_category_serialization() {
        let json = serde_json::to_string(&VulnCategory::Injection).unwrap();
        assert_eq!(json, "\"INJECTION\"");
        let parsed: VulnCategory = serde_json::from_str("\"XSS\"").unwrap();
        assert_eq!(parsed, VulnCategory::Xss);
    }

    #[test]
    fn test_finding_source_serialization() {
        let json = serde_json::to_string(&FindingSource::Whitebox).unwrap();
        assert_eq!(json, "\"whitebox\"");
    }

    #[test]
    fn test_finding_roundtrip() {
        let finding = Finding {
            title: "SQLi in /api/users".to_string(),
            severity: Severity::Critical,
            category: VulnCategory::Injection,
            description: "SQL injection found".to_string(),
            evidence: "' OR 1=1 --".to_string(),
            recommendation: "Use parameterized queries".to_string(),
            tool: "sqlmap".to_string(),
            technique: "sql-injection-scan".to_string(),
            source: FindingSource::Blackbox,
            verdict: None,
            proof_of_exploit: None,
            cwe_id: Some("CWE-89".to_string()),
            cvss_score: Some(9.8),
            cvss_vector: None,
        };
        let json = serde_json::to_string(&finding).unwrap();
        let parsed: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.title, "SQLi in /api/users");
        assert_eq!(parsed.severity, Severity::Critical);
    }
}
