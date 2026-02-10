use std::collections::HashMap;
use std::collections::hash_map::Entry;
use crate::models::finding::Finding;

pub fn deduplicate_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut seen: HashMap<String, Finding> = HashMap::new();
    for finding in findings {
        let key = normalize_title(&finding.title);
        match seen.entry(key) {
            Entry::Vacant(e) => { e.insert(finding); }
            Entry::Occupied(mut e) => {
                // Keep higher severity (lower rank number)
                if finding.severity.rank() < e.get().severity.rank() {
                    e.insert(finding);
                }
            }
        }
    }
    seen.into_values().collect()
}

fn normalize_title(title: &str) -> String {
    title.to_lowercase()
        .trim()
        .replace(|c: char| !c.is_alphanumeric() && c != ' ', "")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::finding::{Finding, Severity, VulnCategory, FindingSource};

    fn make_finding(title: &str, severity: Severity) -> Finding {
        Finding {
            title: title.to_string(),
            severity,
            category: VulnCategory::Injection,
            description: "test".to_string(),
            evidence: "test".to_string(),
            recommendation: "test".to_string(),
            tool: "test".to_string(),
            technique: "test".to_string(),
            source: FindingSource::Blackbox,
            verdict: None,
            proof_of_exploit: None,
            cwe_id: None,
            cvss_score: None,
            cvss_vector: None,
        }
    }

    #[test]
    fn test_dedup_keeps_higher_severity() {
        let findings = vec![
            make_finding("SQL Injection in /login", Severity::Medium),
            make_finding("SQL Injection in /login", Severity::Critical),
        ];
        let deduped = deduplicate_findings(findings);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].severity, Severity::Critical);
    }

    #[test]
    fn test_dedup_normalizes_titles() {
        let findings = vec![
            make_finding("  SQL Injection - /login  ", Severity::High),
            make_finding("sql injection /login", Severity::Medium),
        ];
        let deduped = deduplicate_findings(findings);
        assert_eq!(deduped.len(), 1);
    }

    #[test]
    fn test_dedup_keeps_distinct_findings() {
        let findings = vec![
            make_finding("SQL Injection in /login", Severity::High),
            make_finding("XSS in /search", Severity::Medium),
        ];
        let deduped = deduplicate_findings(findings);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_dedup_empty_input() {
        let findings: Vec<Finding> = vec![];
        let deduped = deduplicate_findings(findings);
        assert!(deduped.is_empty());
    }

    #[test]
    fn test_normalize_title() {
        assert_eq!(normalize_title("  SQL Injection - /login  "), "sql injection login");
        assert_eq!(normalize_title("XSS (reflected)"), "xss reflected");
    }
}
