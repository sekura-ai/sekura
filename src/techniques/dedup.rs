use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::collections::HashSet;
use crate::models::finding::Finding;

const STOP_WORDS: &[&str] = &[
    "the", "a", "an", "for", "in", "at", "to", "of", "is", "on",
    "detected", "found", "enabled", "missing", "exposed", "page",
];

pub fn deduplicate_findings(findings: Vec<Finding>) -> Vec<Finding> {
    // Pass 1: exact dedup by (category, path, normalized title)
    let mut seen: HashMap<String, Finding> = HashMap::new();
    for finding in findings {
        let key = dedup_key(&finding);
        match seen.entry(key) {
            Entry::Vacant(e) => { e.insert(finding); }
            Entry::Occupied(mut e) => {
                merge_findings(e.get_mut(), &finding);
            }
        }
    }

    // Pass 2: fuzzy dedup to collapse same-meaning different-wording titles
    let mut fuzzy_map: HashMap<String, Finding> = HashMap::new();
    for finding in seen.into_values() {
        let fkey = fuzzy_key(&finding);
        match fuzzy_map.entry(fkey) {
            Entry::Vacant(e) => { e.insert(finding); }
            Entry::Occupied(mut e) => {
                merge_findings(e.get_mut(), &finding);
            }
        }
    }

    fuzzy_map.into_values().collect()
}

fn dedup_key(finding: &Finding) -> String {
    let title = normalize_title(&finding.title);
    let path = extract_target_path(&finding.evidence);
    let category = format!("{:?}", finding.category).to_lowercase();
    format!("{}|{}|{}", category, path, title)
}

fn fuzzy_key(finding: &Finding) -> String {
    let path = extract_target_path(&finding.evidence);
    let category = format!("{:?}", finding.category).to_lowercase();
    let stop: HashSet<&str> = STOP_WORDS.iter().copied().collect();
    let normalized = normalize_title(&finding.title);
    let mut words: Vec<&str> = normalized
        .split_whitespace()
        .filter(|w| !stop.contains(w))
        .collect();
    words.sort();
    format!("{}|{}|{}", category, path, words.join(" "))
}

fn extract_target_path(evidence: &str) -> String {
    let path_re = regex::Regex::new(r"(/[a-zA-Z0-9._\-]+(?:/[a-zA-Z0-9._\-]*)*)").unwrap();
    if let Some(cap) = path_re.find(evidence) {
        cap.as_str().to_lowercase()
    } else {
        "global".to_string()
    }
}

fn merge_findings(existing: &mut Finding, incoming: &Finding) {
    // Keep higher severity (lower rank number)
    if incoming.severity.rank() < existing.severity.rank() {
        let old_tool = existing.tool.clone();
        let old_evidence = existing.evidence.clone();
        *existing = incoming.clone();
        // Merge tool names from old into new
        merge_tool_names(&mut existing.tool, &old_tool);
        // Keep longer evidence
        if old_evidence.len() > existing.evidence.len() {
            existing.evidence = old_evidence;
        }
    } else {
        // Merge tool names from incoming into existing
        merge_tool_names(&mut existing.tool, &incoming.tool);
        // Keep longer evidence
        if incoming.evidence.len() > existing.evidence.len() {
            existing.evidence = incoming.evidence.clone();
        }
    }
}

fn merge_tool_names(existing: &mut String, incoming: &str) {
    let current_tools: HashSet<String> = existing.split(", ").map(String::from).collect();
    for tool in incoming.split(", ") {
        if !current_tools.contains(tool) {
            existing.push_str(", ");
            existing.push_str(tool);
        }
    }
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

    fn make_finding_full(
        title: &str,
        severity: Severity,
        category: VulnCategory,
        evidence: &str,
        tool: &str,
    ) -> Finding {
        Finding {
            title: title.to_string(),
            severity,
            category,
            description: "test".to_string(),
            evidence: evidence.to_string(),
            recommendation: "test".to_string(),
            tool: tool.to_string(),
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

    #[test]
    fn test_extract_target_path() {
        assert_eq!(extract_target_path("Found at /config/ on the server"), "/config/");
        assert_eq!(extract_target_path("Exposed /.htpasswd file"), "/.htpasswd");
        assert_eq!(extract_target_path("GET /server-status returned 200"), "/server-status");
        assert_eq!(extract_target_path("No path here"), "global");
    }

    #[test]
    fn test_fuzzy_dedup_collapses_same_meaning() {
        // "Exposed .gitignore File" vs "Exposed Git Ignore File (.gitignore)"
        // After normalize: "exposed gitignore file" vs "exposed git ignore file gitignore"
        // After stop-word removal + sort: "file gitignore" vs "file git gitignore ignore"
        // These differ, but let's test with a more realistic case:
        let findings = vec![
            make_finding_full(
                "Exposed .gitignore File",
                Severity::Low,
                VulnCategory::Infrastructure,
                "Found /.gitignore exposed",
                "nikto",
            ),
            make_finding_full(
                "Exposed .gitignore File Detected",
                Severity::Info,
                VulnCategory::Infrastructure,
                "/.gitignore is accessible",
                "ffuf",
            ),
        ];
        let deduped = deduplicate_findings(findings);
        // Both normalize to same fuzzy key since "detected" is a stop word
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].severity, Severity::Low);
        assert!(deduped[0].tool.contains("nikto"));
        assert!(deduped[0].tool.contains("ffuf"));
    }

    #[test]
    fn test_dedup_preserves_distinct_paths() {
        let findings = vec![
            make_finding_full(
                "Directory Listing Enabled",
                Severity::Low,
                VulnCategory::Infrastructure,
                "GET /images/ returned directory listing",
                "nikto",
            ),
            make_finding_full(
                "Directory Listing Enabled",
                Severity::Low,
                VulnCategory::Infrastructure,
                "GET /uploads/ returned directory listing",
                "ffuf",
            ),
        ];
        let deduped = deduplicate_findings(findings);
        // Same title but different paths — should remain distinct
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_merge_aggregates_tools() {
        let findings = vec![
            make_finding_full("SQL Injection", Severity::High, VulnCategory::Injection, "/login POST", "sqlmap"),
            make_finding_full("SQL Injection", Severity::High, VulnCategory::Injection, "/login POST username=admin", "nikto"),
        ];
        let deduped = deduplicate_findings(findings);
        assert_eq!(deduped.len(), 1);
        assert!(deduped[0].tool.contains("sqlmap"));
        assert!(deduped[0].tool.contains("nikto"));
        // Should keep longer evidence
        assert!(deduped[0].evidence.contains("username=admin"));
    }
}
