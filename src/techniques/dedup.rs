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
