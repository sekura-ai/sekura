use chrono::Utc;
use crate::errors::SekuraError;
use crate::models::finding::{Finding, Severity, VulnCategory, FindingSource};
use crate::models::verdict::Verdict;
use super::Database;

impl Database {
    pub fn insert_finding(&self, scan_id: &str, finding: &Finding) -> Result<(), SekuraError> {
        let conn = self.conn.lock().unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO findings (id, scan_id, title, severity, category, description, evidence, recommendation, tool, technique, source, verdict, proof_of_exploit, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            rusqlite::params![
                id,
                scan_id,
                finding.title,
                serde_json::to_value(&finding.severity).unwrap().as_str().unwrap_or("info"),
                serde_json::to_value(&finding.category).unwrap().as_str().unwrap_or("INJECTION"),
                finding.description,
                finding.evidence,
                finding.recommendation,
                finding.tool,
                finding.technique,
                serde_json::to_value(&finding.source).unwrap().as_str().unwrap_or("blackbox"),
                finding.verdict.as_ref().map(|v| serde_json::to_value(v).unwrap().as_str().unwrap_or("").to_string()),
                finding.proof_of_exploit,
                Utc::now().to_rfc3339(),
            ],
        ).map_err(|e| SekuraError::Database(format!("Failed to insert finding: {}", e)))?;
        Ok(())
    }

    pub fn get_findings(&self, scan_id: &str) -> Result<Vec<Finding>, SekuraError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT title, severity, category, description, evidence, recommendation, tool, technique, source, verdict, proof_of_exploit FROM findings WHERE scan_id = ?1 ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END"
        ).map_err(|e| SekuraError::Database(format!("Query failed: {}", e)))?;

        let rows = stmt.query_map(rusqlite::params![scan_id], |row: &rusqlite::Row| {
            let severity_str: String = row.get(1)?;
            let category_str: String = row.get(2)?;
            let source_str: String = row.get(8)?;
            let verdict_str: Option<String> = row.get(9)?;

            let severity: Severity = serde_json::from_value(serde_json::Value::String(severity_str))
                .unwrap_or(Severity::Info);
            let category: VulnCategory = serde_json::from_value(serde_json::Value::String(category_str))
                .unwrap_or(VulnCategory::Infrastructure);
            let source: FindingSource = serde_json::from_value(serde_json::Value::String(source_str))
                .unwrap_or(FindingSource::Blackbox);
            let verdict: Option<Verdict> = verdict_str.and_then(|v| {
                serde_json::from_value(serde_json::Value::String(v)).ok()
            });

            Ok(Finding {
                title: row.get(0)?,
                severity,
                category,
                description: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
                evidence: row.get::<_, Option<String>>(4)?.unwrap_or_default(),
                recommendation: row.get::<_, Option<String>>(5)?.unwrap_or_default(),
                tool: row.get::<_, Option<String>>(6)?.unwrap_or_default(),
                technique: row.get::<_, Option<String>>(7)?.unwrap_or_default(),
                source,
                verdict,
                proof_of_exploit: row.get(10)?,
                cwe_id: None,
                cvss_score: None,
                cvss_vector: None,
            })
        }).map_err(|e| SekuraError::Database(format!("Query error: {}", e)))?;

        let mut findings = Vec::new();
        for row in rows {
            findings.push(row.map_err(|e| SekuraError::Database(format!("Row error: {}", e)))?);
        }
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::finding::{Finding, Severity, VulnCategory, FindingSource};
    use crate::models::verdict::Verdict;

    fn make_finding(title: &str, severity: Severity) -> Finding {
        Finding {
            title: title.to_string(),
            severity,
            category: VulnCategory::Injection,
            description: "Test description".to_string(),
            evidence: "Test evidence".to_string(),
            recommendation: "Test recommendation".to_string(),
            tool: "sqlmap".to_string(),
            technique: "sql-injection-scan".to_string(),
            source: FindingSource::Blackbox,
            verdict: Some(Verdict::Exploited),
            proof_of_exploit: Some("curl http://example.com/?id=1'".to_string()),
            cwe_id: Some("CWE-89".to_string()),
            cvss_score: Some(9.8),
            cvss_vector: None,
        }
    }

    #[test]
    fn test_db_insert_and_get_findings() {
        let db = Database::in_memory().unwrap();
        db.create_scan("scan-1", "http://example.com", None, "standard", "anthropic", None, None, None).unwrap();

        let finding = make_finding("SQLi in /api/users", Severity::Critical);
        db.insert_finding("scan-1", &finding).unwrap();

        let results = db.get_findings("scan-1").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].title, "SQLi in /api/users");
        assert_eq!(results[0].severity, Severity::Critical);
        assert_eq!(results[0].category, VulnCategory::Injection);
        assert_eq!(results[0].tool, "sqlmap");
        assert_eq!(results[0].verdict, Some(Verdict::Exploited));
    }

    #[test]
    fn test_db_get_findings_empty_scan() {
        let db = Database::in_memory().unwrap();
        db.create_scan("scan-empty", "http://example.com", None, "standard", "anthropic", None, None, None).unwrap();

        let results = db.get_findings("scan-empty").unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_db_findings_ordered_by_severity() {
        let db = Database::in_memory().unwrap();
        db.create_scan("scan-2", "http://example.com", None, "standard", "anthropic", None, None, None).unwrap();

        db.insert_finding("scan-2", &make_finding("Low issue", Severity::Low)).unwrap();
        db.insert_finding("scan-2", &make_finding("Critical issue", Severity::Critical)).unwrap();
        db.insert_finding("scan-2", &make_finding("High issue", Severity::High)).unwrap();

        let results = db.get_findings("scan-2").unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].severity, Severity::Critical);
        assert_eq!(results[1].severity, Severity::High);
        assert_eq!(results[2].severity, Severity::Low);
    }

    #[test]
    fn test_db_findings_cascade_delete() {
        let db = Database::in_memory().unwrap();
        // Enable foreign keys for in-memory DB
        {
            let conn = db.conn.lock().unwrap();
            conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        }
        db.create_scan("scan-3", "http://example.com", None, "standard", "anthropic", None, None, None).unwrap();
        db.insert_finding("scan-3", &make_finding("Test finding", Severity::High)).unwrap();

        assert_eq!(db.get_findings("scan-3").unwrap().len(), 1);
        db.delete_scan("scan-3").unwrap();
        assert_eq!(db.get_findings("scan-3").unwrap().len(), 0);
    }
}
