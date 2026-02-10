use sekura::models::finding::{Finding, FindingSource, Severity, VulnCategory};
use sekura::models::verdict::Verdict;
use std::fs;
use tempfile::TempDir;

fn make_test_findings() -> Vec<Finding> {
    vec![
        Finding {
            title: "SQL Injection in /api/users".to_string(),
            severity: Severity::Critical,
            category: VulnCategory::Injection,
            description: "SQL injection via user ID parameter".to_string(),
            evidence: "Parameter: id=1' OR 1=1--".to_string(),
            recommendation: "Use parameterized queries".to_string(),
            tool: "sqlmap".to_string(),
            technique: "sql-injection-scan".to_string(),
            source: FindingSource::Blackbox,
            verdict: Some(Verdict::Exploited),
            proof_of_exploit: Some("Extracted 10 rows from users table".to_string()),
            cwe_id: Some("CWE-89".to_string()),
            cvss_score: Some(9.8),
            cvss_vector: None,
        },
        Finding {
            title: "XSS in search field".to_string(),
            severity: Severity::High,
            category: VulnCategory::Xss,
            description: "Reflected XSS".to_string(),
            evidence: "<script>alert(1)</script>".to_string(),
            recommendation: "Encode output".to_string(),
            tool: "manual".to_string(),
            technique: "xss-scan".to_string(),
            source: FindingSource::Combined,
            verdict: None,
            proof_of_exploit: None,
            cwe_id: Some("CWE-79".to_string()),
            cvss_score: Some(6.1),
            cvss_vector: None,
        },
    ]
}

fn create_scan_fixture(dir: &TempDir, scan_id: &str) -> std::path::PathBuf {
    let scan_dir = dir.path().join(scan_id);
    let deliverables = scan_dir.join("deliverables");
    fs::create_dir_all(&deliverables).unwrap();

    // Write findings.json
    let findings = make_test_findings();
    let json = serde_json::to_string_pretty(&findings).unwrap();
    fs::write(deliverables.join("findings.json"), &json).unwrap();

    // Write session_metrics.json
    let metrics = serde_json::json!({
        "target": "http://example.com",
        "duration_ms": 120000,
        "cost_usd": 0.15,
        "total_findings": 2
    });
    fs::write(
        deliverables.join("session_metrics.json"),
        serde_json::to_string_pretty(&metrics).unwrap(),
    ).unwrap();

    // Write report files
    fs::write(
        deliverables.join("comprehensive_security_assessment_report.md"),
        "# Security Report\n\nTest content",
    ).unwrap();
    fs::write(deliverables.join("report.html"), "<html><body>Report</body></html>").unwrap();

    scan_dir
}

#[test]
fn test_load_findings_from_disk() {
    let dir = TempDir::new().unwrap();
    let scan_id = "test-scan-001";
    create_scan_fixture(&dir, scan_id);

    let findings_path = dir.path().join(scan_id).join("deliverables").join("findings.json");
    let content = fs::read_to_string(findings_path).unwrap();
    let findings: Vec<Finding> = serde_json::from_str(&content).unwrap();

    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].title, "SQL Injection in /api/users");
    assert_eq!(findings[0].severity, Severity::Critical);
    assert_eq!(findings[1].severity, Severity::High);
}

#[test]
fn test_load_session_metrics() {
    let dir = TempDir::new().unwrap();
    let scan_id = "test-scan-002";
    create_scan_fixture(&dir, scan_id);

    let metrics_path = dir.path().join(scan_id).join("deliverables").join("session_metrics.json");
    let content = fs::read_to_string(metrics_path).unwrap();
    let metrics: serde_json::Value = serde_json::from_str(&content).unwrap();

    assert_eq!(metrics["target"], "http://example.com");
    assert_eq!(metrics["duration_ms"], 120000);
    assert_eq!(metrics["cost_usd"], 0.15);
    assert_eq!(metrics["total_findings"], 2);
}

#[test]
fn test_build_deliverable_list() {
    let dir = TempDir::new().unwrap();
    let scan_id = "test-scan-003";
    create_scan_fixture(&dir, scan_id);

    let deliverables_dir = dir.path().join(scan_id).join("deliverables");

    let expected_files = [
        "findings.json",
        "session_metrics.json",
        "comprehensive_security_assessment_report.md",
        "report.html",
    ];

    for file in &expected_files {
        assert!(
            deliverables_dir.join(file).exists(),
            "Expected deliverable {} to exist",
            file
        );
    }

    // Non-existent file should not exist
    assert!(!deliverables_dir.join("nonexistent.pdf").exists());
}

#[test]
fn test_list_all_scans() {
    let dir = TempDir::new().unwrap();

    // Create multiple scan directories
    for i in 1..=3 {
        create_scan_fixture(&dir, &format!("scan-{:03}", i));
    }

    // List scan directories
    let mut scan_dirs: Vec<String> = fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.ok()?;
            if entry.file_type().ok()?.is_dir() {
                entry.file_name().to_str().map(|s| s.to_string())
            } else {
                None
            }
        })
        .collect();
    scan_dirs.sort();

    assert_eq!(scan_dirs.len(), 3);
    assert_eq!(scan_dirs[0], "scan-001");
    assert_eq!(scan_dirs[2], "scan-003");
}

#[test]
fn test_findings_roundtrip_serialization() {
    let findings = make_test_findings();
    let json = serde_json::to_string(&findings).unwrap();
    let parsed: Vec<Finding> = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.len(), findings.len());
    assert_eq!(parsed[0].title, findings[0].title);
    assert_eq!(parsed[0].severity, findings[0].severity);
    assert_eq!(parsed[0].verdict, findings[0].verdict);
    assert_eq!(parsed[1].cwe_id, findings[1].cwe_id);
}
