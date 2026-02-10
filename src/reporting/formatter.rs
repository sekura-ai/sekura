use crate::models::finding::{Finding, Severity};

pub fn format_finding_markdown(finding: &Finding) -> String {
    let mut md = format!(
        "### {}\n\n**Severity:** {:?}",
        finding.title,
        finding.severity,
    );

    if let Some(cvss) = finding.cvss_score {
        md.push_str(&format!(" (CVSS {:.1})", cvss));
    }
    md.push('\n');

    md.push_str(&format!("**Category:** {:?}\n", finding.category));

    if let Some(cwe) = &finding.cwe_id {
        md.push_str(&format!("**CWE:** {}\n", cwe));
    }

    md.push_str(&format!(
        "\n{}\n\n**Evidence:**\n```\n{}\n```\n\n**Recommendation:** {}\n",
        finding.description,
        finding.evidence,
        finding.recommendation,
    ));

    if let Some(verdict) = &finding.verdict {
        md.push_str(&format!("\n**Verdict:** {:?}\n", verdict));
    }

    if let Some(proof) = &finding.proof_of_exploit {
        md.push_str(&format!("\n**Proof of Exploit:**\n```\n{}\n```\n", proof));
    }

    md
}

pub fn format_executive_summary(findings: &[Finding]) -> String {
    let critical = findings.iter().filter(|f| f.severity.rank() == 0).count();
    let high = findings.iter().filter(|f| f.severity.rank() == 1).count();
    let medium = findings.iter().filter(|f| f.severity.rank() == 2).count();
    let low = findings.iter().filter(|f| f.severity.rank() == 3).count();
    let info = findings.iter().filter(|f| f.severity.rank() == 4).count();

    format!(
        "## Executive Summary\n\n| Severity | Count |\n|---|---|\n| Critical | {} |\n| High | {} |\n| Medium | {} |\n| Low | {} |\n| Info | {} |\n| **Total** | **{}** |\n",
        critical, high, medium, low, info, findings.len()
    )
}

/// Generate an HTML report from findings.
pub fn format_html_report(findings: &[Finding], target: &str, scan_id: &str) -> String {
    let critical = findings.iter().filter(|f| f.severity.rank() == 0).count();
    let high = findings.iter().filter(|f| f.severity.rank() == 1).count();
    let medium = findings.iter().filter(|f| f.severity.rank() == 2).count();
    let low = findings.iter().filter(|f| f.severity.rank() == 3).count();
    let info = findings.iter().filter(|f| f.severity.rank() == 4).count();

    let mut html = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Security Assessment - {target}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #0a0e17; color: #e0e0e0; }}
.container {{ max-width: 1000px; margin: 0 auto; }}
h1 {{ color: #00d4ff; border-bottom: 2px solid #1a2332; padding-bottom: 12px; }}
h2 {{ color: #8899aa; }}
h3 {{ color: #e0e0e0; }}
.summary-table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
.summary-table th, .summary-table td {{ padding: 10px 16px; text-align: left; border: 1px solid #1a2332; }}
.summary-table th {{ background: #1a2332; color: #00d4ff; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }}
.badge-critical {{ background: #dc3545; color: white; }}
.badge-high {{ background: #fd7e14; color: white; }}
.badge-medium {{ background: #ffc107; color: black; }}
.badge-low {{ background: #17a2b8; color: white; }}
.badge-info {{ background: #6c757d; color: white; }}
.finding {{ background: #111827; border: 1px solid #1a2332; border-radius: 8px; padding: 20px; margin: 16px 0; }}
.evidence {{ background: #0d1117; padding: 12px; border-radius: 4px; font-family: monospace; white-space: pre-wrap; overflow-x: auto; color: #7ee787; }}
.meta {{ color: #8899aa; font-size: 14px; }}
</style>
</head>
<body>
<div class="container">
<h1>Security Assessment Report</h1>
<p class="meta">Target: {target} | Scan: {scan_id}</p>

<h2>Executive Summary</h2>
<table class="summary-table">
<tr><th>Severity</th><th>Count</th></tr>
<tr><td><span class="badge badge-critical">CRITICAL</span></td><td>{critical}</td></tr>
<tr><td><span class="badge badge-high">HIGH</span></td><td>{high}</td></tr>
<tr><td><span class="badge badge-medium">MEDIUM</span></td><td>{medium}</td></tr>
<tr><td><span class="badge badge-low">LOW</span></td><td>{low}</td></tr>
<tr><td><span class="badge badge-info">INFO</span></td><td>{info}</td></tr>
<tr><td><strong>Total</strong></td><td><strong>{total}</strong></td></tr>
</table>

<h2>Findings</h2>
"#, target = html_escape(target), scan_id = html_escape(scan_id),
        critical = critical, high = high, medium = medium, low = low, info = info,
        total = findings.len());

    for finding in findings {
        let badge_class = match finding.severity {
            Severity::Critical => "badge-critical",
            Severity::High => "badge-high",
            Severity::Medium => "badge-medium",
            Severity::Low => "badge-low",
            Severity::Info => "badge-info",
        };

        html.push_str(&format!(
            r#"<div class="finding">
<h3>{title}</h3>
<p><span class="badge {badge_class}">{severity:?}</span>"#,
            title = html_escape(&finding.title),
            badge_class = badge_class,
            severity = finding.severity,
        ));

        if let Some(cvss) = finding.cvss_score {
            html.push_str(&format!(" CVSS: {:.1}", cvss));
        }
        if let Some(cwe) = &finding.cwe_id {
            html.push_str(&format!(" | {}", html_escape(cwe)));
        }

        html.push_str(&format!(
            r#" | {:?}</p>
<p>{}</p>
<h4>Evidence</h4>
<div class="evidence">{}</div>
<h4>Recommendation</h4>
<p>{}</p>
</div>
"#,
            finding.category,
            html_escape(&finding.description),
            html_escape(&finding.evidence),
            html_escape(&finding.recommendation),
        ));
    }

    html.push_str("</div>\n</body>\n</html>");
    html
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::finding::{VulnCategory, FindingSource};

    fn make_finding(title: &str, severity: Severity) -> Finding {
        Finding {
            title: title.to_string(),
            severity,
            category: VulnCategory::Injection,
            description: "Test description".to_string(),
            evidence: "Test evidence".to_string(),
            recommendation: "Fix it".to_string(),
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
    fn test_format_finding_markdown_contains_title() {
        let f = make_finding("SQL Injection", Severity::Critical);
        let md = format_finding_markdown(&f);
        assert!(md.contains("### SQL Injection"));
        assert!(md.contains("Critical"));
        assert!(md.contains("Test evidence"));
        assert!(md.contains("Fix it"));
    }

    #[test]
    fn test_format_finding_with_cwe_cvss() {
        let mut f = make_finding("SQL Injection", Severity::Critical);
        f.cwe_id = Some("CWE-89".to_string());
        f.cvss_score = Some(9.8);
        let md = format_finding_markdown(&f);
        assert!(md.contains("CWE-89"));
        assert!(md.contains("CVSS 9.8"));
    }

    #[test]
    fn test_executive_summary_counts() {
        let findings = vec![
            make_finding("f1", Severity::Critical),
            make_finding("f2", Severity::Critical),
            make_finding("f3", Severity::High),
            make_finding("f4", Severity::Medium),
            make_finding("f5", Severity::Info),
        ];
        let summary = format_executive_summary(&findings);
        assert!(summary.contains("| Critical | 2 |"));
        assert!(summary.contains("| High | 1 |"));
        assert!(summary.contains("| Medium | 1 |"));
        assert!(summary.contains("| Low | 0 |"));
        assert!(summary.contains("| Info | 1 |"));
        assert!(summary.contains("**5**"));
    }

    #[test]
    fn test_executive_summary_empty() {
        let summary = format_executive_summary(&[]);
        assert!(summary.contains("**0**"));
    }

    #[test]
    fn test_html_report_structure() {
        let findings = vec![
            make_finding("XSS in /search", Severity::High),
        ];
        let html = format_html_report(&findings, "http://target.com", "scan-001");
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("http://target.com"));
        assert!(html.contains("XSS in /search"));
        assert!(html.contains("badge-high"));
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<script>alert(1)</script>"), "&lt;script&gt;alert(1)&lt;/script&gt;");
    }
}
