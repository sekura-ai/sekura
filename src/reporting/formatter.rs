use crate::models::finding::Finding;

pub fn format_finding_markdown(finding: &Finding) -> String {
    format!(
        "### {}\n\n**Severity:** {:?}\n**Category:** {:?}\n\n{}\n\n**Evidence:**\n```\n{}\n```\n\n**Recommendation:** {}\n",
        finding.title,
        finding.severity,
        finding.category,
        finding.description,
        finding.evidence,
        finding.recommendation,
    )
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
