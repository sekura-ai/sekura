use std::collections::{HashMap, HashSet};
use std::path::Path;
use serde::Deserialize;
use crate::errors::SekuraError;
use tracing::info;

#[derive(Debug, Deserialize)]
struct WstgMappingFile {
    wstg_version: String,
    mappings: Vec<WstgMapping>,
}

#[derive(Debug, Deserialize)]
struct WstgMapping {
    wstg_id: String,
    wstg_title: String,
    techniques: Vec<String>,
    #[serde(default)]
    coverage: Option<String>,
    #[serde(default)]
    notes: Option<String>,
}

/// Summary of WSTG coverage for a scan.
#[derive(Debug, Clone)]
pub struct WstgCoverage {
    pub wstg_version: String,
    pub total_items: usize,
    pub covered_by_techniques: usize,
    pub covered_by_llm_agents: usize,
    pub uncovered: usize,
    pub technique_coverage_pct: f64,
    pub total_coverage_pct: f64,
    pub covered_items: Vec<WstgCoveredItem>,
    pub uncovered_items: Vec<WstgUncoveredItem>,
}

#[derive(Debug, Clone)]
pub struct WstgCoveredItem {
    pub wstg_id: String,
    pub wstg_title: String,
    pub matched_techniques: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct WstgUncoveredItem {
    pub wstg_id: String,
    pub wstg_title: String,
    pub notes: Option<String>,
}

/// Compute WSTG coverage based on which techniques were executed during a scan.
pub fn compute_wstg_coverage(
    techniques_dir: &Path,
    executed_techniques: &HashSet<String>,
) -> Result<WstgCoverage, SekuraError> {
    let mapping_path = techniques_dir.join("wstg-mapping.yaml");
    if !mapping_path.exists() {
        return Err(SekuraError::Config("wstg-mapping.yaml not found".into()));
    }

    let content = std::fs::read_to_string(&mapping_path)?;
    let mapping_file: WstgMappingFile = serde_yaml::from_str(&content)?;

    let total_items = mapping_file.mappings.len();
    let mut covered_items = Vec::new();
    let mut uncovered_items = Vec::new();
    let mut covered_by_techniques = 0;
    let mut covered_by_llm_agents = 0;

    for mapping in &mapping_file.mappings {
        let matched: Vec<String> = mapping.techniques.iter()
            .filter(|t| executed_techniques.contains(t.as_str()))
            .cloned()
            .collect();

        if !matched.is_empty() {
            covered_by_techniques += 1;
            covered_items.push(WstgCoveredItem {
                wstg_id: mapping.wstg_id.clone(),
                wstg_title: mapping.wstg_title.clone(),
                matched_techniques: matched,
            });
        } else if mapping.coverage.as_deref() == Some("llm-agent") {
            covered_by_llm_agents += 1;
            covered_items.push(WstgCoveredItem {
                wstg_id: mapping.wstg_id.clone(),
                wstg_title: mapping.wstg_title.clone(),
                matched_techniques: vec!["llm-agent".to_string()],
            });
        } else {
            uncovered_items.push(WstgUncoveredItem {
                wstg_id: mapping.wstg_id.clone(),
                wstg_title: mapping.wstg_title.clone(),
                notes: mapping.notes.clone(),
            });
        }
    }

    let total_covered = covered_by_techniques + covered_by_llm_agents;
    let technique_coverage_pct = if total_items > 0 {
        (covered_by_techniques as f64 / total_items as f64) * 100.0
    } else {
        0.0
    };
    let total_coverage_pct = if total_items > 0 {
        (total_covered as f64 / total_items as f64) * 100.0
    } else {
        0.0
    };

    info!(
        total = total_items,
        by_techniques = covered_by_techniques,
        by_llm = covered_by_llm_agents,
        uncovered = uncovered_items.len(),
        coverage_pct = format!("{:.1}%", total_coverage_pct),
        "WSTG coverage computed"
    );

    Ok(WstgCoverage {
        wstg_version: mapping_file.wstg_version,
        total_items,
        covered_by_techniques,
        covered_by_llm_agents,
        uncovered: uncovered_items.len(),
        technique_coverage_pct,
        total_coverage_pct,
        covered_items,
        uncovered_items,
    })
}

/// Format WSTG coverage as a markdown section for inclusion in reports.
pub fn format_wstg_coverage_markdown(coverage: &WstgCoverage) -> String {
    let mut md = String::new();
    md.push_str(&format!("## OWASP WSTG v{} Coverage\n\n", coverage.wstg_version));
    md.push_str(&format!("| Metric | Count |\n|---|---|\n"));
    md.push_str(&format!("| Total WSTG test cases | {} |\n", coverage.total_items));
    md.push_str(&format!("| Covered by tool techniques | {} |\n", coverage.covered_by_techniques));
    md.push_str(&format!("| Covered by LLM agents | {} |\n", coverage.covered_by_llm_agents));
    md.push_str(&format!("| Uncovered | {} |\n", coverage.uncovered));
    md.push_str(&format!("| Tool coverage | {:.1}% |\n", coverage.technique_coverage_pct));
    md.push_str(&format!("| **Total coverage** | **{:.1}%** |\n\n", coverage.total_coverage_pct));

    if !coverage.uncovered_items.is_empty() {
        md.push_str("### Uncovered Test Cases (Roadmap)\n\n");
        for item in &coverage.uncovered_items {
            md.push_str(&format!("- **{}**: {}", item.wstg_id, item.wstg_title));
            if let Some(notes) = &item.notes {
                md.push_str(&format!(" _{}_", notes));
            }
            md.push('\n');
        }
        md.push('\n');
    }

    md
}
