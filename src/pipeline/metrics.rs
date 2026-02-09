use std::collections::HashMap;
use super::state::{AgentMetrics, PipelineSummary};

pub fn compute_summary(
    agent_metrics: &HashMap<String, AgentMetrics>,
    total_findings: usize,
    finding_counts: HashMap<String, usize>,
    phases_completed: usize,
) -> PipelineSummary {
    let total_cost_usd: f64 = agent_metrics.values()
        .filter_map(|m| m.cost_usd)
        .sum();

    let total_duration_ms: u64 = agent_metrics.values()
        .map(|m| m.duration_ms)
        .sum();

    PipelineSummary {
        total_cost_usd,
        total_duration_ms,
        total_findings,
        finding_counts,
        agent_count: agent_metrics.len(),
        phases_completed,
    }
}
