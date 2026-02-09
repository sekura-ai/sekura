use serde::{Deserialize, Serialize};
use super::finding::Finding;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateReport {
    pub findings: Vec<Finding>,
    pub executive_summary: String,
    pub total_cost_usd: f64,
    pub total_duration_ms: u64,
}
