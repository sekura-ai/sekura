use chrono::{DateTime, Utc};
use crate::pipeline::state::AgentMetrics;
use crate::agents::registry::AgentName;

#[derive(Debug, Clone)]
pub struct AgentState {
    pub name: AgentName,
    pub status: AgentStatus,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub attempt: u32,
    pub metrics: Option<AgentMetrics>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AgentStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Skipped,
    RolledBack,
}
