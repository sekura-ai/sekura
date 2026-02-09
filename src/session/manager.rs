use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::Utc;
use crate::agents::registry::{AgentName, AGENT_REGISTRY};
use crate::pipeline::state::AgentMetrics;
use super::state::{AgentState, AgentStatus};

pub struct SessionManager {
    agent_states: Arc<RwLock<HashMap<AgentName, AgentState>>>,
}

pub struct SessionProgress {
    pub completed: usize,
    pub running: usize,
    pub failed: usize,
    pub total: usize,
}

impl SessionManager {
    pub fn new() -> Self {
        let mut states = HashMap::new();
        for def in AGENT_REGISTRY.iter() {
            states.insert(def.name, AgentState {
                name: def.name,
                status: AgentStatus::Pending,
                started_at: None,
                completed_at: None,
                attempt: 0,
                metrics: None,
                error: None,
            });
        }
        Self {
            agent_states: Arc::new(RwLock::new(states)),
        }
    }

    pub async fn mark_running(&self, name: AgentName) {
        let mut states = self.agent_states.write().await;
        if let Some(state) = states.get_mut(&name) {
            state.status = AgentStatus::Running;
            state.started_at = Some(Utc::now());
            state.attempt += 1;
        }
    }

    pub async fn mark_completed(&self, name: AgentName, metrics: AgentMetrics) {
        let mut states = self.agent_states.write().await;
        if let Some(state) = states.get_mut(&name) {
            state.status = AgentStatus::Completed;
            state.completed_at = Some(Utc::now());
            state.metrics = Some(metrics);
        }
    }

    pub async fn mark_failed(&self, name: AgentName, error: String) {
        let mut states = self.agent_states.write().await;
        if let Some(state) = states.get_mut(&name) {
            state.status = AgentStatus::Failed;
            state.completed_at = Some(Utc::now());
            state.error = Some(error);
        }
    }

    pub async fn mark_skipped(&self, name: AgentName) {
        let mut states = self.agent_states.write().await;
        if let Some(state) = states.get_mut(&name) {
            state.status = AgentStatus::Skipped;
        }
    }

    pub async fn prerequisites_met(&self, name: AgentName) -> bool {
        let def = AGENT_REGISTRY.iter().find(|d| d.name == name);
        let def = match def {
            Some(d) => d,
            None => return false,
        };

        let states = self.agent_states.read().await;
        def.prerequisites.iter().all(|prereq| {
            states.get(prereq)
                .map(|s| s.status == AgentStatus::Completed)
                .unwrap_or(false)
        })
    }

    pub async fn get_progress(&self) -> SessionProgress {
        let states = self.agent_states.read().await;
        SessionProgress {
            completed: states.values().filter(|s| s.status == AgentStatus::Completed).count(),
            running: states.values().filter(|s| s.status == AgentStatus::Running).count(),
            failed: states.values().filter(|s| s.status == AgentStatus::Failed).count(),
            total: states.len(),
        }
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}
