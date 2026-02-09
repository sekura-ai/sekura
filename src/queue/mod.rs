pub mod validator;
pub mod decision;

pub use decision::{VulnType, ExploitationDecision};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitationQueue {
    pub vulnerabilities: Vec<QueueEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueEntry {
    pub id: String,
    pub vulnerability_type: String,
    pub source: String,
    pub path: String,
    pub sink_call: Option<String>,
    pub slot_type: Option<String>,
    pub sanitization_observed: Option<String>,
    pub verdict: String,
    pub confidence: Confidence,
    pub witness_payload: Option<String>,
    pub exploitation_hypothesis: Option<String>,
    pub suggested_exploit_technique: Option<String>,
    pub externally_exploitable: Option<bool>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}
