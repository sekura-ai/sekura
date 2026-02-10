use crate::models::finding::Severity;
use crate::pipeline::state::PhaseName;

/// Messages sent from the pipeline to the REPL for real-time display.
#[derive(Debug, Clone)]
pub enum PipelineEvent {
    /// Pipeline execution started
    PipelineStarted {
        scan_id: String,
        target: String,
    },
    /// A new phase has begun
    PhaseStarted {
        phase: PhaseName,
        display_name: String,
    },
    /// A phase completed
    PhaseCompleted {
        phase: PhaseName,
        display_name: String,
    },
    /// An agent started executing
    AgentStarted {
        agent_name: String,
    },
    /// An agent finished successfully
    AgentCompleted {
        agent_name: String,
        duration_ms: u64,
        cost_usd: Option<f64>,
    },
    /// An agent failed
    AgentFailed {
        agent_name: String,
        error: String,
    },
    /// A new finding was discovered
    FindingDiscovered {
        title: String,
        severity: Severity,
        category: String,
    },
    /// A technique/tool is being executed
    TechniqueRunning {
        technique_name: String,
        layer: String,
    },
    /// A technique completed
    TechniqueCompleted {
        technique_name: String,
        findings_count: usize,
    },
    /// Pipeline completed successfully
    PipelineCompleted {
        total_findings: usize,
        total_cost_usd: f64,
        total_duration_ms: u64,
    },
    /// Pipeline failed
    PipelineFailed {
        error: String,
    },
    /// Cost budget warning (at 80%+ utilization)
    CostWarning {
        current_usd: f64,
        max_usd: f64,
    },
    /// Informational log message
    Log {
        message: String,
    },
}
