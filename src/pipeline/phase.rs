use super::state::PhaseName;

pub struct PhaseDefinition {
    pub name: PhaseName,
    pub display_name: &'static str,
    pub description: &'static str,
}

pub static PHASES: &[PhaseDefinition] = &[
    PhaseDefinition {
        name: PhaseName::WhiteboxAnalysis,
        display_name: "White-Box Analysis",
        description: "LLM-driven source code review to identify attack surfaces",
    },
    PhaseDefinition {
        name: PhaseName::Reconnaissance,
        display_name: "Reconnaissance",
        description: "Network scanning and web application discovery",
    },
    PhaseDefinition {
        name: PhaseName::VulnerabilityAnalysis,
        display_name: "Vulnerability Analysis",
        description: "Automated vulnerability detection across five categories",
    },
    PhaseDefinition {
        name: PhaseName::Exploitation,
        display_name: "Exploitation",
        description: "Proof-of-concept exploit development and execution",
    },
    PhaseDefinition {
        name: PhaseName::Reporting,
        display_name: "Reporting",
        description: "Comprehensive security assessment report generation",
    },
];
