use std::sync::LazyLock;
use crate::pipeline::state::PhaseName;
use crate::models::deliverable::DeliverableType;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentName {
    WhiteboxAnalyzer,
    ReconTools,
    ReconBrowser,
    InjectionVuln,
    XssVuln,
    AuthVuln,
    SsrfVuln,
    AuthzVuln,
    InjectionExploit,
    XssExploit,
    AuthExploit,
    SsrfExploit,
    AuthzExploit,
    Report,
}

impl AgentName {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::WhiteboxAnalyzer => "whitebox-analyzer",
            Self::ReconTools => "recon-tools",
            Self::ReconBrowser => "recon-browser",
            Self::InjectionVuln => "injection-vuln",
            Self::XssVuln => "xss-vuln",
            Self::AuthVuln => "auth-vuln",
            Self::SsrfVuln => "ssrf-vuln",
            Self::AuthzVuln => "authz-vuln",
            Self::InjectionExploit => "injection-exploit",
            Self::XssExploit => "xss-exploit",
            Self::AuthExploit => "auth-exploit",
            Self::SsrfExploit => "ssrf-exploit",
            Self::AuthzExploit => "authz-exploit",
            Self::Report => "report",
        }
    }
}

impl std::fmt::Display for AgentName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum AgentType {
    Whitebox,
    ToolRunner,
    BrowserAgent,
    VulnAnalyzer,
    Exploiter,
    Reporter,
}

pub struct AgentDefinition {
    pub name: AgentName,
    pub display_name: &'static str,
    pub phase: PhaseName,
    pub prerequisites: &'static [AgentName],
    pub prompt_file: &'static str,
    pub required_deliverables: &'static [DeliverableType],
    pub agent_type: AgentType,
}

pub static AGENT_REGISTRY: LazyLock<Vec<AgentDefinition>> = LazyLock::new(|| vec![
    AgentDefinition {
        name: AgentName::WhiteboxAnalyzer,
        display_name: "White-box analyzer",
        phase: PhaseName::WhiteboxAnalysis,
        prerequisites: &[],
        prompt_file: "whitebox-analysis",
        required_deliverables: &[DeliverableType::CodeAnalysis],
        agent_type: AgentType::Whitebox,
    },
    AgentDefinition {
        name: AgentName::ReconTools,
        display_name: "Recon tools",
        phase: PhaseName::Reconnaissance,
        prerequisites: &[AgentName::WhiteboxAnalyzer],
        prompt_file: "recon-tools",
        required_deliverables: &[],
        agent_type: AgentType::ToolRunner,
    },
    AgentDefinition {
        name: AgentName::ReconBrowser,
        display_name: "Recon browser",
        phase: PhaseName::Reconnaissance,
        prerequisites: &[AgentName::ReconTools],
        prompt_file: "recon-browser",
        required_deliverables: &[DeliverableType::Recon],
        agent_type: AgentType::BrowserAgent,
    },
    AgentDefinition {
        name: AgentName::InjectionVuln,
        display_name: "Injection vuln agent",
        phase: PhaseName::VulnerabilityAnalysis,
        prerequisites: &[AgentName::ReconBrowser],
        prompt_file: "vuln-injection",
        required_deliverables: &[DeliverableType::InjectionAnalysis, DeliverableType::InjectionQueue],
        agent_type: AgentType::VulnAnalyzer,
    },
    AgentDefinition {
        name: AgentName::XssVuln,
        display_name: "XSS vuln agent",
        phase: PhaseName::VulnerabilityAnalysis,
        prerequisites: &[AgentName::ReconBrowser],
        prompt_file: "vuln-xss",
        required_deliverables: &[DeliverableType::XssAnalysis, DeliverableType::XssQueue],
        agent_type: AgentType::VulnAnalyzer,
    },
    AgentDefinition {
        name: AgentName::AuthVuln,
        display_name: "Auth vuln agent",
        phase: PhaseName::VulnerabilityAnalysis,
        prerequisites: &[AgentName::ReconBrowser],
        prompt_file: "vuln-auth",
        required_deliverables: &[DeliverableType::AuthAnalysis, DeliverableType::AuthQueue],
        agent_type: AgentType::VulnAnalyzer,
    },
    AgentDefinition {
        name: AgentName::SsrfVuln,
        display_name: "SSRF vuln agent",
        phase: PhaseName::VulnerabilityAnalysis,
        prerequisites: &[AgentName::ReconBrowser],
        prompt_file: "vuln-ssrf",
        required_deliverables: &[DeliverableType::SsrfAnalysis, DeliverableType::SsrfQueue],
        agent_type: AgentType::VulnAnalyzer,
    },
    AgentDefinition {
        name: AgentName::AuthzVuln,
        display_name: "Authz vuln agent",
        phase: PhaseName::VulnerabilityAnalysis,
        prerequisites: &[AgentName::ReconBrowser],
        prompt_file: "vuln-authz",
        required_deliverables: &[DeliverableType::AuthzAnalysis, DeliverableType::AuthzQueue],
        agent_type: AgentType::VulnAnalyzer,
    },
    AgentDefinition {
        name: AgentName::InjectionExploit,
        display_name: "Injection exploit agent",
        phase: PhaseName::Exploitation,
        prerequisites: &[AgentName::InjectionVuln],
        prompt_file: "exploit-injection",
        required_deliverables: &[DeliverableType::InjectionEvidence],
        agent_type: AgentType::Exploiter,
    },
    AgentDefinition {
        name: AgentName::XssExploit,
        display_name: "XSS exploit agent",
        phase: PhaseName::Exploitation,
        prerequisites: &[AgentName::XssVuln],
        prompt_file: "exploit-xss",
        required_deliverables: &[DeliverableType::XssEvidence],
        agent_type: AgentType::Exploiter,
    },
    AgentDefinition {
        name: AgentName::AuthExploit,
        display_name: "Auth exploit agent",
        phase: PhaseName::Exploitation,
        prerequisites: &[AgentName::AuthVuln],
        prompt_file: "exploit-auth",
        required_deliverables: &[DeliverableType::AuthEvidence],
        agent_type: AgentType::Exploiter,
    },
    AgentDefinition {
        name: AgentName::SsrfExploit,
        display_name: "SSRF exploit agent",
        phase: PhaseName::Exploitation,
        prerequisites: &[AgentName::SsrfVuln],
        prompt_file: "exploit-ssrf",
        required_deliverables: &[DeliverableType::SsrfEvidence],
        agent_type: AgentType::Exploiter,
    },
    AgentDefinition {
        name: AgentName::AuthzExploit,
        display_name: "Authz exploit agent",
        phase: PhaseName::Exploitation,
        prerequisites: &[AgentName::AuthzVuln],
        prompt_file: "exploit-authz",
        required_deliverables: &[DeliverableType::AuthzEvidence],
        agent_type: AgentType::Exploiter,
    },
    AgentDefinition {
        name: AgentName::Report,
        display_name: "Report agent",
        phase: PhaseName::Reporting,
        prerequisites: &[
            AgentName::InjectionExploit, AgentName::XssExploit,
            AgentName::AuthExploit, AgentName::SsrfExploit, AgentName::AuthzExploit,
        ],
        prompt_file: "report-executive",
        required_deliverables: &[DeliverableType::FinalReport],
        agent_type: AgentType::Reporter,
    },
]);

pub fn vuln_agents() -> &'static [AgentName] {
    &[AgentName::InjectionVuln, AgentName::XssVuln, AgentName::AuthVuln,
      AgentName::SsrfVuln, AgentName::AuthzVuln]
}

pub fn exploit_agents() -> &'static [AgentName] {
    &[AgentName::InjectionExploit, AgentName::XssExploit, AgentName::AuthExploit,
      AgentName::SsrfExploit, AgentName::AuthzExploit]
}
