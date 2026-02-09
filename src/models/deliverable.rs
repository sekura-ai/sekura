use serde::{Deserialize, Serialize};

/// Types of deliverable artifacts produced by agents during a scan.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DeliverableType {
    CodeAnalysis,
    Recon,
    InjectionAnalysis,
    InjectionQueue,
    InjectionEvidence,
    XssAnalysis,
    XssQueue,
    XssEvidence,
    AuthAnalysis,
    AuthQueue,
    AuthEvidence,
    AuthzAnalysis,
    AuthzQueue,
    AuthzEvidence,
    SsrfAnalysis,
    SsrfQueue,
    SsrfEvidence,
    FinalReport,
}

impl DeliverableType {
    /// Returns the canonical filename for this deliverable type.
    pub fn filename(&self) -> &'static str {
        match self {
            Self::CodeAnalysis => "code_analysis_deliverable.md",
            Self::Recon => "recon_deliverable.md",
            Self::InjectionAnalysis => "injection_analysis_deliverable.md",
            Self::InjectionQueue => "injection_exploitation_queue.json",
            Self::InjectionEvidence => "injection_exploitation_evidence.md",
            Self::XssAnalysis => "xss_analysis_deliverable.md",
            Self::XssQueue => "xss_exploitation_queue.json",
            Self::XssEvidence => "xss_exploitation_evidence.md",
            Self::AuthAnalysis => "auth_analysis_deliverable.md",
            Self::AuthQueue => "auth_exploitation_queue.json",
            Self::AuthEvidence => "auth_exploitation_evidence.md",
            Self::AuthzAnalysis => "authz_analysis_deliverable.md",
            Self::AuthzQueue => "authz_exploitation_queue.json",
            Self::AuthzEvidence => "authz_exploitation_evidence.md",
            Self::SsrfAnalysis => "ssrf_analysis_deliverable.md",
            Self::SsrfQueue => "ssrf_exploitation_queue.json",
            Self::SsrfEvidence => "ssrf_exploitation_evidence.md",
            Self::FinalReport => "comprehensive_security_assessment_report.md",
        }
    }

    /// Returns true if this deliverable is an exploitation queue (JSON format).
    pub fn is_queue(&self) -> bool {
        matches!(
            self,
            Self::InjectionQueue
                | Self::XssQueue
                | Self::AuthQueue
                | Self::AuthzQueue
                | Self::SsrfQueue
        )
    }
}
