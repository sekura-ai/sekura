use serde::{Deserialize, Serialize};

/// Outcome of attempting to exploit a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    /// Successfully demonstrated impact via public interface.
    Exploited,
    /// Valid vulnerability but blocked by WAF/security controls.
    BlockedBySecurity,
    /// Requires internal access -- not pursued.
    OutOfScopeInternal,
    /// Not actually vulnerable after testing.
    FalsePositive,
    /// Code analysis suggests vulnerability but live test inconclusive.
    Potential,
}

impl Verdict {
    /// Only `Exploited` and `BlockedBySecurity` are considered reportable findings.
    pub fn is_reportable(&self) -> bool {
        matches!(self, Verdict::Exploited | Verdict::BlockedBySecurity)
    }
}
