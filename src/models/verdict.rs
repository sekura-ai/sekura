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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exploited_is_reportable() {
        assert!(Verdict::Exploited.is_reportable());
    }

    #[test]
    fn test_blocked_is_reportable() {
        assert!(Verdict::BlockedBySecurity.is_reportable());
    }

    #[test]
    fn test_false_positive_not_reportable() {
        assert!(!Verdict::FalsePositive.is_reportable());
    }

    #[test]
    fn test_out_of_scope_not_reportable() {
        assert!(!Verdict::OutOfScopeInternal.is_reportable());
    }

    #[test]
    fn test_potential_not_reportable() {
        assert!(!Verdict::Potential.is_reportable());
    }

    #[test]
    fn test_verdict_serialization() {
        let json = serde_json::to_string(&Verdict::Exploited).unwrap();
        assert_eq!(json, "\"EXPLOITED\"");
        let parsed: Verdict = serde_json::from_str("\"BLOCKED_BY_SECURITY\"").unwrap();
        assert_eq!(parsed, Verdict::BlockedBySecurity);
    }
}
