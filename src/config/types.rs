use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct SekuraConfig {
    pub authentication: Option<AuthenticationConfig>,
    pub rules: Option<RulesConfig>,
    pub scan: Option<ScanConfig>,
    pub llm: Option<LLMConfig>,
    pub container: Option<ContainerConfig>,
    pub output: Option<OutputConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthenticationConfig {
    pub login_type: LoginType,
    pub login_url: String,
    pub credentials: Credentials,
    pub login_flow: Option<Vec<String>>,
    pub success_condition: Option<SuccessCondition>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LoginType {
    Form,
    Sso,
    Api,
    Basic,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Credentials {
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp_secret: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SuccessCondition {
    pub redirect_contains: Option<String>,
    pub cookie_name: Option<String>,
    pub status_code: Option<u16>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct RulesConfig {
    pub avoid: Option<Vec<Rule>>,
    pub focus: Option<Vec<Rule>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rule {
    pub description: String,
    #[serde(rename = "type")]
    pub rule_type: RuleType,
    pub url_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleType {
    Path,
    Subdomain,
    Domain,
    Method,
    Header,
    Parameter,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ScanConfig {
    pub intensity: Option<Intensity>,
    pub layers: Option<Vec<String>>,
    pub max_agent_iterations: Option<u32>,
    pub parallel_phases: Option<bool>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Intensity {
    Quick,
    #[default]
    Standard,
    Thorough,
}

impl Intensity {
    pub fn max_level(&self) -> u8 {
        match self {
            Self::Quick => 0,
            Self::Standard => 1,
            Self::Thorough => 2,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Quick => "quick",
            Self::Standard => "standard",
            Self::Thorough => "thorough",
        }
    }
}

impl std::fmt::Display for Intensity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct LLMConfig {
    pub provider: Option<String>,
    pub model: Option<String>,
    pub api_key: Option<String>,
    pub base_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ContainerConfig {
    pub image: Option<String>,
    pub name: Option<String>,
    pub network_mode: Option<String>,
    pub capabilities: Option<Vec<String>>,
}

impl Default for ContainerConfig {
    fn default() -> Self {
        Self {
            image: Some("sekura-kali:latest".to_string()),
            name: Some("sekura-kali".to_string()),
            network_mode: Some("host".to_string()),
            capabilities: Some(vec!["NET_RAW".to_string(), "NET_ADMIN".to_string()]),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct OutputConfig {
    pub directory: Option<String>,
    pub format: Option<String>,
}
