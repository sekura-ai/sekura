use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct CreateScanRequest {
    pub target: String,
    pub repo_path: Option<String>,
    pub config_path: Option<String>,
    pub intensity: Option<String>,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub api_key: Option<String>,
    pub skip_whitebox: Option<bool>,
    pub skip_blackbox: Option<bool>,
    pub skip_exploit: Option<bool>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub cookie: Option<String>,
    pub login_url: Option<String>,
    pub no_auth: Option<bool>,
    pub layers: Option<Vec<String>>,
    pub webhook_url: Option<String>,
}

#[derive(Serialize)]
pub struct ScanResponse {
    pub id: String,
    pub status: String,
    pub target: String,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}
