use std::path::PathBuf;
use std::sync::Arc;
use crate::container::ContainerManager;
use crate::errors::SekuraError;
use tracing::{info, warn, debug};

const LOGIN_PATHS: &[&str] = &[
    "/login", "/login.php", "/login.html", "/signin",
    "/auth/login", "/admin/login", "/user/login",
    "/wp-login.php", "/administrator/",
];

/// Known CSRF/anti-forgery token field names across major frameworks
const CSRF_FIELD_NAMES: &[&str] = &[
    "user_token",            // DVWA
    "csrf_token",            // Generic / Flask-WTF
    "csrftoken",             // Generic
    "csrf-token",            // Generic
    "_token",                // Laravel
    "csrfmiddlewaretoken",   // Django
    "authenticity_token",    // Rails
    "_csrf",                 // Express/csurf
    "__RequestVerificationToken", // ASP.NET
    "token",                 // Generic fallback
];

pub struct WebAuthenticator {
    container: Arc<ContainerManager>,
    target_url: String,
    username: Option<String>,
    password: Option<String>,
    /// Host-side path for reading cookies back after auth
    cookie_file: PathBuf,
    /// Container-side path where curl writes cookies
    container_cookie_file: String,
}

impl WebAuthenticator {
    pub fn new(
        container: Arc<ContainerManager>,
        target_url: &str,
        username: Option<String>,
        password: Option<String>,
        output_dir: &std::path::Path,
    ) -> Self {
        Self {
            container,
            target_url: target_url.trim_end_matches('/').to_string(),
            username,
            password,
            cookie_file: output_dir.join("cookies.txt"),
            container_cookie_file: "/tmp/sekura_cookies.txt".to_string(),
        }
    }

    pub async fn authenticate(
        &mut self,
        login_url: Option<&str>,
    ) -> Result<bool, SekuraError> {
        let (username, password) = match (&self.username, &self.password) {
            (Some(u), Some(p)) => (u.clone(), p.clone()),
            _ => {
                info!("No credentials provided, skipping authentication");
                return Ok(false);
            }
        };

        // 1. Discover or use provided login URL
        let login_url = match login_url {
            Some(url) => url.to_string(),
            None => self.discover_login_page().await?,
        };

        info!(login_url = %login_url, "Attempting authentication");

        // 2. Get CSRF token from login page
        let csrf_token = self.extract_csrf_token(&login_url).await?;

        // 3. Submit credentials via curl in container (using container-local cookie path)
        let cfile = &self.container_cookie_file;
        let mut cmd = format!(
            "curl -v -c {} -b {} -L -X POST '{}' -d 'username={}&password={}'",
            cfile,
            cfile,
            login_url,
            username,
            password,
        );

        if let Some((field_name, csrf_value)) = &csrf_token {
            cmd.push_str(&format!(" -d '{}={}'", field_name, csrf_value));
        }

        let output = self.container.exec(&cmd, 30).await?;
        debug!(output_len = output.len(), "Login response received");

        // 4. Verify authentication by checking for session cookie
        let success = self.verify_auth().await?;
        if success {
            info!("Authentication successful");
            // Copy cookie jar from container to host for get_cookie_string()
            self.copy_cookies_to_host().await;
        } else {
            warn!("Authentication may have failed — no session cookie detected");
        }

        Ok(success)
    }

    async fn discover_login_page(&self) -> Result<String, SekuraError> {
        for path in LOGIN_PATHS {
            let url = format!("{}{}", self.target_url, path);
            let cmd = format!(
                "curl -s -o /dev/null -w '%{{http_code}}' '{}'",
                url
            );
            let output = self.container.exec(&cmd, 10).await?;
            let status: u16 = output.trim().parse().unwrap_or(0);
            if status == 200 || status == 302 {
                info!(url = %url, status, "Found login page");
                return Ok(url);
            }
        }
        Err(SekuraError::Authentication(format!(
            "Could not discover login page at {}",
            self.target_url
        )))
    }

    async fn extract_csrf_token(&self, login_url: &str) -> Result<Option<(String, String)>, SekuraError> {
        // Fetch the login page and extract all hidden input fields
        let cmd = format!(
            "curl -s -c {} '{}' | grep -oP '<input[^>]+type=\"hidden\"[^>]*>' | grep -oP 'name=\"\\K[^\"]*|value=\"\\K[^\"]*'",
            self.container_cookie_file,
            login_url
        );
        let output = self.container.exec(&cmd, 15).await?;
        let tokens: Vec<&str> = output.lines().collect();

        // Parse name/value pairs (grep outputs alternating name, value lines)
        let mut i = 0;
        while i + 1 < tokens.len() {
            let field_name = tokens[i].trim();
            let field_value = tokens[i + 1].trim();
            if CSRF_FIELD_NAMES.iter().any(|known| field_name.eq_ignore_ascii_case(known)) {
                debug!(field = %field_name, value_len = field_value.len(), "CSRF token extracted");
                return Ok(Some((field_name.to_string(), field_value.to_string())));
            }
            i += 2;
        }

        debug!("No CSRF token found on login page");
        Ok(None)
    }

    async fn verify_auth(&self) -> Result<bool, SekuraError> {
        let cmd = format!("cat {} 2>/dev/null", self.container_cookie_file);
        let output = self.container.exec(&cmd, 5).await?;

        // Check for common session cookie names
        let session_indicators = ["session", "PHPSESSID", "JSESSIONID", "connect.sid", "token", "auth"];
        let has_session = session_indicators.iter().any(|s| output.to_lowercase().contains(&s.to_lowercase()));
        Ok(has_session)
    }

    pub fn get_cookie_string(&self) -> Result<Option<String>, SekuraError> {
        // Try host-side file first (populated by copy_cookies_to_host)
        let content = if self.cookie_file.exists() {
            std::fs::read_to_string(&self.cookie_file)?
        } else {
            return Ok(None);
        };

        let cookies = Self::parse_cookie_jar(&content);

        if cookies.is_empty() {
            Ok(None)
        } else {
            Ok(Some(cookies.join("; ")))
        }
    }

    /// Parse Netscape cookie jar format into "name=value" pairs.
    fn parse_cookie_jar(content: &str) -> Vec<String> {
        content.lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .filter_map(|l| {
                let parts: Vec<&str> = l.split('\t').collect();
                if parts.len() >= 7 {
                    Some(format!("{}={}", parts[5], parts[6]))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Copy the cookie jar from the container to the host-side path.
    async fn copy_cookies_to_host(&self) {
        let cmd = format!("cat {} 2>/dev/null", self.container_cookie_file);
        match self.container.exec(&cmd, 5).await {
            Ok(content) if !content.trim().is_empty() => {
                // Ensure parent dir exists
                if let Some(parent) = self.cookie_file.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if let Err(e) = std::fs::write(&self.cookie_file, &content) {
                    warn!(error = %e, "Failed to write cookie file to host");
                }
            }
            _ => {
                debug!("No cookies to copy from container");
            }
        }
    }

    pub fn cookie_file(&self) -> &PathBuf {
        &self.cookie_file
    }

    /// Returns the container-side cookie file path (for use in container exec commands).
    pub fn container_cookie_path(&self) -> &str {
        &self.container_cookie_file
    }
}
