use std::sync::Arc;
use tokio::sync::Mutex;
use crate::container::ContainerManager;
use crate::errors::SekuraError;

/// Manages a persistent Playwright browser session within the Kali container.
///
/// Unlike the previous implementation which launched a fresh browser for every action,
/// this version starts a persistent Node.js server process inside the container that
/// keeps a single Chromium instance alive. All actions (navigate, click, type, etc.)
/// are sent as commands to this server, preserving cookies, sessions, and DOM state
/// across operations.
pub struct BrowserSession {
    container: Arc<ContainerManager>,
    session_id: String,
    /// Tracks whether the persistent browser server has been started.
    initialized: Mutex<bool>,
}

impl BrowserSession {
    pub fn new(container: Arc<ContainerManager>, session_id: &str) -> Self {
        Self {
            container,
            session_id: session_id.to_string(),
            initialized: Mutex::new(false),
        }
    }

    /// Ensure the persistent Playwright browser server is running in the container.
    /// The server script stays resident and accepts commands via a named pipe.
    async fn ensure_initialized(&self) -> Result<(), SekuraError> {
        let mut initialized = self.initialized.lock().await;
        if *initialized {
            return Ok(());
        }

        // Write the persistent browser server script into the container
        let server_script = self.browser_server_script();
        let escaped_script = server_script.replace('\\', "\\\\").replace('"', "\\\"");
        let write_cmd = format!(
            "mkdir -p /tmp/pw && echo \"{}\" > /tmp/pw/server_{}.js",
            escaped_script, self.session_id
        );
        self.container.exec(&write_cmd, 10).await?;

        // Start the server in the background
        let start_cmd = format!(
            "cd /tmp/pw && node server_{}.js &",
            self.session_id
        );
        self.container.exec(&start_cmd, 15).await?;

        // Wait for the browser to be ready
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        *initialized = true;
        Ok(())
    }

    /// Generate the Node.js server script that maintains a persistent browser session.
    fn browser_server_script(&self) -> String {
        format!(
            r#"const fs = require('fs');
const pw = require('playwright');

const PIPE_IN = '/tmp/pw/cmd_{sid}';
const PIPE_OUT = '/tmp/pw/out_{sid}';
const READY = '/tmp/pw/ready_{sid}';

(async () => {{
  const browser = await pw.chromium.launch({{headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage']}});
  const context = await browser.newContext({{ignoreHTTPSErrors: true}});
  const page = await context.newPage();

  // Signal readiness
  fs.writeFileSync(READY, 'ready');

  // Process commands from stdin-like interface via file polling
  const cmdFile = '/tmp/pw/pending_{sid}';

  while (true) {{
    try {{
      if (fs.existsSync(cmdFile)) {{
        const raw = fs.readFileSync(cmdFile, 'utf-8').trim();
        fs.unlinkSync(cmdFile);

        if (raw === 'QUIT') {{
          await browser.close();
          process.exit(0);
        }}

        const cmd = JSON.parse(raw);
        let result = '';

        switch (cmd.action) {{
          case 'navigate':
            await page.goto(cmd.url, {{waitUntil: 'domcontentloaded', timeout: 30000}});
            result = await page.content();
            break;
          case 'click':
            await page.click(cmd.selector, {{timeout: 10000}});
            result = 'clicked';
            break;
          case 'type':
            await page.fill(cmd.selector, cmd.text, {{timeout: 10000}});
            result = 'typed';
            break;
          case 'screenshot':
            const path = '/tmp/pw/screenshot_{sid}.png';
            await page.screenshot({{path: path, fullPage: true}});
            result = 'screenshot:' + path;
            break;
          case 'evaluate':
            const r = await page.evaluate(cmd.js);
            result = JSON.stringify(r);
            break;
          case 'content':
            result = await page.content();
            break;
          case 'cookies':
            const cookies = await context.cookies();
            result = JSON.stringify(cookies);
            break;
          case 'set_cookies':
            await context.addCookies(cmd.cookies);
            result = 'cookies_set';
            break;
          case 'url':
            result = page.url();
            break;
          default:
            result = 'unknown_action';
        }}

        fs.writeFileSync('/tmp/pw/result_{sid}', result);
      }}
    }} catch (e) {{
      fs.writeFileSync('/tmp/pw/result_{sid}', 'ERROR:' + e.message);
    }}
    await new Promise(r => setTimeout(r, 100));
  }}
}})();"#,
            sid = self.session_id
        )
    }

    /// Send a command to the persistent browser and read the result.
    async fn send_command(&self, cmd: &serde_json::Value) -> Result<String, SekuraError> {
        self.ensure_initialized().await?;

        let cmd_json = serde_json::to_string(cmd)
            .map_err(|e| SekuraError::Internal(format!("Failed to serialize browser command: {}", e)))?;

        // Write command file
        let write_cmd = format!(
            "echo '{}' > /tmp/pw/pending_{}",
            cmd_json.replace('\'', "'\\''"),
            self.session_id
        );
        self.container.exec(&write_cmd, 5).await?;

        // Poll for result with timeout
        let result_path = format!("/tmp/pw/result_{}", self.session_id);
        let timeout = std::time::Duration::from_secs(35);
        let start = std::time::Instant::now();

        loop {
            if start.elapsed() > timeout {
                return Err(SekuraError::Timeout("Browser command timed out".into()));
            }

            let check_cmd = format!(
                "cat {} 2>/dev/null && rm -f {}",
                result_path, result_path
            );
            match self.container.exec(&check_cmd, 5).await {
                Ok(result) if !result.trim().is_empty() => {
                    if result.starts_with("ERROR:") {
                        return Err(SekuraError::Browser(result[6..].to_string()));
                    }
                    return Ok(result);
                }
                _ => {
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
            }
        }
    }

    /// Navigate to a URL, preserving session state (cookies, local storage) from prior actions.
    pub async fn navigate(&self, url: &str) -> Result<String, SekuraError> {
        let cmd = serde_json::json!({"action": "navigate", "url": url});
        self.send_command(&cmd).await
    }

    /// Click an element by CSS selector on the current page.
    pub async fn click(&self, selector: &str) -> Result<(), SekuraError> {
        let cmd = serde_json::json!({"action": "click", "selector": selector});
        self.send_command(&cmd).await?;
        Ok(())
    }

    /// Type text into a form field by CSS selector, preserving page state.
    pub async fn type_text(&self, selector: &str, text: &str) -> Result<(), SekuraError> {
        let cmd = serde_json::json!({"action": "type", "selector": selector, "text": text});
        self.send_command(&cmd).await?;
        Ok(())
    }

    /// Take a screenshot of the current page state.
    pub async fn screenshot(&self) -> Result<Vec<u8>, SekuraError> {
        let cmd = serde_json::json!({"action": "screenshot"});
        let result = self.send_command(&cmd).await?;

        if let Some(path) = result.strip_prefix("screenshot:") {
            let output = self.container.exec(&format!("base64 {}", path.trim()), 10).await?;
            Ok(output.into_bytes())
        } else {
            Err(SekuraError::Browser("Unexpected screenshot result".into()))
        }
    }

    /// Evaluate JavaScript in the context of the current page.
    pub async fn evaluate(&self, js: &str) -> Result<String, SekuraError> {
        let cmd = serde_json::json!({"action": "evaluate", "js": js});
        self.send_command(&cmd).await
    }

    /// Get the current page content (HTML).
    pub async fn content(&self) -> Result<String, SekuraError> {
        let cmd = serde_json::json!({"action": "content"});
        self.send_command(&cmd).await
    }

    /// Get all cookies from the current browser context.
    pub async fn cookies(&self) -> Result<String, SekuraError> {
        let cmd = serde_json::json!({"action": "cookies"});
        self.send_command(&cmd).await
    }

    /// Get the current page URL.
    pub async fn current_url(&self) -> Result<String, SekuraError> {
        let cmd = serde_json::json!({"action": "url"});
        self.send_command(&cmd).await
    }

    /// Close the persistent browser session.
    pub async fn close(&self) -> Result<(), SekuraError> {
        let write_cmd = format!(
            "echo 'QUIT' > /tmp/pw/pending_{}",
            self.session_id
        );
        let _ = self.container.exec(&write_cmd, 5).await;
        let mut initialized = self.initialized.lock().await;
        *initialized = false;
        Ok(())
    }
}

impl Drop for BrowserSession {
    fn drop(&mut self) {
        // Best-effort cleanup — can't do async in drop
        let sid = self.session_id.clone();
        let container = self.container.clone();
        tokio::spawn(async move {
            let _ = container.exec(&format!("echo 'QUIT' > /tmp/pw/pending_{}", sid), 5).await;
        });
    }
}
