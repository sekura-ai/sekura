use std::sync::Arc;
use crate::container::ContainerManager;
use crate::errors::SekuraError;

pub struct BrowserSession {
    container: Arc<ContainerManager>,
    session_id: String,
}

impl BrowserSession {
    pub fn new(container: Arc<ContainerManager>, session_id: &str) -> Self {
        Self {
            container,
            session_id: session_id.to_string(),
        }
    }

    pub async fn navigate(&self, url: &str) -> Result<String, SekuraError> {
        let script = format!(
            r#"node -e "const pw = require('playwright'); (async () => {{ const b = await pw.chromium.launch({{headless: true}}); const p = await b.newPage(); await p.goto('{}'); const c = await p.content(); console.log(c); await b.close(); }})()" "#,
            url.replace('\'', "\\'")
        );
        self.container.exec(&script, 30).await
    }

    pub async fn click(&self, selector: &str) -> Result<(), SekuraError> {
        let script = format!(
            r#"node -e "const pw = require('playwright'); (async () => {{ const b = await pw.chromium.launch({{headless: true}}); const p = await b.newPage(); await p.click('{}'); await b.close(); }})()" "#,
            selector.replace('\'', "\\'")
        );
        self.container.exec(&script, 15).await?;
        Ok(())
    }

    pub async fn type_text(&self, selector: &str, text: &str) -> Result<(), SekuraError> {
        let script = format!(
            r#"node -e "const pw = require('playwright'); (async () => {{ const b = await pw.chromium.launch({{headless: true}}); const p = await b.newPage(); await p.fill('{}', '{}'); await b.close(); }})()" "#,
            selector.replace('\'', "\\'"),
            text.replace('\'', "\\'")
        );
        self.container.exec(&script, 15).await?;
        Ok(())
    }

    pub async fn screenshot(&self) -> Result<Vec<u8>, SekuraError> {
        let path = format!("/tmp/screenshot_{}.png", self.session_id);
        let script = format!(
            r#"node -e "const pw = require('playwright'); (async () => {{ const b = await pw.chromium.launch({{headless: true}}); const p = await b.newPage(); await p.screenshot({{path: '{}'}}); await b.close(); }})()" "#,
            path
        );
        self.container.exec(&script, 15).await?;
        let output = self.container.exec(&format!("base64 {}", path), 5).await?;
        Ok(output.into_bytes())
    }

    pub async fn evaluate(&self, js: &str) -> Result<String, SekuraError> {
        let escaped = js.replace('\\', "\\\\").replace('\'', "\\'").replace('\n', "\\n");
        let script = format!(
            r#"node -e "const pw = require('playwright'); (async () => {{ const b = await pw.chromium.launch({{headless: true}}); const p = await b.newPage(); const r = await p.evaluate('{}'); console.log(JSON.stringify(r)); await b.close(); }})()" "#,
            escaped
        );
        self.container.exec(&script, 15).await
    }
}
