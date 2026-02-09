use async_trait::async_trait;
use reqwest::Client;
use serde_json::{json, Value};
use crate::errors::SekuraError;
use super::provider::LLMProvider;
use super::types::LLMResponse;

pub struct LocalProvider {
    client: Client,
    base_url: String,
    model: String,
    api_key: String,
}

impl LocalProvider {
    pub fn new(base_url: Option<&str>, model: Option<&str>, api_key: &str) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.unwrap_or("http://localhost:11434/v1").to_string(),
            model: model.unwrap_or("qwen2.5-coder:1.5b").to_string(),
            api_key: api_key.to_string(),
        }
    }
}

#[async_trait]
impl LLMProvider for LocalProvider {
    async fn complete(&self, prompt: &str, system: Option<&str>) -> Result<LLMResponse, SekuraError> {
        let mut messages = Vec::new();
        if let Some(sys) = system {
            messages.push(json!({"role": "system", "content": sys}));
        }
        messages.push(json!({"role": "user", "content": prompt}));

        let body = json!({
            "model": self.model,
            "messages": messages,
            "max_tokens": 4096,
        });

        let resp = self.client
            .post(format!("{}/chat/completions", self.base_url))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&body)
            .send()
            .await
            .map_err(|e| SekuraError::Network(format!("Local LLM request failed: {}", e)))?;

        let data: Value = resp.json().await
            .map_err(|e| SekuraError::LLMApi(format!("Parse error: {}", e)))?;

        let content = data["choices"][0]["message"]["content"].as_str().unwrap_or("").to_string();

        Ok(LLMResponse { content, input_tokens: None, output_tokens: None, cost_usd: None, model: self.model.clone() })
    }

    async fn complete_structured(&self, prompt: &str, schema: &Value, system: Option<&str>) -> Result<Value, SekuraError> {
        let augmented = format!("{}\n\nRespond with ONLY valid JSON:\n{}", prompt, serde_json::to_string_pretty(schema).unwrap_or_default());
        let response = self.complete(&augmented, system).await?;
        let text = &response.content;
        if let Ok(v) = serde_json::from_str::<Value>(text) { return Ok(v); }
        if let Some(start) = text.find('{') {
            if let Some(end) = text.rfind('}') {
                if start < end {
                    return serde_json::from_str(&text[start..=end])
                        .map_err(|e| SekuraError::LLMApi(format!("JSON error: {}", e)));
                }
            }
        }
        Err(SekuraError::LLMApi("No valid JSON in local LLM response".into()))
    }

    fn provider_name(&self) -> &str { "local" }
    fn model_name(&self) -> &str { &self.model }
}
