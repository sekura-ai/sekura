use async_trait::async_trait;
use reqwest::Client;
use serde_json::{json, Value};
use crate::errors::SekuraError;
use super::provider::LLMProvider;
use super::types::LLMResponse;

pub struct OpenRouterProvider {
    client: Client,
    api_key: String,
    model: String,
}

impl OpenRouterProvider {
    pub fn new(api_key: &str, model: Option<&str>) -> Self {
        Self {
            client: Client::new(),
            api_key: api_key.to_string(),
            model: model.unwrap_or("anthropic/claude-sonnet-4-5-20250929").to_string(),
        }
    }
}

#[async_trait]
impl LLMProvider for OpenRouterProvider {
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
            .post("https://openrouter.ai/api/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("HTTP-Referer", "https://sekura.dev")
            .json(&body)
            .send()
            .await
            .map_err(|e| SekuraError::Network(format!("OpenRouter request failed: {}", e)))?;

        if resp.status().as_u16() == 429 {
            return Err(SekuraError::RateLimit("OpenRouter rate limit".into()));
        }

        let data: Value = resp.json().await
            .map_err(|e| SekuraError::LLMApi(format!("Parse error: {}", e)))?;

        if let Some(error) = data.get("error") {
            return Err(SekuraError::LLMApi(
                error["message"].as_str().unwrap_or("Unknown OpenRouter error").to_string()
            ));
        }

        let content = data["choices"][0]["message"]["content"].as_str()
            .ok_or_else(|| SekuraError::LLMApi("No content in OpenRouter response".into()))?
            .to_string();
        let input_tokens = data["usage"]["prompt_tokens"].as_u64();
        let output_tokens = data["usage"]["completion_tokens"].as_u64();

        Ok(LLMResponse { content, input_tokens, output_tokens, cost_usd: None, model: self.model.clone() })
    }

    async fn complete_structured(&self, prompt: &str, schema: &Value, system: Option<&str>) -> Result<Value, SekuraError> {
        let augmented = format!("{}\n\nRespond with ONLY valid JSON matching:\n{}", prompt, serde_json::to_string_pretty(schema).unwrap_or_default());
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
        Err(SekuraError::LLMApi("No valid JSON in response".into()))
    }

    fn provider_name(&self) -> &str { "openrouter" }
    fn model_name(&self) -> &str { &self.model }
}
