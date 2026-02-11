use async_trait::async_trait;
use reqwest::Client;
use serde_json::{json, Value};
use crate::errors::SekuraError;
use super::provider::LLMProvider;
use super::types::LLMResponse;

pub struct OpenAIProvider {
    client: Client,
    api_key: String,
    model: String,
    base_url: String,
}

impl OpenAIProvider {
    pub fn new(api_key: &str, model: Option<&str>) -> Self {
        Self {
            client: Client::new(),
            api_key: api_key.to_string(),
            model: model.unwrap_or("gpt-4o").to_string(),
            base_url: "https://api.openai.com/v1".to_string(),
        }
    }
}

#[async_trait]
impl LLMProvider for OpenAIProvider {
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
            .map_err(|e| SekuraError::Network(format!("OpenAI request failed: {}", e)))?;

        let status = resp.status();
        if status.as_u16() == 429 {
            return Err(SekuraError::RateLimit("OpenAI rate limit".into()));
        }
        if status.as_u16() == 401 {
            return Err(SekuraError::Authentication("Invalid OpenAI API key".into()));
        }

        let data: Value = resp.json().await
            .map_err(|e| SekuraError::LLMApi(format!("Failed to parse OpenAI response: {}", e)))?;

        if let Some(error) = data.get("error") {
            return Err(SekuraError::LLMApi(error["message"].as_str().unwrap_or("Unknown").to_string()));
        }

        let content = data["choices"][0]["message"]["content"].as_str()
            .ok_or_else(|| SekuraError::LLMApi("No content in OpenAI response".into()))?
            .to_string();
        let input_tokens = data["usage"]["prompt_tokens"].as_u64();
        let output_tokens = data["usage"]["completion_tokens"].as_u64();

        Ok(LLMResponse {
            content,
            input_tokens,
            output_tokens,
            cost_usd: None,
            model: self.model.clone(),
        })
    }

    async fn complete_structured(&self, prompt: &str, schema: &Value, system: Option<&str>) -> Result<Value, SekuraError> {
        let mut messages = Vec::new();
        if let Some(sys) = system {
            messages.push(json!({"role": "system", "content": sys}));
        }
        messages.push(json!({"role": "user", "content": format!("{}\n\nRespond ONLY with valid JSON matching this schema:\n{}", prompt, serde_json::to_string_pretty(schema).unwrap_or_default())}));

        let body = json!({
            "model": self.model,
            "messages": messages,
            "max_tokens": 4096,
            "response_format": { "type": "json_object" },
        });

        let resp = self.client
            .post(format!("{}/chat/completions", self.base_url))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&body)
            .send()
            .await
            .map_err(|e| SekuraError::Network(format!("OpenAI request failed: {}", e)))?;

        let data: Value = resp.json().await
            .map_err(|e| SekuraError::LLMApi(format!("Parse error: {}", e)))?;

        let content = data["choices"][0]["message"]["content"].as_str()
            .ok_or_else(|| SekuraError::LLMApi("No content in OpenAI structured response".into()))?;
        serde_json::from_str(content)
            .map_err(|e| SekuraError::LLMApi(format!("Invalid JSON: {}", e)))
    }

    fn provider_name(&self) -> &str { "openai" }
    fn model_name(&self) -> &str { &self.model }
}
