use async_trait::async_trait;
use reqwest::Client;
use serde_json::{json, Value};
use crate::errors::SekuraError;
use super::provider::LLMProvider;
use super::types::LLMResponse;
use tracing::debug;

pub struct AnthropicProvider {
    client: Client,
    api_key: String,
    model: String,
    base_url: String,
}

impl AnthropicProvider {
    pub fn new(api_key: &str, model: Option<&str>) -> Self {
        Self {
            client: Client::new(),
            api_key: api_key.to_string(),
            model: model.unwrap_or("claude-sonnet-4-5-20250929").to_string(),
            base_url: "https://api.anthropic.com".to_string(),
        }
    }
}

#[async_trait]
impl LLMProvider for AnthropicProvider {
    async fn complete(&self, prompt: &str, system: Option<&str>) -> Result<LLMResponse, SekuraError> {
        let mut body = json!({
            "model": self.model,
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": prompt}]
        });

        if let Some(sys) = system {
            body["system"] = json!(sys);
        }

        let resp = self.client
            .post(format!("{}/v1/messages", self.base_url))
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| SekuraError::Network(format!("Anthropic API request failed: {}", e)))?;

        let status = resp.status();
        if status == 429 {
            return Err(SekuraError::RateLimit("Anthropic rate limit exceeded".into()));
        }
        if status == 401 {
            return Err(SekuraError::Authentication("Invalid Anthropic API key".into()));
        }

        let data: Value = resp.json().await
            .map_err(|e| SekuraError::LLMApi(format!("Failed to parse Anthropic response: {}", e)))?;

        if let Some(error) = data.get("error") {
            let msg = error["message"].as_str().unwrap_or("Unknown error");
            if msg.contains("billing") || msg.contains("quota") {
                return Err(SekuraError::Billing(msg.to_string()));
            }
            return Err(SekuraError::LLMApi(msg.to_string()));
        }

        let content = data["content"][0]["text"].as_str()
            .ok_or_else(|| SekuraError::LLMApi("No content in Anthropic response".into()))?
            .to_string();

        let input_tokens = data["usage"]["input_tokens"].as_u64();
        let output_tokens = data["usage"]["output_tokens"].as_u64();

        let cost_usd = match (input_tokens, output_tokens) {
            (Some(inp), Some(out)) => {
                // Claude Sonnet pricing approximation
                Some((inp as f64 * 3.0 / 1_000_000.0) + (out as f64 * 15.0 / 1_000_000.0))
            }
            _ => None,
        };

        debug!(model = %self.model, input_tokens, output_tokens, "Anthropic completion");

        Ok(LLMResponse {
            content,
            input_tokens,
            output_tokens,
            cost_usd,
            model: self.model.clone(),
        })
    }

    async fn complete_structured(&self, prompt: &str, schema: &Value, system: Option<&str>) -> Result<Value, SekuraError> {
        let augmented_prompt = format!(
            "{}\n\nRespond with valid JSON matching this schema:\n```json\n{}\n```\n\nReturn ONLY the JSON, no other text.",
            prompt,
            serde_json::to_string_pretty(schema).unwrap_or_default()
        );

        let response = self.complete(&augmented_prompt, system).await?;
        extract_json(&response.content)
    }

    fn provider_name(&self) -> &str { "anthropic" }
    fn model_name(&self) -> &str { &self.model }
}

fn extract_json(text: &str) -> Result<Value, SekuraError> {
    // Try direct parse first
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        return Ok(v);
    }
    // Try extracting from markdown code block
    if let Some(start) = text.find("```json") {
        let rest = &text[start + 7..];
        if let Some(end) = rest.find("```") {
            let json_str = rest[..end].trim();
            return serde_json::from_str(json_str)
                .map_err(|e| SekuraError::LLMApi(format!("Invalid JSON in code block: {}", e)));
        }
    }
    // Try finding first { to last }
    if let (Some(start), Some(end)) = (text.find('{'), text.rfind('}')) {
        if start < end {
            let json_str = &text[start..=end];
            return serde_json::from_str(json_str)
                .map_err(|e| SekuraError::LLMApi(format!("Invalid JSON extraction: {}", e)));
        }
    }
    Err(SekuraError::LLMApi("No valid JSON found in LLM response".into()))
}
