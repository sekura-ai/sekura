use async_trait::async_trait;
use reqwest::Client;
use serde_json::{json, Value};
use crate::errors::SekuraError;
use super::provider::LLMProvider;
use super::types::LLMResponse;

pub struct GeminiProvider {
    client: Client,
    api_key: String,
    model: String,
}

impl GeminiProvider {
    pub fn new(api_key: &str, model: Option<&str>) -> Self {
        Self {
            client: Client::new(),
            api_key: api_key.to_string(),
            model: model.unwrap_or("gemini-2.5-flash").to_string(),
        }
    }
}

#[async_trait]
impl LLMProvider for GeminiProvider {
    async fn complete(&self, prompt: &str, system: Option<&str>) -> Result<LLMResponse, SekuraError> {
        let mut contents = Vec::new();
        if let Some(sys) = system {
            contents.push(json!({"role": "user", "parts": [{"text": format!("System: {}\n\n{}", sys, prompt)}]}));
        } else {
            contents.push(json!({"role": "user", "parts": [{"text": prompt}]}));
        }

        let body = json!({
            "contents": contents,
            "generationConfig": {
                "maxOutputTokens": 4096,
            }
        });

        let url = format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
            self.model, self.api_key
        );

        let resp = self.client.post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| SekuraError::Network(format!("Gemini request failed: {}", e)))?;

        if resp.status().as_u16() == 429 {
            return Err(SekuraError::RateLimit("Gemini rate limit".into()));
        }

        let data: Value = resp.json().await
            .map_err(|e| SekuraError::LLMApi(format!("Parse error: {}", e)))?;

        if let Some(error) = data.get("error") {
            return Err(SekuraError::LLMApi(error["message"].as_str().unwrap_or("Unknown").to_string()));
        }

        let content = data["candidates"][0]["content"]["parts"][0]["text"]
            .as_str().unwrap_or("").to_string();

        let input_tokens = data["usageMetadata"]["promptTokenCount"].as_u64();
        let output_tokens = data["usageMetadata"]["candidatesTokenCount"].as_u64();

        Ok(LLMResponse {
            content,
            input_tokens,
            output_tokens,
            cost_usd: None,
            model: self.model.clone(),
        })
    }

    async fn complete_structured(&self, prompt: &str, schema: &Value, system: Option<&str>) -> Result<Value, SekuraError> {
        let augmented = format!("{}\n\nRespond with ONLY valid JSON matching:\n{}", prompt, serde_json::to_string_pretty(schema).unwrap_or_default());
        let response = self.complete(&augmented, system).await?;
        // Extract JSON from response
        let text = &response.content;
        if let Ok(v) = serde_json::from_str::<Value>(text) { return Ok(v); }
        if let Some(start) = text.find('{') {
            if let Some(end) = text.rfind('}') {
                if start < end {
                    return serde_json::from_str(&text[start..=end])
                        .map_err(|e| SekuraError::LLMApi(format!("JSON parse error: {}", e)));
                }
            }
        }
        Err(SekuraError::LLMApi("No valid JSON in Gemini response".into()))
    }

    fn provider_name(&self) -> &str { "gemini" }
    fn model_name(&self) -> &str { &self.model }
}
