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
                "maxOutputTokens": 16384,
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
        let text = &response.content;

        // Try direct parse first
        if let Ok(v) = serde_json::from_str::<Value>(text) { return Ok(v); }

        // Strip markdown code fences if present
        let stripped = text.trim()
            .strip_prefix("```json").or_else(|| text.trim().strip_prefix("```"))
            .and_then(|s| s.strip_suffix("```"))
            .unwrap_or(text);
        if let Ok(v) = serde_json::from_str::<Value>(stripped.trim()) { return Ok(v); }

        // Extract JSON object from the response text
        if let Some(start) = stripped.find('{') {
            if let Some(end) = stripped.rfind('}') {
                if start < end {
                    let candidate = &stripped[start..=end];
                    if let Ok(v) = serde_json::from_str::<Value>(candidate) {
                        return Ok(v);
                    }
                    // Truncated array recovery: try closing open arrays/objects
                    if let Some(repaired) = repair_truncated_json(candidate) {
                        if let Ok(v) = serde_json::from_str::<Value>(&repaired) {
                            return Ok(v);
                        }
                    }
                    return Err(SekuraError::LLMApi(format!(
                        "JSON parse error: {}",
                        serde_json::from_str::<Value>(candidate).unwrap_err()
                    )));
                }
            }
        }
        Err(SekuraError::LLMApi("No valid JSON in Gemini response".into()))
    }

    fn provider_name(&self) -> &str { "gemini" }
    fn model_name(&self) -> &str { &self.model }
}

/// Attempt to repair truncated JSON by closing open brackets.
/// Handles the common case where an LLM response is cut off mid-array.
fn repair_truncated_json(text: &str) -> Option<String> {
    // Find the last complete object in the array (last '}' that precedes a truncation)
    // Strategy: repeatedly trim from the end until we find a valid close point
    let mut s = text.to_string();

    // Remove any trailing partial object (everything after the last complete '}')
    if let Some(last_brace) = s.rfind('}') {
        s.truncate(last_brace + 1);
    } else {
        return None;
    }

    // Count open brackets and close them
    let mut open_braces = 0i32;
    let mut open_brackets = 0i32;
    for ch in s.chars() {
        match ch {
            '{' => open_braces += 1,
            '}' => open_braces -= 1,
            '[' => open_brackets += 1,
            ']' => open_brackets -= 1,
            _ => {}
        }
    }

    // Close any unclosed brackets
    for _ in 0..open_braces { s.push('}'); }
    for _ in 0..open_brackets { s.push(']'); }

    if open_braces != 0 || open_brackets != 0 {
        Some(s)
    } else {
        None
    }
}
