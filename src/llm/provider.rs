use async_trait::async_trait;
use crate::errors::SekuraError;
use super::types::LLMResponse;

#[async_trait]
pub trait LLMProvider: Send + Sync {
    /// Free-form text completion
    async fn complete(
        &self,
        prompt: &str,
        system: Option<&str>,
    ) -> Result<LLMResponse, SekuraError>;

    /// Structured JSON completion with schema enforcement
    async fn complete_structured(
        &self,
        prompt: &str,
        schema: &serde_json::Value,
        system: Option<&str>,
    ) -> Result<serde_json::Value, SekuraError>;

    /// Provider name for logging
    fn provider_name(&self) -> &str;

    /// Model identifier
    fn model_name(&self) -> &str;
}
