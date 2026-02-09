use crate::errors::SekuraError;
use super::provider::LLMProvider;
use super::anthropic::AnthropicProvider;
use super::openai::OpenAIProvider;
use super::gemini::GeminiProvider;
use super::openrouter::OpenRouterProvider;
use super::local::LocalProvider;

pub fn create_provider(
    provider_name: &str,
    api_key: &str,
    model: Option<&str>,
    base_url: Option<&str>,
) -> Result<Box<dyn LLMProvider>, SekuraError> {
    match provider_name {
        "anthropic" => Ok(Box::new(AnthropicProvider::new(api_key, model))),
        "openai" => Ok(Box::new(OpenAIProvider::new(api_key, model))),
        "gemini" => Ok(Box::new(GeminiProvider::new(api_key, model))),
        "openrouter" => Ok(Box::new(OpenRouterProvider::new(api_key, model))),
        "local" => Ok(Box::new(LocalProvider::new(base_url, model, api_key))),
        _ => Err(SekuraError::Config(format!("Unknown LLM provider: {}", provider_name))),
    }
}
