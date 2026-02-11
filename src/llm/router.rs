use crate::errors::SekuraError;
use super::provider::LLMProvider;
use super::anthropic::AnthropicProvider;
use super::openai::OpenAIProvider;
use super::gemini::GeminiProvider;
use super::openrouter::OpenRouterProvider;
use super::local::LocalProvider;
use super::catalog;

pub fn create_provider(
    provider_name: &str,
    api_key: &str,
    model: Option<&str>,
    base_url: Option<&str>,
) -> Result<Box<dyn LLMProvider>, SekuraError> {
    let backend = catalog::backend_for_provider(provider_name);

    match backend {
        "anthropic" => Ok(Box::new(AnthropicProvider::new(api_key, model))),
        "openai" => Ok(Box::new(OpenAIProvider::new(api_key, model))),
        "gemini" => Ok(Box::new(GeminiProvider::new(api_key, model))),
        "openrouter" => Ok(Box::new(OpenRouterProvider::new(api_key, model))),
        "local" => Ok(Box::new(LocalProvider::new(base_url, model, api_key))),
        "openai_compatible" => {
            // Use explicit base_url override, or the one from the catalog
            let url = base_url
                .map(|s| s.to_string())
                .or_else(|| catalog::get_provider(provider_name).and_then(|p| p.base_url.clone()))
                .unwrap_or_else(|| "https://api.openai.com/v1".to_string());
            Ok(Box::new(OpenAIProvider::with_base_url(api_key, model, &url)))
        }
        "unsupported" => {
            let provider_label = catalog::get_provider(provider_name)
                .map(|p| p.name.as_str())
                .unwrap_or(provider_name);
            Err(SekuraError::Config(format!(
                "{} requires advanced authentication not yet supported. \
                 Use a simpler provider or configure manually.",
                provider_label
            )))
        }
        _ => Err(SekuraError::Config(format!("Unknown LLM provider: {}", provider_name))),
    }
}
