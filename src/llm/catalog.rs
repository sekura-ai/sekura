use std::collections::HashMap;
use std::sync::LazyLock;
use serde::Deserialize;

/// Raw top-level JSON structure with a `providers` map and optional `_meta`.
#[derive(Deserialize)]
struct RawCatalog {
    providers: HashMap<String, ProviderInfo>,
}

#[derive(Deserialize, Clone)]
pub struct ProviderInfo {
    pub name: String,
    #[serde(default)]
    pub base_url: Option<String>,
    #[serde(default)]
    pub openai_compatible: Option<bool>,
    #[serde(default)]
    pub auth_method: Option<String>,
    #[serde(default)]
    pub requires: Option<Vec<String>>,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub models: Vec<ModelInfo>,
}

#[derive(Deserialize, Clone)]
pub struct ModelInfo {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub context_window: Option<u64>,
    #[serde(default)]
    pub max_output: Option<u64>,
    #[serde(default)]
    pub supports_vision: Option<bool>,
    #[serde(default)]
    pub supports_tools: Option<bool>,
    #[serde(default)]
    pub reasoning: Option<bool>,
    #[serde(default)]
    pub open_weight: Option<bool>,
}

pub struct ProviderCatalog {
    providers: HashMap<String, ProviderInfo>,
}

static CATALOG: LazyLock<ProviderCatalog> = LazyLock::new(|| {
    let json = include_str!("../ai_providers.json");
    let raw: RawCatalog = serde_json::from_str(json)
        .expect("ai_providers.json must be valid JSON");
    ProviderCatalog {
        providers: raw.providers,
    }
});

/// Returns a sorted list of (provider_id, &ProviderInfo) suitable for display.
///
/// Ordering: primary backends first (anthropic, openai, google, openrouter, local),
/// then openai-compatible alphabetically, then advanced-auth providers.
/// Skips `meta_llama` (no direct API).
pub fn provider_list() -> Vec<(&'static str, &'static ProviderInfo)> {
    let catalog = &*CATALOG;

    // Primary backends in display order
    let primary = ["anthropic", "openai", "google", "openrouter", "local"];
    // Providers that require complex auth (skip from simple list)
    let advanced_auth = ["google_vertex", "aws_bedrock", "azure_openai"];
    let skip = ["meta_llama"];

    let mut result: Vec<(&str, &ProviderInfo)> = Vec::new();

    // 1. Primary backends
    for id in &primary {
        if let Some(info) = catalog.providers.get(*id) {
            result.push((id, info));
        }
    }

    // 2. OpenAI-compatible (alphabetical), excluding primary/advanced/skip
    let mut compat: Vec<(&str, &ProviderInfo)> = catalog
        .providers
        .iter()
        .filter(|(id, info)| {
            !primary.contains(&id.as_str())
                && !advanced_auth.contains(&id.as_str())
                && !skip.contains(&id.as_str())
                && info.openai_compatible.unwrap_or(false)
        })
        .map(|(id, info)| (id.as_str(), info))
        .collect();
    compat.sort_by_key(|(id, _)| *id);
    result.extend(compat);

    // 3. Remaining non-advanced providers (like cohere, ai21 — have base_url but not marked openai_compatible)
    let mut remaining: Vec<(&str, &ProviderInfo)> = catalog
        .providers
        .iter()
        .filter(|(id, _info)| {
            !result.iter().any(|(rid, _)| rid == &id.as_str())
                && !advanced_auth.contains(&id.as_str())
                && !skip.contains(&id.as_str())
        })
        .map(|(id, info)| (id.as_str(), info))
        .collect();
    remaining.sort_by_key(|(id, _)| *id);
    result.extend(remaining);

    // 4. Advanced auth last
    for id in &advanced_auth {
        if let Some(info) = catalog.providers.get(*id) {
            result.push((id, info));
        }
    }

    result
}

/// Look up a provider by ID.
pub fn get_provider(id: &str) -> Option<&'static ProviderInfo> {
    CATALOG.providers.get(id)
}

/// Returns the first model ID in the provider's model list (the recommended default).
pub fn get_default_model(provider_id: &str) -> Option<&'static str> {
    CATALOG
        .providers
        .get(provider_id)
        .and_then(|p| p.models.first())
        .map(|m| m.id.as_str())
}

/// Convention: `{ID}_API_KEY` uppercased, with special cases.
pub fn env_var_for_provider(id: &str) -> String {
    match id {
        "google" => "GEMINI_API_KEY".to_string(),
        "local" => String::new(),
        _ => format!("{}_API_KEY", id.to_uppercase()),
    }
}

/// Maps a provider ID to the Rust backend type used for routing.
pub fn backend_for_provider(id: &str) -> &'static str {
    match id {
        "anthropic" => "anthropic",
        "openai" => "openai",
        "google" => "gemini",
        "openrouter" => "openrouter",
        "local" => "local",
        _ => {
            // Check if the provider is marked openai_compatible or has a simple base_url
            if let Some(info) = CATALOG.providers.get(id) {
                if info.openai_compatible.unwrap_or(false) {
                    return "openai_compatible";
                }
                // Providers with requires (complex auth) are unsupported for now
                if info.requires.is_some() {
                    return "unsupported";
                }
                // Has a base_url → try openai_compatible as fallback
                if info.base_url.is_some() {
                    return "openai_compatible";
                }
            }
            "unsupported"
        }
    }
}

/// Format a context window size for display, e.g. 200000 → "200k", 1048576 → "1M".
pub fn format_context_window(tokens: Option<u64>) -> String {
    match tokens {
        None => "—".to_string(),
        Some(n) if n >= 1_000_000 => {
            let m = n as f64 / 1_000_000.0;
            if m == m.floor() {
                format!("{}M", m as u64)
            } else {
                format!("{:.1}M", m)
            }
        }
        Some(n) if n >= 1_000 => {
            let k = n as f64 / 1_000.0;
            if k == k.floor() {
                format!("{}k", k as u64)
            } else {
                format!("{:.1}k", k)
            }
        }
        Some(n) => n.to_string(),
    }
}
