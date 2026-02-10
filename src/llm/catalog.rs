pub struct ProviderInfo {
    pub id: &'static str,
    pub name: &'static str,
    pub env_var: &'static str,
    pub models: &'static [ModelInfo],
}

pub struct ModelInfo {
    pub id: &'static str,
    pub label: &'static str,
    pub context_window: &'static str,
    pub recommended: bool,
}

pub static PROVIDERS: &[ProviderInfo] = &[
    ProviderInfo {
        id: "anthropic",
        name: "Anthropic",
        env_var: "ANTHROPIC_API_KEY",
        models: &[
            ModelInfo { id: "claude-sonnet-4-5-20250929", label: "Claude 4.5 Sonnet", context_window: "200k", recommended: true },
            ModelInfo { id: "claude-opus-4-6", label: "Claude Opus 4.6", context_window: "200k", recommended: false },
            ModelInfo { id: "claude-3-5-haiku-20241022", label: "Claude 3.5 Haiku", context_window: "200k", recommended: false },
        ],
    },
    ProviderInfo {
        id: "openai",
        name: "OpenAI",
        env_var: "OPENAI_API_KEY",
        models: &[
            ModelInfo { id: "gpt-4o", label: "GPT-4o", context_window: "128k", recommended: true },
            ModelInfo { id: "gpt-4o-mini", label: "GPT-4o Mini", context_window: "128k", recommended: false },
            ModelInfo { id: "o3", label: "o3", context_window: "200k", recommended: false },
            ModelInfo { id: "o4-mini", label: "o4-mini", context_window: "200k", recommended: false },
        ],
    },
    ProviderInfo {
        id: "gemini",
        name: "Google Gemini",
        env_var: "GEMINI_API_KEY",
        models: &[
            ModelInfo { id: "gemini-2.5-flash", label: "Gemini 2.5 Flash", context_window: "1M", recommended: true },
            ModelInfo { id: "gemini-2.5-pro", label: "Gemini 2.5 Pro", context_window: "1M", recommended: false },
        ],
    },
    ProviderInfo {
        id: "openrouter",
        name: "OpenRouter",
        env_var: "OPENROUTER_API_KEY",
        models: &[
            ModelInfo { id: "anthropic/claude-sonnet-4-5-20250929", label: "Claude 4.5 Sonnet", context_window: "200k", recommended: true },
            ModelInfo { id: "openai/gpt-4o", label: "GPT-4o", context_window: "128k", recommended: false },
            ModelInfo { id: "google/gemini-2.5-flash", label: "Gemini 2.5 Flash", context_window: "1M", recommended: false },
            ModelInfo { id: "deepseek/deepseek-chat-v3", label: "DeepSeek V3", context_window: "64k", recommended: false },
        ],
    },
    ProviderInfo {
        id: "local",
        name: "Local / Ollama",
        env_var: "",
        models: &[
            ModelInfo { id: "qwen2.5-coder:1.5b", label: "Qwen 2.5 Coder 1.5B", context_window: "32k", recommended: true },
        ],
    },
];

pub fn get_provider(id: &str) -> Option<&'static ProviderInfo> {
    PROVIDERS.iter().find(|p| p.id == id)
}

pub fn get_default_model(provider_id: &str) -> &'static str {
    if let Some(provider) = get_provider(provider_id) {
        provider.models.iter()
            .find(|m| m.recommended)
            .map(|m| m.id)
            .unwrap_or(provider.models[0].id)
    } else {
        "claude-sonnet-4-5-20250929"
    }
}
