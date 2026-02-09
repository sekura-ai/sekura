use crate::cli::commands::StartArgs;
use crate::config::{self, SekuraConfig, Intensity, ContainerConfig, LLMConfig};
use crate::errors::SekuraError;
use crate::pipeline::orchestrator::PipelineOrchestrator;
use crate::pipeline::state::PipelineConfig;
use std::path::PathBuf;
use tracing::info;

pub async fn handle_start(args: StartArgs) -> Result<(), SekuraError> {
    info!(target = %args.target, repo = %args.repo, "Starting penetration test");

    // Parse config file if provided
    let file_config = if let Some(config_path) = &args.config {
        Some(config::parse_config(&PathBuf::from(config_path)).await?)
    } else {
        None
    };

    // Build pipeline config from CLI args + file config
    let pipeline_config = build_pipeline_config(&args, file_config.as_ref())?;

    // Create and run orchestrator
    let orchestrator = PipelineOrchestrator::new(pipeline_config).await?;
    let summary = orchestrator.run().await?;

    info!(
        total_findings = summary.total_findings,
        cost_usd = summary.total_cost_usd,
        duration_ms = summary.total_duration_ms,
        "Scan completed"
    );

    Ok(())
}

fn build_pipeline_config(args: &StartArgs, file_config: Option<&SekuraConfig>) -> Result<PipelineConfig, SekuraError> {
    let intensity = match args.intensity.as_str() {
        "quick" => Intensity::Quick,
        "standard" => Intensity::Standard,
        "thorough" => Intensity::Thorough,
        other => return Err(SekuraError::Config(format!("Invalid intensity: {}", other))),
    };

    let api_key = args.api_key.clone()
        .or_else(|| file_config.and_then(|c| c.llm.as_ref()?.api_key.clone()))
        .or_else(|| resolve_api_key_from_env(&args.provider));

    let scan_id = args.scan_id.clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    Ok(PipelineConfig {
        scan_id,
        target: args.target.clone(),
        repo_path: PathBuf::from(&args.repo),
        output_dir: PathBuf::from(&args.output),
        intensity,
        provider: args.provider.clone(),
        model: args.model.clone(),
        api_key: api_key.unwrap_or_default(),
        base_url: args.base_url.clone(),
        skip_whitebox: args.skip_whitebox || args.blackbox_only,
        skip_blackbox: args.skip_blackbox || args.whitebox_only,
        skip_exploit: args.skip_exploit,
        blackbox_only: args.blackbox_only,
        whitebox_only: args.whitebox_only,
        layers: args.layers.as_ref().map(|l| l.split(',').map(|s| s.trim().to_string()).collect()),
        username: args.username.clone(),
        password: args.password.clone(),
        cookie: args.cookie.clone(),
        login_url: args.login_url.clone(),
        no_auth: args.no_auth,
        pipeline_testing: args.pipeline_testing,
        rebuild: args.rebuild,
        max_retries: 5,
        max_agent_iterations: 5,
        container_config: ContainerConfig::default(),
    })
}

fn resolve_api_key_from_env(provider: &str) -> Option<String> {
    let var_name = match provider {
        "anthropic" => "ANTHROPIC_API_KEY",
        "openai" => "OPENAI_API_KEY",
        "gemini" => "GEMINI_API_KEY",
        "openrouter" => "OPENROUTER_API_KEY",
        _ => return None,
    };
    std::env::var(var_name).ok()
}
