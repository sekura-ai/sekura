mod cli;
mod api;
mod pipeline;
mod agents;
mod llm;
mod container;
mod techniques;
mod whitebox;
mod browser;
mod queue;
mod session;
mod audit;
mod auth;
mod config;
mod reporting;
mod git;
mod errors;
mod db;
mod models;
mod utils;

use clap::Parser;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    let cli = cli::Cli::parse();

    // Initialize logging
    let log_level = match cli.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_ansi(!cli.no_color)
        .init();

    let result = match cli.command {
        cli::Commands::Start(args) => cli::start::handle_start(args).await,
        cli::Commands::Scan(args) => cli::scan::handle_scan(args).await,
        cli::Commands::Serve(args) => cli::serve::handle_serve(args).await,
        cli::Commands::Query(args) => cli::query::handle_query(args).await,
        cli::Commands::Logs(args) => cli::logs::handle_logs(args).await,
        cli::Commands::Stop(args) => cli::stop::handle_stop(args).await,
        cli::Commands::Validate(args) => handle_validate(args).await,
    };

    match result {
        Ok(()) => {}
        Err(e) => {
            eprintln!("Error: {}", e);
            let exit_code = match &e {
                errors::SekuraError::Config(_) => 2,
                errors::SekuraError::Container(_) => 3,
                errors::SekuraError::Authentication(_) => 4,
                errors::SekuraError::InvalidTarget(_) => 5,
                _ => 1,
            };
            std::process::exit(exit_code);
        }
    }
}

async fn handle_validate(args: cli::commands::ValidateArgs) -> Result<(), errors::SekuraError> {
    let path = std::path::PathBuf::from(&args.config);
    let _config = config::parse_config(&path).await?;
    println!("Configuration is valid: {}", args.config);
    Ok(())
}
