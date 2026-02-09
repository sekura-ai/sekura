use clap::{Parser, Subcommand, Args};

#[derive(Parser)]
#[command(name = "sekura", version, about = "Autonomous AI Penetration Testing Agent")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Increase log verbosity (repeat for more)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Suppress non-essential output
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Disable colored output
    #[arg(long, global = true)]
    pub no_color: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start a penetration test
    Start(StartArgs),
    /// Run scan without web UI (headless)
    Scan(StartArgs),
    /// Start the HTTP REST API server
    Serve(ServeArgs),
    /// Query a running scan's progress
    Query(QueryArgs),
    /// Stream scan execution logs
    Logs(LogsArgs),
    /// Stop containers and/or running scans
    Stop(StopArgs),
    /// Validate a configuration file
    Validate(ValidateArgs),
}

#[derive(Args, Clone)]
pub struct StartArgs {
    /// Target web application URL
    #[arg(short, long)]
    pub target: String,

    /// Path to target source code repository
    #[arg(short, long)]
    pub repo: String,

    /// YAML configuration file
    #[arg(short, long)]
    pub config: Option<String>,

    /// Output directory for results
    #[arg(short, long, default_value = "./results")]
    pub output: String,

    /// Scan intensity: quick, standard, thorough
    #[arg(long, default_value = "standard")]
    pub intensity: String,

    /// LLM provider: anthropic, openai, gemini, openrouter, local
    #[arg(long, default_value = "anthropic")]
    pub provider: String,

    /// LLM model identifier
    #[arg(long)]
    pub model: Option<String>,

    /// LLM API key (or use env vars)
    #[arg(long)]
    pub api_key: Option<String>,

    /// Local LLM endpoint
    #[arg(long, default_value = "http://localhost:11434/v1")]
    pub base_url: String,

    /// Skip source code analysis phase
    #[arg(long)]
    pub skip_whitebox: bool,

    /// Skip tool-based scanning phase
    #[arg(long)]
    pub skip_blackbox: bool,

    /// Skip exploitation phase
    #[arg(long)]
    pub skip_exploit: bool,

    /// Only run tool-based scanning
    #[arg(long)]
    pub blackbox_only: bool,

    /// Only run source code analysis
    #[arg(long)]
    pub whitebox_only: bool,

    /// Comma-separated OSI layers to scan
    #[arg(long)]
    pub layers: Option<String>,

    /// Web app username for authenticated scanning
    #[arg(long)]
    pub username: Option<String>,

    /// Web app password
    #[arg(long)]
    pub password: Option<String>,

    /// Pre-set session cookie string
    #[arg(long)]
    pub cookie: Option<String>,

    /// Explicit login URL
    #[arg(long)]
    pub login_url: Option<String>,

    /// Skip authentication entirely
    #[arg(long)]
    pub no_auth: bool,

    /// Use minimal prompts for fast pipeline validation
    #[arg(long)]
    pub pipeline_testing: bool,

    /// Force Docker image rebuild
    #[arg(long)]
    pub rebuild: bool,

    /// Block and poll progress until completion
    #[arg(long)]
    pub wait: bool,

    /// Custom scan identifier
    #[arg(long)]
    pub scan_id: Option<String>,
}

#[derive(Args, Clone)]
pub struct ServeArgs {
    /// Listen port
    #[arg(long, default_value = "8080")]
    pub port: u16,

    /// Listen address
    #[arg(long, default_value = "0.0.0.0")]
    pub host: String,

    /// SQLite database path
    #[arg(long, default_value = "./data/sekura.db")]
    pub db: String,

    /// Max concurrent scans
    #[arg(long, default_value = "3")]
    pub workers: usize,
}

#[derive(Args, Clone)]
pub struct QueryArgs {
    /// Scan ID to query
    pub scan_id: String,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Continuously poll until completion
    #[arg(long)]
    pub follow: bool,

    /// Poll interval in seconds
    #[arg(long, default_value = "10")]
    pub interval: u64,
}

#[derive(Args, Clone)]
pub struct LogsArgs {
    /// Scan ID
    pub scan_id: String,

    /// Follow log output
    #[arg(short, long)]
    pub follow: bool,

    /// Number of lines to show
    #[arg(short, long, default_value = "100")]
    pub lines: usize,
}

#[derive(Args, Clone)]
pub struct StopArgs {
    /// Scan ID to stop (omit to stop all)
    pub scan_id: Option<String>,

    /// Also remove containers
    #[arg(long)]
    pub remove: bool,
}

#[derive(Args, Clone)]
pub struct ValidateArgs {
    /// Config file to validate
    pub config: String,
}
