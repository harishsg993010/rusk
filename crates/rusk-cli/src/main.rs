//! rusk CLI entry point.
//!
//! Parses command-line arguments using clap derive and dispatches
//! to the appropriate subcommand handler.

mod cli_config;
mod commands;
mod output;

use clap::Parser;
use miette::Result;
use tracing::info;

/// rusk -- a trust-aware, supply-chain-hardened package manager.
#[derive(Debug, Parser)]
#[command(name = "rusk", version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    /// Enable verbose output (repeat for more: -vv, -vvv).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Suppress all output except errors.
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Output format: text or json.
    #[arg(long, default_value = "text", global = true)]
    pub format: output::OutputFormat,

    /// Path to rusk configuration file.
    #[arg(long, global = true)]
    pub config: Option<std::path::PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

/// Top-level subcommands.
#[derive(Debug, clap::Subcommand)]
pub enum Commands {
    /// Install dependencies from the manifest and lockfile.
    Install(commands::install::InstallArgs),
    /// Update dependencies to their latest allowed versions.
    Update(commands::update::UpdateArgs),
    /// Verify signatures, provenance, and trust state of installed packages.
    Verify(commands::verify::VerifyArgs),
    /// Audit the dependency tree for policy violations and known vulnerabilities.
    Audit(commands::audit::AuditArgs),
    /// Run a build script in a sandboxed environment.
    Build(commands::build::BuildArgs),
    /// Publish a package to a registry.
    Publish(commands::publish::PublishArgs),
    /// Explain why a policy decision was made.
    Explain(commands::explain::ExplainArgs),
    /// Run garbage collection on the content-addressed store.
    Gc(commands::gc::GcArgs),
    /// Initialize a new rusk project.
    Init(commands::init::InitArgs),
    /// View or modify rusk configuration.
    Config(commands::config::ConfigArgs),
    /// Add a package to the manifest and install it.
    Add(commands::add::AddArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize observability based on verbosity.
    let tracing_config = rusk_observability::TracingConfig {
        filter: match cli.verbose {
            0 => "warn".to_string(),
            1 => "info".to_string(),
            2 => "debug".to_string(),
            _ => "trace".to_string(),
        },
        format: match cli.format {
            output::OutputFormat::Json => rusk_observability::OutputFormat::Json,
            output::OutputFormat::Text => rusk_observability::OutputFormat::Pretty,
        },
        ..Default::default()
    };
    rusk_observability::init_tracing(&tracing_config);

    info!(version = env!("CARGO_PKG_VERSION"), "rusk starting");

    match cli.command {
        Commands::Install(args) => commands::install::run(args).await,
        Commands::Update(args) => commands::update::run(args).await,
        Commands::Verify(args) => commands::verify::run(args).await,
        Commands::Audit(args) => commands::audit::run(args).await,
        Commands::Build(args) => commands::build::run(args).await,
        Commands::Publish(args) => commands::publish::run(args).await,
        Commands::Explain(args) => commands::explain::run(args).await,
        Commands::Gc(args) => commands::gc::run(args).await,
        Commands::Init(args) => commands::init::run(args).await,
        Commands::Config(args) => commands::config::run(args).await,
        Commands::Add(args) => commands::add::run(args).await,
    }
}
