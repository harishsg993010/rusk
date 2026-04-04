//! rusk CLI entry point.
//!
//! Parses command-line arguments using clap derive and dispatches
//! to the appropriate subcommand handler.

mod cli_config;
mod commands;
mod output;

use clap::Parser;
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

    /// Print all structured exit codes and exit.
    #[arg(long, global = true)]
    pub exit_codes: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
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
    /// Remove packages from the manifest and uninstall them.
    Remove(commands::remove::RemoveArgs),
    /// Display the dependency tree from the lockfile.
    Tree(commands::tree::TreeArgs),
    /// Run a command with the correct ecosystem environment.
    Run(commands::run::RunArgs),
    /// Resolve dependencies and write rusk.lock without installing.
    Lock(commands::lock::LockArgs),
    /// Install from lockfile and remove extraneous packages.
    Sync(commands::sync::SyncArgs),
    /// Create a Python virtual environment.
    Venv(commands::venv::VenvArgs),
    /// List installed packages with versions.
    List(commands::list::ListArgs),
    /// Manage Python installations (list, find, pin).
    Python(commands::python::PythonArgs),
    /// Manage isolated CLI tools (like uvx / pipx).
    Tool(commands::tool::ToolArgs),
    /// Import dependencies from package-lock.json, yarn.lock, or pnpm-lock.yaml.
    Migrate(commands::migrate::MigrateArgs),
    /// Shorthand for `rusk tool run` (like uvx).
    #[command(name = "x")]
    X(commands::tool::ToolRunArgs),
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Handle --exit-codes before anything else.
    if cli.exit_codes {
        output::print_exit_codes(cli.format);
        std::process::exit(0);
    }

    // A subcommand is required unless --exit-codes was passed.
    let command = match cli.command {
        Some(cmd) => cmd,
        None => {
            // Re-parse to trigger clap's "missing subcommand" error message.
            let _ = Cli::parse_from(["rusk", "--help"]);
            std::process::exit(1);
        }
    };

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

    let fmt = cli.format;

    let result = match command {
        Commands::Install(args) => commands::install::run(args, fmt).await,
        Commands::Update(args) => commands::update::run(args).await,
        Commands::Verify(args) => commands::verify::run(args, fmt).await,
        Commands::Audit(args) => commands::audit::run(args, fmt).await,
        Commands::Build(args) => commands::build::run(args).await,
        Commands::Publish(args) => commands::publish::run(args).await,
        Commands::Explain(args) => commands::explain::run(args).await,
        Commands::Gc(args) => commands::gc::run(args).await,
        Commands::Init(args) => commands::init::run(args).await,
        Commands::Config(args) => commands::config::run(args).await,
        Commands::Add(args) => commands::add::run(args).await,
        Commands::Remove(args) => commands::remove::run(args).await,
        Commands::Tree(args) => commands::tree::run(args).await,
        Commands::Run(args) => commands::run::run(args).await,
        Commands::Lock(args) => commands::lock::run(args, fmt).await,
        Commands::Sync(args) => commands::sync::run(args, fmt).await,
        Commands::Venv(args) => commands::venv::run(args).await,
        Commands::List(args) => commands::list::run(args, fmt).await,
        Commands::Python(args) => commands::python::run(args).await,
        Commands::Migrate(args) => commands::migrate::run(args, fmt).await,
        Commands::Tool(args) => commands::tool::run(args).await,
        Commands::X(args) => commands::tool::run_x(args).await,
    };

    match result {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            // miette errors already printed by the command handlers;
            // just extract the exit code and terminate.
            eprintln!("{e:?}");
            std::process::exit(1);
        }
    }
}
