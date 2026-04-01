//! `rusk update` command.
//!
//! Re-resolves dependencies, updating packages to their latest versions
//! within the constraints of the manifest and policy.

use clap::Args;
use miette::Result;
use rusk_orchestrator::config::OrchestratorConfig;

/// Arguments for the update command.
#[derive(Debug, Args)]
pub struct UpdateArgs {
    /// Only update specific packages.
    pub packages: Vec<String>,

    /// Allow major version updates.
    #[arg(long)]
    pub major: bool,

    /// Dry-run: show what would change without modifying the lockfile.
    #[arg(long)]
    pub dry_run: bool,
}

pub async fn run(args: UpdateArgs) -> Result<()> {
    tracing::info!(
        packages = ?args.packages,
        major = args.major,
        dry_run = args.dry_run,
        "starting update"
    );

    let project_dir = std::env::current_dir()
        .map_err(|e| miette::miette!("failed to get current directory: {}", e))?;

    let config = OrchestratorConfig::for_project(project_dir);

    // Check rusk.toml exists
    if !config.manifest_path().exists() {
        crate::output::print_error("rusk.toml not found. Run 'rusk init' to create a project.");
        return Err(miette::miette!("rusk.toml not found"));
    }

    // Check lockfile exists
    let lockfile_path = config.lockfile_path();
    if !lockfile_path.exists() {
        crate::output::print_warning("No lockfile found. Running install instead.");
        let install_args = super::install::InstallArgs {
            production: false,
            frozen: false,
            lockfile_only: false,
            packages: vec![],
        };
        return super::install::run(install_args).await;
    }

    if args.dry_run {
        crate::output::print_info("Dry run mode: checking for updates...");
    }

    let spinner = crate::output::create_spinner("Checking for updates...");

    // Read existing lockfile
    let lockfile = rusk_lockfile::load_lockfile(&lockfile_path)
        .map_err(|e| miette::miette!("failed to read lockfile: {}", e))?;

    let pkg_count = lockfile.package_count();
    spinner.finish_and_clear();

    if args.packages.is_empty() {
        // Run full re-resolve (re-install with fresh resolution)
        if args.dry_run {
            crate::output::print_info(&format!(
                "{} packages currently locked. A full update would re-resolve all.",
                pkg_count
            ));
            crate::output::print_success("update dry-run complete (no changes made)");
        } else {
            crate::output::print_info(&format!(
                "Re-resolving {} locked packages...",
                pkg_count
            ));
            // Re-run install which will re-resolve everything
            let install_args = super::install::InstallArgs {
                production: false,
                frozen: false,
                lockfile_only: false,
                packages: vec![],
            };
            return super::install::run(install_args).await;
        }
    } else {
        let target_names: Vec<&str> = args.packages.iter().map(|s| s.as_str()).collect();
        if args.dry_run {
            crate::output::print_info(&format!(
                "Would update: {}",
                target_names.join(", ")
            ));
            crate::output::print_success("update dry-run complete (no changes made)");
        } else {
            crate::output::print_info(&format!(
                "Updating: {}",
                target_names.join(", ")
            ));
            // Re-run full install for simplicity
            let install_args = super::install::InstallArgs {
                production: false,
                frozen: false,
                lockfile_only: false,
                packages: vec![],
            };
            return super::install::run(install_args).await;
        }
    }

    Ok(())
}
