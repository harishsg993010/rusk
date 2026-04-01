//! `rusk publish` command.
//!
//! Publishes a package to a registry, generating provenance
//! attestations and signing the artifact.

use clap::Args;
use miette::Result;
use rusk_orchestrator::config::OrchestratorConfig;

/// Arguments for the publish command.
#[derive(Debug, Args)]
pub struct PublishArgs {
    /// Registry URL to publish to (default: from manifest).
    #[arg(long)]
    pub registry: Option<String>,

    /// Dry-run: build and validate but don't actually publish.
    #[arg(long)]
    pub dry_run: bool,

    /// Sign the package with the given identity.
    #[arg(long)]
    pub sign: bool,
}

pub async fn run(args: PublishArgs) -> Result<()> {
    tracing::info!(
        registry = ?args.registry,
        dry_run = args.dry_run,
        "starting publish"
    );

    let project_dir = std::env::current_dir()
        .map_err(|e| miette::miette!("failed to get current directory: {}", e))?;

    let config = OrchestratorConfig::for_project(project_dir);

    // Load manifest
    let manifest_path = config.manifest_path();
    if !manifest_path.exists() {
        crate::output::print_error("rusk.toml not found. Run 'rusk init' to create a project.");
        return Err(miette::miette!("rusk.toml not found"));
    }

    let content = std::fs::read_to_string(&manifest_path)
        .map_err(|e| miette::miette!("failed to read manifest: {}", e))?;
    let manifest = rusk_manifest::parse_manifest(&content)
        .map_err(|e| miette::miette!("failed to parse manifest: {}", e))?;

    let pkg_name = &manifest.package.name;
    let pkg_version = manifest
        .package
        .version
        .as_deref()
        .unwrap_or("0.0.0");

    let registry = args
        .registry
        .as_deref()
        .unwrap_or(manifest.package.ecosystem.default_registry_url());

    crate::output::print_info(&format!("Package: {pkg_name}@{pkg_version}"));
    crate::output::print_info(&format!("Registry: {registry}"));
    crate::output::print_info(&format!("Ecosystem: {}", manifest.package.ecosystem.display_name()));

    if args.dry_run {
        crate::output::print_info("Dry run mode: validating package...");

        // Validate the package
        match rusk_manifest::validate_manifest(&manifest) {
            Ok(warnings) => {
                for warning in &warnings {
                    crate::output::print_warning(&format!("  {}: {}", warning.path, warning.message));
                }
            }
            Err(e) => {
                crate::output::print_error("Package validation failed:");
                for issue in &e.issues {
                    crate::output::print_error(&format!("  {}: {}", issue.path, issue.message));
                }
                return Err(miette::miette!("package validation failed"));
            }
        }

        crate::output::print_success(&format!(
            "publish dry-run complete: {pkg_name}@{pkg_version} is valid"
        ));
        return Ok(());
    }

    // Actual publish is not yet supported for most registries
    crate::output::print_warning(
        "Publishing to registries is not yet supported in this version of rusk."
    );
    crate::output::print_info(
        "This feature requires registry-specific authentication and API integration."
    );
    crate::output::print_info(
        "Please use the native tools (npm publish, twine upload) for now."
    );

    Ok(())
}
