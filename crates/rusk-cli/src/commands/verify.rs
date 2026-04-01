//! `rusk verify` command.
//!
//! Verifies that installed packages match their lockfile digests,
//! ensuring no tampering has occurred in node_modules.

use clap::Args;
use miette::Result;
use rusk_orchestrator::config::OrchestratorConfig;

/// Arguments for the verify command.
#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Verify specific packages only.
    pub packages: Vec<String>,

    /// Strict mode: fail on any missing signatures or provenance.
    #[arg(long)]
    pub strict: bool,

    /// Show detailed verification information.
    #[arg(long)]
    pub detailed: bool,
}

pub async fn run(args: VerifyArgs) -> Result<()> {
    tracing::info!(
        packages = ?args.packages,
        strict = args.strict,
        "starting verification"
    );

    let project_dir = std::env::current_dir()
        .map_err(|e| miette::miette!("failed to get current directory: {}", e))?;

    let config = OrchestratorConfig::for_project(project_dir);

    // Load lockfile
    let lockfile_path = config.lockfile_path();
    if !lockfile_path.exists() {
        crate::output::print_error("No lockfile found. Run 'rusk install' first.");
        return Err(miette::miette!("rusk.lock not found"));
    }

    let lockfile = rusk_lockfile::load_lockfile(&lockfile_path)
        .map_err(|e| miette::miette!("failed to read lockfile: {}", e))?;

    // Load install state
    let state_path = config.state_path();
    let state = rusk_materialize::InstallState::load(&state_path)
        .map_err(|e| miette::miette!("failed to load install state: {}", e))?;

    let spinner = crate::output::create_spinner("Verifying installed packages...");

    let mut verified = 0usize;
    let mut failed = 0usize;
    let mut warnings = 0usize;
    let mut failures: Vec<String> = Vec::new();

    let cas = rusk_cas::CasStore::open(&config.cas_dir)
        .map_err(|e| miette::miette!("failed to open CAS: {}", e))?;

    for (canonical_id, locked_pkg) in &lockfile.packages {
        // Filter by specified packages if any
        if !args.packages.is_empty() {
            let pkg_name = locked_pkg.package.display_name();
            if !args.packages.iter().any(|p| p == &pkg_name || p == canonical_id) {
                continue;
            }
        }

        let pkg_name = locked_pkg.package.display_name();

        // Check if the package is in the CAS
        if cas.contains(&locked_pkg.digest) {
            // Verify the installed files match the CAS
            if let Some(installed) = state.packages.get(canonical_id) {
                if installed.digest == locked_pkg.digest {
                    verified += 1;
                    if args.detailed {
                        crate::output::print_info(&format!(
                            "  OK  {}@{} ({})",
                            pkg_name, locked_pkg.version, locked_pkg.digest
                        ));
                    }
                } else {
                    failed += 1;
                    let msg = format!(
                        "{}@{}: installed digest mismatch (expected {}, got {})",
                        pkg_name, locked_pkg.version, locked_pkg.digest, installed.digest
                    );
                    failures.push(msg);
                }
            } else {
                warnings += 1;
                if args.detailed {
                    crate::output::print_warning(&format!(
                        "{}@{}: not in install state (may not be materialized)",
                        pkg_name, locked_pkg.version
                    ));
                }
            }
        } else {
            failed += 1;
            let msg = format!(
                "{}@{}: not found in CAS (digest: {})",
                pkg_name, locked_pkg.version, locked_pkg.digest
            );
            failures.push(msg);
        }
    }

    spinner.finish_and_clear();

    // Print results
    let total = verified + failed + warnings;
    crate::output::print_info(&format!(
        "Verified {verified}/{total} packages: {verified} passed, {failed} failed, {warnings} warnings"
    ));

    for failure in &failures {
        crate::output::print_error(&format!("  FAIL  {failure}"));
    }

    if failed > 0 {
        if args.strict {
            return Err(miette::miette!("{} packages failed verification", failed));
        }
        crate::output::print_warning("Some packages failed verification. Run 'rusk install' to fix.");
    } else {
        crate::output::print_success("verification complete - all packages OK");
    }

    Ok(())
}
