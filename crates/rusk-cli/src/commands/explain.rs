//! `rusk explain` command.
//!
//! Shows why a specific policy decision was made for a package,
//! displaying the evaluation trace and matched rules.

use clap::Args;
use miette::Result;
use rusk_orchestrator::config::OrchestratorConfig;

/// Arguments for the explain command.
#[derive(Debug, Args)]
pub struct ExplainArgs {
    /// The package to explain the policy decision for.
    pub package: String,

    /// Show the full evaluation trace (verbose).
    #[arg(long)]
    pub trace: bool,
}

pub async fn run(args: ExplainArgs) -> Result<()> {
    tracing::info!(package = %args.package, "explaining policy decision");

    let project_dir = std::env::current_dir()
        .map_err(|e| miette::miette!("failed to get current directory: {}", e))?;

    let config = OrchestratorConfig::for_project(project_dir);

    // Load lockfile to find the package
    let lockfile_path = config.lockfile_path();
    if !lockfile_path.exists() {
        crate::output::print_error("No lockfile found. Run 'rusk install' first.");
        return Err(miette::miette!("rusk.lock not found"));
    }

    let lockfile = rusk_lockfile::load_lockfile(&lockfile_path)
        .map_err(|e| miette::miette!("failed to read lockfile: {}", e))?;

    // Load manifest for trust config
    let manifest_path = config.manifest_path();
    let trust_config = if manifest_path.exists() {
        let content = std::fs::read_to_string(&manifest_path)
            .map_err(|e| miette::miette!("failed to read manifest: {}", e))?;
        let manifest = rusk_manifest::parse_manifest(&content)
            .map_err(|e| miette::miette!("failed to parse manifest: {}", e))?;
        manifest.trust
    } else {
        None
    };

    // Find the package in the lockfile
    let target_name = &args.package;
    let found_pkg = lockfile.packages.iter().find(|(_, pkg)| {
        pkg.package.display_name() == *target_name || pkg.package.name == *target_name
    });

    match found_pkg {
        Some((_canonical_id, locked_pkg)) => {
            let pkg_name = locked_pkg.package.display_name();
            let version = &locked_pkg.version;

            println!();
            crate::output::print_info(&format!("Package: {pkg_name}@{version}"));
            crate::output::print_info(&format!("Ecosystem: {}", locked_pkg.ecosystem));
            crate::output::print_info(&format!("Digest: {}", locked_pkg.digest));

            if let Some(ref url) = locked_pkg.source_url {
                crate::output::print_info(&format!("Source: {url}"));
            }

            println!();
            crate::output::print_info("Policy evaluation:");

            // Determine the verdict
            let mut verdict = "ALLOW";
            let mut reasons: Vec<String> = Vec::new();

            // Check trust configuration
            if let Some(ref tc) = trust_config {
                if tc.require_signatures {
                    if locked_pkg.signer.is_some() {
                        reasons.push("  + Package is signed (required by policy)".to_string());
                    } else {
                        verdict = "WARN";
                        reasons.push("  ! Package is NOT signed (signatures required by policy)".to_string());
                    }
                } else {
                    reasons.push("  - Signatures not required by policy".to_string());
                }

                if tc.require_provenance {
                    reasons.push("  ! Provenance required but not checked (not yet implemented)".to_string());
                }

                if !tc.trusted_signers.is_empty() {
                    if let Some(ref signer) = locked_pkg.signer {
                        if tc.trusted_signers.contains(&signer.identity) {
                            reasons.push(format!("  + Signer '{}' is in trusted signers list", signer.identity));
                        } else {
                            verdict = "WARN";
                            reasons.push(format!("  ! Signer '{}' is NOT in trusted signers list", signer.identity));
                        }
                    }
                }
            } else {
                reasons.push("  - No trust policy configured (default: allow all)".to_string());
            }

            // Check digest
            if locked_pkg.digest == rusk_core::Sha256Digest::zero() {
                verdict = "WARN";
                reasons.push("  ! Package has zero digest (integrity not verified)".to_string());
            } else {
                reasons.push("  + Package has valid digest".to_string());
            }

            for reason in &reasons {
                println!("{reason}");
            }

            println!();
            match verdict {
                "ALLOW" => crate::output::print_success(&format!("Verdict: {verdict} - package is trusted")),
                "WARN" => crate::output::print_warning(&format!("Verdict: {verdict} - package has trust warnings")),
                "DENY" => crate::output::print_error(&format!("Verdict: {verdict} - package is blocked by policy")),
                _ => {}
            }

            if args.trace {
                println!();
                crate::output::print_info("Full evaluation trace:");
                crate::output::print_info(&format!("  1. Load trust config from rusk.toml"));
                crate::output::print_info(&format!("  2. Look up {pkg_name}@{version} in lockfile"));
                crate::output::print_info(&format!("  3. Check signature requirement: {}", trust_config.as_ref().map_or("N/A", |t| if t.require_signatures { "required" } else { "not required" })));
                crate::output::print_info(&format!("  4. Check provenance requirement: {}", trust_config.as_ref().map_or("N/A", |t| if t.require_provenance { "required" } else { "not required" })));
                crate::output::print_info(&format!("  5. Check digest integrity: {}", if locked_pkg.digest != rusk_core::Sha256Digest::zero() { "OK" } else { "MISSING" }));
                crate::output::print_info(&format!("  6. Final verdict: {verdict}"));
            }
        }
        None => {
            crate::output::print_error(&format!(
                "Package '{}' not found in the lockfile. Is it installed?",
                target_name
            ));
            crate::output::print_info("Installed packages:");
            for (_id, pkg) in &lockfile.packages {
                crate::output::print_info(&format!(
                    "  {}@{}",
                    pkg.package.display_name(),
                    pkg.version
                ));
            }
        }
    }

    Ok(())
}
