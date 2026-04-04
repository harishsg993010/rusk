//! `rusk sync` command.
//!
//! Installs exactly what's in rusk.lock and removes any extra packages
//! from node_modules/ or site-packages/ that are NOT in the lockfile.

use clap::Args;
use miette::Result;
use rusk_orchestrator::config::OrchestratorConfig;
use std::collections::HashSet;
use std::time::Instant;

/// Arguments for the sync command.
#[derive(Debug, Args)]
pub struct SyncArgs {
    /// Only sync production dependencies (skip dev).
    #[arg(long)]
    pub production: bool,

    /// Frozen mode: fail if lockfile is out of date instead of updating it.
    #[arg(long)]
    pub frozen: bool,
}

pub async fn run(args: SyncArgs, format: crate::output::OutputFormat) -> Result<()> {
    let start = Instant::now();
    let json_output = format == crate::output::OutputFormat::Json;

    tracing::info!(
        frozen = args.frozen,
        production = args.production,
        "starting sync"
    );

    let project_dir = std::env::current_dir()
        .map_err(|e| miette::miette!("failed to get current directory: {}", e))?;

    let mut config = OrchestratorConfig::for_project(project_dir);
    config.frozen = args.frozen;
    config.include_dev = !args.production;

    // Create a spinner for progress (suppressed in JSON mode)
    let spinner = if json_output {
        indicatif::ProgressBar::hidden()
    } else {
        crate::output::create_spinner("Syncing dependencies...")
    };
    let spinner_clone = spinner.clone();

    let on_progress: Box<dyn Fn(&str) + Send + Sync> = Box::new(move |msg: &str| {
        spinner_clone.set_message(msg.to_string());
    });

    // Run install (resolve + download + materialize + write lockfile)
    let result = rusk_orchestrator::run_install(&config, Some(on_progress)).await;

    spinner.finish_and_clear();

    match result {
        Ok(install_result) => {
            // After install completes, clean up extras not in the lockfile
            let lockfile_path = config.lockfile_path();
            let mut removed_count = 0usize;

            if lockfile_path.exists() {
                if let Ok(lockfile) = rusk_lockfile::load_lockfile(&lockfile_path) {
                    let locked_names: HashSet<String> = lockfile
                        .packages
                        .values()
                        .map(|p| p.package.display_name())
                        .collect();

                    // Clean up node_modules/
                    let node_modules = config.node_modules_path();
                    if node_modules.exists() {
                        if let Ok(entries) = std::fs::read_dir(&node_modules) {
                            for entry in entries.flatten() {
                                let name = entry.file_name().to_string_lossy().to_string();
                                if !name.starts_with('.') && !locked_names.contains(&name) {
                                    if let Ok(ft) = entry.file_type() {
                                        if ft.is_dir() {
                                            let _ = std::fs::remove_dir_all(entry.path());
                                            if !json_output {
                                                crate::output::print_info(
                                                    &format!("  Removed {name} (not in lockfile)"),
                                                );
                                            }
                                            removed_count += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Clean up site-packages/
                    let site_packages = config.site_packages_path();
                    if site_packages.exists() {
                        // Build a set of normalized Python package names from lockfile
                        let locked_python_names: HashSet<String> = lockfile
                            .packages
                            .values()
                            .filter(|p| p.ecosystem == rusk_core::Ecosystem::Python)
                            .map(|p| normalize_python_name(&p.package.display_name()))
                            .collect();

                        if let Ok(entries) = std::fs::read_dir(&site_packages) {
                            for entry in entries.flatten() {
                                let name = entry.file_name().to_string_lossy().to_string();
                                // Skip hidden dirs, __pycache__, *.dist-info, etc.
                                if name.starts_with('.')
                                    || name.starts_with('_')
                                    || name.ends_with(".dist-info")
                                    || name.ends_with(".egg-info")
                                {
                                    continue;
                                }

                                let normalized = normalize_python_name(&name);
                                if !locked_python_names.contains(&normalized) {
                                    if let Ok(ft) = entry.file_type() {
                                        if ft.is_dir() {
                                            let _ = std::fs::remove_dir_all(entry.path());
                                            if !json_output {
                                                crate::output::print_info(
                                                    &format!("  Removed {name} (not in lockfile)"),
                                                );
                                            }
                                            removed_count += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let elapsed = start.elapsed();

            if json_output {
                let output = serde_json::json!({
                    "status": "success",
                    "resolved": install_result.resolved,
                    "downloaded": install_result.downloaded,
                    "cached": install_result.cached,
                    "materialized": install_result.materialized,
                    "removed": removed_count,
                    "elapsed_ms": elapsed.as_millis() as u64,
                });
                println!("{}", serde_json::to_string_pretty(&output).unwrap_or_default());
            } else if install_result.resolved == 0 && removed_count == 0 {
                crate::output::print_success("Already in sync.");
            } else {
                let summary = format!(
                    "Synced {} packages in {:.1}s",
                    install_result.materialized,
                    elapsed.as_secs_f64()
                );
                crate::output::print_success(&summary);

                if removed_count > 0 {
                    crate::output::print_info(
                        &format!("  Removed {} extraneous packages", removed_count),
                    );
                }
            }

            Ok(())
        }
        Err(e) => {
            let exit_code = e.exit_code();
            if json_output {
                let output = serde_json::json!({
                    "status": "error",
                    "exit_code": exit_code.as_i32(),
                    "exit_code_name": exit_code.code_name(),
                    "error": format!("{}", e),
                });
                println!("{}", serde_json::to_string_pretty(&output).unwrap_or_default());
                std::process::exit(exit_code.as_i32());
            } else {
                crate::output::print_error(&format!("Sync failed: {}", e));
                Err(miette::miette!("{}", e))
            }
        }
    }
}

/// Normalize a Python package name for comparison.
/// PEP 503: lowercase, replace [-_.] with a single hyphen.
fn normalize_python_name(name: &str) -> String {
    name.to_lowercase()
        .replace(['-', '_', '.'], "-")
}
