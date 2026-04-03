//! `rusk install` command.
//!
//! Resolves dependencies from the manifest, downloads artifacts,
//! verifies trust, and materializes the dependency tree.

use clap::Args;
use miette::Result;
use rusk_orchestrator::config::OrchestratorConfig;
use std::time::Instant;

/// Arguments for the install command.
#[derive(Debug, Args)]
pub struct InstallArgs {
    /// Only install production dependencies (skip dev).
    #[arg(long)]
    pub production: bool,

    /// Frozen mode: fail if lockfile is out of date instead of updating it.
    #[arg(long)]
    pub frozen: bool,

    /// Lockfile-only mode: install exactly what is in the lockfile without resolving.
    #[arg(long)]
    pub lockfile_only: bool,

    /// Specific packages to install (if empty, installs all from manifest).
    pub packages: Vec<String>,
}

pub async fn run(args: InstallArgs, format: crate::output::OutputFormat) -> Result<()> {
    let start = Instant::now();
    let json_output = format == crate::output::OutputFormat::Json;

    tracing::info!(
        frozen = args.frozen,
        production = args.production,
        packages = ?args.packages,
        "starting install"
    );

    // Build orchestrator config from current directory
    let project_dir = std::env::current_dir()
        .map_err(|e| miette::miette!("failed to get current directory: {}", e))?;

    let mut config = OrchestratorConfig::for_project(project_dir);
    config.frozen = args.frozen;
    config.include_dev = !args.production;

    // Create a spinner for progress (suppressed in JSON mode)
    let spinner = if json_output {
        let pb = indicatif::ProgressBar::hidden();
        pb
    } else {
        crate::output::create_spinner("Resolving dependencies...")
    };
    let spinner_clone = spinner.clone();

    let on_progress: Box<dyn Fn(&str) + Send + Sync> = Box::new(move |msg: &str| {
        spinner_clone.set_message(msg.to_string());
    });

    // Run the install
    let result = rusk_orchestrator::run_install(&config, Some(on_progress)).await;

    spinner.finish_and_clear();

    match result {
        Ok(install_result) => {
            let elapsed = start.elapsed();

            if json_output {
                let output = serde_json::json!({
                    "status": "success",
                    "exit_code": rusk_core::ExitCode::Success.as_i32(),
                    "resolved": install_result.resolved,
                    "downloaded": install_result.downloaded,
                    "cached": install_result.cached,
                    "materialized": install_result.materialized,
                    "elapsed_ms": elapsed.as_millis() as u64,
                    "warnings": [],
                });
                println!("{}", serde_json::to_string_pretty(&output).unwrap_or_default());
            } else {
                // Print summary (human-readable)
                if install_result.resolved == 0 {
                    crate::output::print_success("No dependencies to install.");
                } else {
                    let mut parts: Vec<String> = Vec::new();

                    if install_result.downloaded > 0 {
                        parts.push(format!(
                            "{} downloaded",
                            install_result.downloaded
                        ));
                    }
                    if install_result.cached > 0 {
                        parts.push(format!(
                            "{} cached",
                            install_result.cached
                        ));
                    }

                    let summary = format!(
                        "Installed {} packages ({}) in {:.1}s",
                        install_result.materialized,
                        parts.join(", "),
                        elapsed.as_secs_f64()
                    );
                    crate::output::print_success(&summary);

                    // Print ecosystem-specific materialization paths
                    let manifest_path = config.manifest_path();
                    let project_dir = config.project_dir.clone();
                    let has_js;
                    let has_python;

                    if let Ok(content) = std::fs::read_to_string(&manifest_path) {
                        has_js = content.contains("[js_dependencies");
                        has_python = content.contains("[python_dependencies");
                    } else {
                        // Auto-detected manifest: infer ecosystem from file type
                        has_js = project_dir.join("package.json").exists();
                        has_python = project_dir.join("pyproject.toml").exists()
                            || project_dir.join("requirements.txt").exists();
                    }

                    if has_js {
                        crate::output::print_info("  Materialized JS packages to node_modules/");
                    }
                    if has_python {
                        crate::output::print_info("  Materialized Python packages to .venv/lib/site-packages/");
                    }
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
                // Use the structured exit code
                std::process::exit(exit_code.as_i32());
            } else {
                crate::output::print_error(&format!("Install failed: {}", e));
                Err(miette::miette!("{}", e))
            }
        }
    }
}
