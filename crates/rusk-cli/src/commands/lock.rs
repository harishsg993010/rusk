//! `rusk lock` command.
//!
//! Resolves dependencies and writes rusk.lock WITHOUT installing.
//! Like `uv lock` -- just generates/updates the lockfile.

use clap::Args;
use miette::Result;
use rusk_orchestrator::config::OrchestratorConfig;
use std::time::Instant;

/// Arguments for the lock command.
#[derive(Debug, Args)]
pub struct LockArgs {
    /// Only lock production dependencies (skip dev).
    #[arg(long)]
    pub production: bool,
}

pub async fn run(args: LockArgs, format: crate::output::OutputFormat) -> Result<()> {
    let start = Instant::now();
    let json_output = format == crate::output::OutputFormat::Json;

    tracing::info!(production = args.production, "starting lock");

    let project_dir = std::env::current_dir()
        .map_err(|e| miette::miette!("failed to get current directory: {}", e))?;

    let mut config = OrchestratorConfig::for_project(project_dir);
    config.include_dev = !args.production;

    // Create a spinner for progress (suppressed in JSON mode)
    let spinner = if json_output {
        indicatif::ProgressBar::hidden()
    } else {
        crate::output::create_spinner("Resolving dependencies...")
    };
    let spinner_clone = spinner.clone();

    let on_progress: Box<dyn Fn(&str) + Send + Sync> = Box::new(move |msg: &str| {
        spinner_clone.set_message(msg.to_string());
    });

    // Run install (which resolves + writes lockfile as a side effect)
    let result = rusk_orchestrator::run_install(&config, Some(on_progress)).await;

    spinner.finish_and_clear();

    match result {
        Ok(install_result) => {
            let elapsed = start.elapsed();

            if json_output {
                let output = serde_json::json!({
                    "status": "success",
                    "locked": install_result.resolved,
                    "elapsed_ms": elapsed.as_millis() as u64,
                });
                println!("{}", serde_json::to_string_pretty(&output).unwrap_or_default());
            } else if install_result.resolved == 0 {
                crate::output::print_success("No dependencies to lock.");
            } else {
                let summary = format!(
                    "Locked {} packages to rusk.lock in {:.1}s",
                    install_result.resolved,
                    elapsed.as_secs_f64()
                );
                crate::output::print_success(&summary);
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
                crate::output::print_error(&format!("Lock failed: {}", e));
                Err(miette::miette!("{}", e))
            }
        }
    }
}
