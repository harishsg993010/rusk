//! `rusk venv` command.
//!
//! Creates a Python virtual environment.
//! `rusk venv` creates .venv in the current directory.
//! `rusk venv myenv` creates myenv/ directory.
//! `rusk venv --python 3.11` requests a specific Python version.

use clap::Args;
use miette::Result;
use std::path::PathBuf;

/// Arguments for the venv command.
#[derive(Debug, Args)]
pub struct VenvArgs {
    /// Path for the virtual environment (default: .venv).
    pub path: Option<PathBuf>,

    /// Python interpreter to use (e.g. python3, python3.11).
    #[arg(long, short)]
    pub python: Option<String>,
}

pub async fn run(args: VenvArgs) -> Result<()> {
    let python = args.python.unwrap_or_else(|| {
        if cfg!(windows) {
            "python".to_string()
        } else {
            "python3".to_string()
        }
    });
    let venv_path = args.path.unwrap_or_else(|| PathBuf::from(".venv"));

    if venv_path.exists() {
        crate::output::print_warning(
            &format!(
                "virtual environment already exists at {}",
                venv_path.display()
            )
            .replace("warning: ", ""),
        );
    }

    let spinner = crate::output::create_spinner(
        &format!("Creating virtual environment at {}...", venv_path.display()),
    );

    let status = tokio::process::Command::new(&python)
        .args(["-m", "venv", &venv_path.to_string_lossy()])
        .status()
        .await
        .map_err(|e| {
            spinner.finish_and_clear();
            miette::miette!(
                "failed to run '{}': {}. Is Python installed and on PATH?",
                python,
                e
            )
        })?;

    spinner.finish_and_clear();

    if status.success() {
        crate::output::print_success(
            &format!("Created virtual environment at {}", venv_path.display()),
        );

        // Print activation instructions
        if cfg!(windows) {
            crate::output::print_info(
                &format!("  Activate with: {}\\Scripts\\activate", venv_path.display()),
            );
        } else {
            crate::output::print_info(
                &format!("  Activate with: source {}/bin/activate", venv_path.display()),
            );
        }

        Ok(())
    } else {
        Err(miette::miette!(
            "failed to create virtual environment (python exited with {})",
            status.code().unwrap_or(-1)
        ))
    }
}
