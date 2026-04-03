//! Output formatting utilities for the CLI.
//!
//! Supports both human-readable terminal output (with colors and progress bars)
//! and machine-readable JSON output for CI/scripting use.

use std::str::FromStr;

/// Output format for CLI commands.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum OutputFormat {
    /// Human-readable terminal output with colors.
    #[default]
    Text,
    /// Machine-readable JSON output.
    Json,
}

impl FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" | "human" => Ok(OutputFormat::Text),
            "json" => Ok(OutputFormat::Json),
            other => Err(format!("unknown output format: {other}")),
        }
    }
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Text => write!(f, "text"),
            OutputFormat::Json => write!(f, "json"),
        }
    }
}

/// Print a success message to the terminal.
pub fn print_success(message: &str) {
    let style = console::Style::new().green().bold();
    eprintln!("{}", style.apply_to(message));
}

/// Print an informational message to the terminal.
pub fn print_info(message: &str) {
    let style = console::Style::new().cyan();
    eprintln!("{}", style.apply_to(message));
}

/// Print a warning message to the terminal.
pub fn print_warning(message: &str) {
    let style = console::Style::new().yellow().bold();
    eprintln!("{}", style.apply_to(format!("warning: {message}")));
}

/// Print an error message to the terminal.
pub fn print_error(message: &str) {
    let style = console::Style::new().red().bold();
    eprintln!("{}", style.apply_to(format!("error: {message}")));
}

/// Create a new progress bar with the given total count.
pub fn create_progress_bar(total: u64, message: &str) -> indicatif::ProgressBar {
    let pb = indicatif::ProgressBar::new(total);
    pb.set_style(
        indicatif::ProgressStyle::with_template(
            "{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} {msg}",
        )
        .unwrap()
        .progress_chars("#>-"),
    );
    pb.set_message(message.to_string());
    pb
}

/// Create a spinner for indeterminate progress.
pub fn create_spinner(message: &str) -> indicatif::ProgressBar {
    let pb = indicatif::ProgressBar::new_spinner();
    pb.set_style(
        indicatif::ProgressStyle::with_template("{spinner:.green} {msg}")
            .unwrap(),
    );
    pb.set_message(message.to_string());
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    pb
}

/// Print all structured exit codes.
///
/// Called when `rusk --exit-codes` is passed. Output respects the global
/// `--format` flag (text table or JSON array).
pub fn print_exit_codes(format: OutputFormat) {
    use rusk_core::ExitCode;

    let codes = ExitCode::all();

    match format {
        OutputFormat::Text => {
            println!("{:<6} {:<26} {}", "CODE", "NAME", "DESCRIPTION");
            println!("{}", "-".repeat(70));
            for code in codes {
                println!(
                    "{:<6} {:<26} {}",
                    code.as_i32(),
                    code.code_name(),
                    code.description(),
                );
            }
        }
        OutputFormat::Json => {
            let entries: Vec<serde_json::Value> = codes
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "code": c.as_i32(),
                        "name": c.code_name(),
                        "description": c.description(),
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&entries).unwrap_or_default()
            );
        }
    }
}
