//! `rusk python` command group.
//!
//! Provides Python version management subcommands:
//! - `rusk python list`  — discover Python installations on the system
//! - `rusk python find <version>` — find a Python matching a version constraint
//! - `rusk python pin <version>`  — write a `.python-version` file

use clap::{Args, Subcommand};
use miette::Result;
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Arguments for the python command group.
#[derive(Debug, Args)]
pub struct PythonArgs {
    #[command(subcommand)]
    pub command: PythonCommand,
}

/// Python subcommands.
#[derive(Debug, Subcommand)]
pub enum PythonCommand {
    /// List all Python installations found on this system.
    List,
    /// Find a Python interpreter matching the given version.
    Find(PythonFindArgs),
    /// Pin the Python version for this project (writes .python-version).
    Pin(PythonPinArgs),
}

/// Arguments for `rusk python find`.
#[derive(Debug, Args)]
pub struct PythonFindArgs {
    /// Version to search for (e.g. "3.11", "3.12.1").
    pub version: String,
}

/// Arguments for `rusk python pin`.
#[derive(Debug, Args)]
pub struct PythonPinArgs {
    /// Version to pin (e.g. "3.11", "3.12").
    pub version: String,
}

/// A discovered Python installation.
#[derive(Debug, Clone)]
struct PythonInstallation {
    /// The version string, e.g. "Python 3.11.9".
    version: String,
    /// The executable path.
    path: String,
    /// Whether this is the default `python`/`python3` on PATH.
    is_default: bool,
}

pub async fn run(args: PythonArgs) -> Result<()> {
    match args.command {
        PythonCommand::List => run_list().await,
        PythonCommand::Find(find_args) => run_find(find_args).await,
        PythonCommand::Pin(pin_args) => run_pin(pin_args).await,
    }
}

/// Discover Python installations on the system.
async fn run_list() -> Result<()> {
    let installations = discover_pythons();

    if installations.is_empty() {
        crate::output::print_warning("no Python installations found on PATH");
        return Ok(());
    }

    for install in &installations {
        let default_marker = if install.is_default { " (default)" } else { "" };
        println!(
            "{:<20} {}{}",
            install.version, install.path, default_marker
        );
    }

    Ok(())
}

/// Find a Python matching the requested version.
async fn run_find(args: PythonFindArgs) -> Result<()> {
    let target = &args.version;
    let installations = discover_pythons();

    for install in &installations {
        // Extract just the version number from "Python X.Y.Z"
        let ver = install
            .version
            .strip_prefix("Python ")
            .unwrap_or(&install.version);
        if ver.starts_with(target) {
            crate::output::print_success(&format!("Found {} at {}", install.version, install.path));
            return Ok(());
        }
    }

    Err(miette::miette!(
        "no Python matching version '{}' found on this system",
        target
    ))
}

/// Pin a Python version by writing `.python-version`.
async fn run_pin(args: PythonPinArgs) -> Result<()> {
    let version = &args.version;
    let path = PathBuf::from(".python-version");

    std::fs::write(&path, format!("{}\n", version))
        .map_err(|e| miette::miette!("failed to write .python-version: {}", e))?;

    crate::output::print_success(&format!(
        "Pinned Python version to {} (wrote .python-version)",
        version
    ));
    Ok(())
}

/// Discover all Python installations on the system.
///
/// Tries common interpreter names, deduplicates by resolved path,
/// and marks the default interpreter.
fn discover_pythons() -> Vec<PythonInstallation> {
    let candidate_names: &[&str] = &[
        "python3",
        "python",
        "python3.13",
        "python3.12",
        "python3.11",
        "python3.10",
        "python3.9",
    ];

    // Track by resolved path to avoid duplicates.
    // BTreeMap so output is deterministic.
    let mut seen: BTreeMap<String, PythonInstallation> = BTreeMap::new();
    let mut default_path: Option<String> = None;

    for name in candidate_names {
        if let Some(install) = probe_python(name) {
            let is_first = default_path.is_none();
            if is_first {
                default_path = Some(install.path.clone());
            }
            seen.entry(install.path.clone()).or_insert(install);
        }
    }

    // On Windows, also try `py -0` to discover installations via the launcher.
    if cfg!(windows) {
        if let Ok(output) = std::process::Command::new("py").args(["-0p"]).output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    // py -0p output looks like:
                    //  -V:3.12 *        C:\Python312\python.exe
                    //  -V:3.11          C:\Python311\python.exe
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    // Try to parse the path from the end of the line
                    if let Some(path_start) = line.rfind("  ") {
                        let path = line[path_start..].trim().to_string();
                        if !path.is_empty() && !seen.contains_key(&path) {
                            // Probe this specific path for version
                            if let Ok(output) =
                                std::process::Command::new(&path).args(["--version"]).output()
                            {
                                if output.status.success() {
                                    let version =
                                        String::from_utf8_lossy(&output.stdout).trim().to_string();
                                    let version = if version.is_empty() {
                                        String::from_utf8_lossy(&output.stderr)
                                            .trim()
                                            .to_string()
                                    } else {
                                        version
                                    };
                                    if !version.is_empty() {
                                        seen.insert(
                                            path.clone(),
                                            PythonInstallation {
                                                version,
                                                path,
                                                is_default: false,
                                            },
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Mark the default
    let mut result: Vec<PythonInstallation> = seen.into_values().collect();
    if let Some(ref dp) = default_path {
        for install in &mut result {
            install.is_default = install.path == *dp;
        }
    }

    // Sort: default first, then by version descending
    result.sort_by(|a, b| {
        b.is_default
            .cmp(&a.is_default)
            .then_with(|| b.version.cmp(&a.version))
    });

    result
}

/// Probe a single python executable name — return version and resolved path.
fn probe_python(name: &str) -> Option<PythonInstallation> {
    // Get the version
    let output = std::process::Command::new(name)
        .args(["--version"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    // Python 2 prints to stderr, Python 3 to stdout
    let version = {
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if stdout.is_empty() {
            String::from_utf8_lossy(&output.stderr).trim().to_string()
        } else {
            stdout
        }
    };

    if version.is_empty() {
        return None;
    }

    // Resolve full path
    let path = resolve_executable_path(name).unwrap_or_else(|| name.to_string());

    Some(PythonInstallation {
        version,
        path,
        is_default: false,
    })
}

/// Resolve the full path of an executable using platform-appropriate commands.
fn resolve_executable_path(name: &str) -> Option<String> {
    let (cmd, args) = if cfg!(windows) {
        ("where", vec![name.to_string()])
    } else {
        ("which", vec![name.to_string()])
    };

    let output = std::process::Command::new(cmd).args(&args).output().ok()?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // `where` on Windows may return multiple lines; take the first
        stdout.lines().next().map(|s| s.trim().to_string())
    } else {
        None
    }
}
