//! `rusk tool` command group (like uvx / pipx).
//!
//! Provides isolated tool execution and management:
//! - `rusk tool run <package> [args...]` — run a Python CLI tool in an ephemeral venv
//! - `rusk tool install <package>`       — persistently install a CLI tool
//! - `rusk tool list`                    — list installed tools
//! - `rusk tool uninstall <package>`     — remove an installed tool
//!
//! `rusk x <package> [args...]` is a shorthand alias for `rusk tool run`.

use clap::{Args, Subcommand};
use miette::Result;
use serde_json;
use std::path::PathBuf;

/// Arguments for the tool command group.
#[derive(Debug, Args)]
pub struct ToolArgs {
    #[command(subcommand)]
    pub command: ToolCommand,
}

/// Tool subcommands.
#[derive(Debug, Subcommand)]
pub enum ToolCommand {
    /// Run a Python package as a CLI tool (installs to a cached venv).
    Run(ToolRunArgs),
    /// Persistently install a Python CLI tool.
    Install(ToolInstallArgs),
    /// List installed tools.
    List,
    /// Uninstall a previously installed tool.
    Uninstall(ToolUninstallArgs),
}

/// Arguments for `rusk tool run` and `rusk x`.
#[derive(Debug, Args)]
pub struct ToolRunArgs {
    /// Python package to run (e.g. "black", "ruff", "mypy").
    pub package: String,

    /// Arguments to pass to the tool.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

/// Arguments for `rusk tool install`.
#[derive(Debug, Args)]
pub struct ToolInstallArgs {
    /// Python package to install (e.g. "black", "ruff").
    pub package: String,
}

/// Arguments for `rusk tool uninstall`.
#[derive(Debug, Args)]
pub struct ToolUninstallArgs {
    /// Tool to uninstall.
    pub package: String,
}

pub async fn run(args: ToolArgs) -> Result<()> {
    match args.command {
        ToolCommand::Run(run_args) => run_tool(&run_args.package, &run_args.args).await,
        ToolCommand::Install(install_args) => install_tool(&install_args.package).await,
        ToolCommand::List => list_tools().await,
        ToolCommand::Uninstall(uninstall_args) => uninstall_tool(&uninstall_args.package).await,
    }
}

/// Shorthand entry point for `rusk x`.
pub async fn run_x(args: ToolRunArgs) -> Result<()> {
    run_tool(&args.package, &args.args).await
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Return the base directory for rusk tools: `~/.rusk/tools/`.
fn tools_base_dir() -> Result<PathBuf> {
    let base = if cfg!(windows) {
        std::env::var("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                let home = std::env::var("USERPROFILE")
                    .unwrap_or_else(|_| ".".to_string());
                PathBuf::from(home).join("AppData").join("Local")
            })
            .join("rusk")
    } else {
        std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(".rusk")
    };
    Ok(base.join("tools"))
}

/// Return the directory where tool binaries/symlinks live: `~/.rusk/bin/`.
fn tools_bin_dir() -> Result<PathBuf> {
    let base = if cfg!(windows) {
        std::env::var("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                let home = std::env::var("USERPROFILE")
                    .unwrap_or_else(|_| ".".to_string());
                PathBuf::from(home).join("AppData").join("Local")
            })
            .join("rusk")
    } else {
        std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(".rusk")
    };
    Ok(base.join("bin"))
}

/// Pick the best `python` interpreter for creating venvs.
fn python_cmd() -> &'static str {
    if cfg!(windows) { "python" } else { "python3" }
}

/// Return the pip path inside a venv.
fn venv_pip(venv_dir: &PathBuf) -> PathBuf {
    if cfg!(windows) {
        venv_dir.join("Scripts").join("pip.exe")
    } else {
        venv_dir.join("bin").join("pip")
    }
}

/// Return the scripts/bin dir inside a venv.
fn venv_bin_dir(venv_dir: &PathBuf) -> PathBuf {
    if cfg!(windows) {
        venv_dir.join("Scripts")
    } else {
        venv_dir.join("bin")
    }
}

/// Ensure a venv exists and the package is installed. Returns the venv dir.
async fn ensure_tool_venv(tool_dir: &PathBuf, package: &str) -> Result<PathBuf> {
    let venv_dir = tool_dir.join(".venv");

    if !venv_dir.exists() {
        std::fs::create_dir_all(tool_dir)
            .map_err(|e| miette::miette!("failed to create tool directory: {}", e))?;

        let spinner =
            crate::output::create_spinner(&format!("Creating venv for '{}'...", package));

        let status = tokio::process::Command::new(python_cmd())
            .args(["-m", "venv", &venv_dir.to_string_lossy()])
            .status()
            .await
            .map_err(|e| {
                spinner.finish_and_clear();
                miette::miette!(
                    "failed to run '{}': {}. Is Python installed and on PATH?",
                    python_cmd(),
                    e
                )
            })?;

        spinner.finish_and_clear();

        if !status.success() {
            return Err(miette::miette!("failed to create tool venv for '{}'", package));
        }
    }

    // Install/upgrade the package
    let pip = venv_pip(&venv_dir);

    let spinner = crate::output::create_spinner(&format!("Installing '{}'...", package));

    let status = tokio::process::Command::new(&pip)
        .args(["install", "-q", "--upgrade", package])
        .status()
        .await
        .map_err(|e| {
            spinner.finish_and_clear();
            miette::miette!("failed to run pip: {}", e)
        })?;

    spinner.finish_and_clear();

    if !status.success() {
        return Err(miette::miette!(
            "pip failed to install '{}' (exit code {})",
            package,
            status.code().unwrap_or(-1)
        ));
    }

    Ok(venv_dir)
}

// ---------------------------------------------------------------------------
// Subcommand implementations
// ---------------------------------------------------------------------------

/// Detect if a package is a JS/npm package or Python package.
/// Heuristic: known JS tools, or if name contains @scope/, it's npm.
fn is_js_tool(package: &str) -> bool {
    // Scoped npm packages
    if package.starts_with('@') {
        return true;
    }
    // Well-known JS tools
    const JS_TOOLS: &[&str] = &[
        "eslint", "prettier", "typescript", "tsc", "tsx", "vite",
        "webpack", "rollup", "esbuild", "swc", "turbo", "next",
        "create-react-app", "create-next-app", "serve", "http-server",
        "nodemon", "pm2", "jest", "vitest", "mocha", "nyc",
        "tailwindcss", "postcss", "sass", "less", "ts-node",
        "concurrently", "cross-env", "rimraf", "mkdirp",
        "degit", "tiged", "npkill", "npm-check-updates",
    ];
    JS_TOOLS.contains(&package)
}

/// Run a JS tool via npx-style: install to cached node_modules, run binary.
async fn run_js_tool(package: &str, args: &[String]) -> Result<()> {
    let tool_dir = tools_base_dir()?.join(format!("js-{}", package));
    let node_modules = tool_dir.join("node_modules");

    // Install if not cached
    if !node_modules.join(package).exists() {
        std::fs::create_dir_all(&tool_dir)
            .map_err(|e| miette::miette!("failed to create tool dir: {}", e))?;

        let spinner = crate::output::create_spinner(&format!("Installing JS tool '{}'...", package));

        // Use rusk itself to install
        let pkg_json = tool_dir.join("package.json");
        let content = format!(r#"{{"name":"rusk-tool-{}","private":true,"dependencies":{{"{}":"latest"}}}}"#, package, package);
        std::fs::write(&pkg_json, content)
            .map_err(|e| miette::miette!("failed to write package.json: {}", e))?;

        // Run npm install via our own orchestrator
        let config = rusk_orchestrator::config::OrchestratorConfig::for_project(tool_dir.clone());
        let result = rusk_orchestrator::run_install(&config, None).await;

        spinner.finish_and_clear();

        if let Err(e) = result {
            return Err(miette::miette!("failed to install JS tool '{}': {}", package, e));
        }
    }

    // Find the binary in node_modules/.bin/
    let bin_dir = node_modules.join(".bin");
    let tool_exe = if cfg!(windows) {
        let cmd = bin_dir.join(format!("{}.cmd", package));
        if cmd.exists() { cmd }
        else { bin_dir.join(format!("{}.exe", package)) }
    } else {
        bin_dir.join(package)
    };

    // Fallback: check package's bin field
    let tool_exe = if !tool_exe.exists() {
        // Read package.json bin field
        let pkg_json = node_modules.join(package).join("package.json");
        if pkg_json.exists() {
            let content = std::fs::read_to_string(&pkg_json).unwrap_or_default();
            if let Ok(doc) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(bin) = doc.get("bin") {
                    let bin_path = match bin {
                        serde_json::Value::String(s) => Some(s.clone()),
                        serde_json::Value::Object(m) => m.get(package).and_then(|v| v.as_str()).map(|s| s.to_string()),
                        _ => None,
                    };
                    if let Some(bp) = bin_path {
                        let full = node_modules.join(package).join(bp);
                        if full.exists() {
                            full
                        } else {
                            tool_exe
                        }
                    } else { tool_exe }
                } else { tool_exe }
            } else { tool_exe }
        } else { tool_exe }
    } else { tool_exe };

    if !tool_exe.exists() {
        return Err(miette::miette!(
            "JS tool binary '{}' not found. The package may not provide a CLI entry point.",
            package
        ));
    }

    // Run with node if it's a .js/.cjs/.mjs file, direct if .cmd/.exe
    let ext = tool_exe.extension().and_then(|e| e.to_str()).unwrap_or("");
    let status = if ext == "js" || ext == "mjs" || ext == "cjs" {
        tokio::process::Command::new("node")
            .arg(&tool_exe)
            .args(args)
            .env("NODE_PATH", node_modules.to_string_lossy().as_ref())
            .status()
            .await
    } else {
        tokio::process::Command::new(&tool_exe)
            .args(args)
            .status()
            .await
    };

    let status = status.map_err(|e| miette::miette!("failed to execute '{}': {}", package, e))?;
    std::process::exit(status.code().unwrap_or(1));
}

/// Run a Python tool in an isolated venv (cached for reuse).
async fn run_py_tool(package: &str, args: &[String]) -> Result<()> {
    let tool_dir = tools_base_dir()?.join(package);
    let venv_dir = ensure_tool_venv(&tool_dir, package).await?;

    let bin_dir = venv_bin_dir(&venv_dir);
    let tool_exe = if cfg!(windows) {
        let exe = bin_dir.join(format!("{}.exe", package));
        if exe.exists() {
            exe
        } else {
            let script = bin_dir.join(package);
            if script.exists() {
                script
            } else {
                bin_dir.join(format!("{}.cmd", package))
            }
        }
    } else {
        bin_dir.join(package)
    };

    if !tool_exe.exists() {
        return Err(miette::miette!(
            "tool binary '{}' not found after installing package '{}'. \
             The package may not provide a command-line entry point with that name.",
            tool_exe.display(),
            package
        ));
    }

    let status = tokio::process::Command::new(&tool_exe)
        .args(args)
        .status()
        .await
        .map_err(|e| miette::miette!("failed to execute '{}': {}", tool_exe.display(), e))?;

    std::process::exit(status.code().unwrap_or(1));
}

/// Run a tool — auto-detects JS vs Python.
async fn run_tool(package: &str, args: &[String]) -> Result<()> {
    if is_js_tool(package) {
        run_js_tool(package, args).await
    } else {
        // Default to Python (like uvx)
        // But if Python tool fails, suggest --ecosystem js
        run_py_tool(package, args).await
    }
}

/// Persistently install a tool and link its binary.
async fn install_tool(package: &str) -> Result<()> {
    let tool_dir = tools_base_dir()?.join(package);
    let venv_dir = ensure_tool_venv(&tool_dir, package).await?;

    // Create the bin directory
    let global_bin = tools_bin_dir()?;
    std::fs::create_dir_all(&global_bin)
        .map_err(|e| miette::miette!("failed to create bin directory: {}", e))?;

    let src_bin_dir = venv_bin_dir(&venv_dir);

    // Find the tool binary
    let (src_exe, dst_name) = if cfg!(windows) {
        let exe = src_bin_dir.join(format!("{}.exe", package));
        if exe.exists() {
            (exe, format!("{}.exe", package))
        } else {
            let script = src_bin_dir.join(format!("{}.cmd", package));
            if script.exists() {
                (script, format!("{}.cmd", package))
            } else {
                (src_bin_dir.join(package), package.to_string())
            }
        }
    } else {
        (src_bin_dir.join(package), package.to_string())
    };

    if !src_exe.exists() {
        crate::output::print_warning(&format!(
            "package '{}' installed but no executable named '{}' found in the venv",
            package, package
        ));
        return Ok(());
    }

    let dst_exe = global_bin.join(&dst_name);

    // On Windows, copy the file. On Unix, create a symlink.
    if cfg!(windows) {
        std::fs::copy(&src_exe, &dst_exe)
            .map_err(|e| miette::miette!("failed to copy tool binary: {}", e))?;
    } else {
        // Remove existing symlink if present
        let _ = std::fs::remove_file(&dst_exe);
        #[cfg(unix)]
        std::os::unix::fs::symlink(&src_exe, &dst_exe)
            .map_err(|e| miette::miette!("failed to symlink tool binary: {}", e))?;
        #[cfg(not(unix))]
        std::fs::copy(&src_exe, &dst_exe)
            .map_err(|e| miette::miette!("failed to copy tool binary: {}", e))?;
    }

    crate::output::print_success(&format!("Installed '{}' to {}", package, dst_exe.display()));
    crate::output::print_info(&format!(
        "  Make sure {} is on your PATH",
        global_bin.display()
    ));

    Ok(())
}

/// List persistently installed tools.
async fn list_tools() -> Result<()> {
    let base = tools_base_dir()?;

    if !base.exists() {
        crate::output::print_info("No tools installed yet.");
        return Ok(());
    }

    let entries: Vec<_> = std::fs::read_dir(&base)
        .map_err(|e| miette::miette!("failed to read tools directory: {}", e))?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|ft| ft.is_dir()).unwrap_or(false))
        .collect();

    if entries.is_empty() {
        crate::output::print_info("No tools installed yet.");
        return Ok(());
    }

    println!("{:<20} {}", "TOOL", "PATH");
    println!("{}", "-".repeat(60));

    for entry in entries {
        let name = entry.file_name().to_string_lossy().to_string();
        let venv_dir = entry.path().join(".venv");
        let status = if venv_dir.exists() { "installed" } else { "incomplete" };
        println!("{:<20} {} ({})", name, entry.path().display(), status);
    }

    Ok(())
}

/// Uninstall a tool by removing its venv and any linked binary.
async fn uninstall_tool(package: &str) -> Result<()> {
    let tool_dir = tools_base_dir()?.join(package);

    if !tool_dir.exists() {
        return Err(miette::miette!("tool '{}' is not installed", package));
    }

    // Remove the binary/symlink from bin dir
    let global_bin = tools_bin_dir()?;
    let possible_names = if cfg!(windows) {
        vec![
            format!("{}.exe", package),
            format!("{}.cmd", package),
            package.to_string(),
        ]
    } else {
        vec![package.to_string()]
    };

    for name in &possible_names {
        let dst = global_bin.join(name);
        if dst.exists() {
            let _ = std::fs::remove_file(&dst);
        }
    }

    // Remove the tool directory
    std::fs::remove_dir_all(&tool_dir)
        .map_err(|e| miette::miette!("failed to remove tool directory: {}", e))?;

    crate::output::print_success(&format!("Uninstalled '{}'", package));

    Ok(())
}
