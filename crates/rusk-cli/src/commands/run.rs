//! `rusk run` command.
//!
//! Runs a command with the correct environment for the detected ecosystem.
//! For JS projects, sets NODE_PATH to node_modules/.
//! For Python projects, sets PYTHONPATH to .venv/lib/site-packages/.
//! Auto-detects the ecosystem from the manifest or the script extension.

use clap::Args;
use miette::Result;

/// Arguments for the run command.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// The command or script to run (e.g., "node server.js", "python app.py", "script.py").
    #[arg(required = true, trailing_var_arg = true)]
    pub args: Vec<String>,
}

pub async fn run(args: RunArgs) -> Result<()> {
    let project_dir = std::env::current_dir()
        .map_err(|e| miette::miette!("failed to get current directory: {}", e))?;

    if args.args.is_empty() {
        return Err(miette::miette!("No command specified. Usage: rusk run <command> [args...]"));
    }

    let first_arg = &args.args[0];
    let rest_args = &args.args[1..];

    // Detect ecosystem from manifest files
    let manifest_ecosystem = detect_ecosystem_from_manifest(&project_dir);

    // Determine program and ecosystem from the command
    let (program, cmd_args, ecosystem) = resolve_command(first_arg, rest_args, manifest_ecosystem);

    let node_modules = project_dir.join("node_modules");
    let site_packages = project_dir.join(".venv").join("lib").join("site-packages");

    let mut cmd = tokio::process::Command::new(&program);
    cmd.args(&cmd_args);
    cmd.current_dir(&project_dir);

    // Set ecosystem-specific env
    match ecosystem.as_str() {
        "js" => {
            cmd.env("NODE_PATH", node_modules.to_string_lossy().as_ref());
        }
        "python" => {
            cmd.env("PYTHONPATH", site_packages.to_string_lossy().as_ref());
        }
        _ => {}
    }

    crate::output::print_info(&format!("Running: {} {}", program, cmd_args.join(" ")));

    let status = cmd.status().await.map_err(|e| {
        miette::miette!("failed to execute '{}': {}", program, e)
    })?;

    std::process::exit(status.code().unwrap_or(1));
}

/// Detect ecosystem from manifest files in the project directory.
fn detect_ecosystem_from_manifest(project_dir: &std::path::Path) -> Option<String> {
    if project_dir.join("rusk.toml").exists() {
        // Try to read the ecosystem from rusk.toml
        if let Ok(content) = std::fs::read_to_string(project_dir.join("rusk.toml")) {
            if content.contains("[js_dependencies") {
                return Some("js".to_string());
            }
            if content.contains("[python_dependencies") {
                return Some("python".to_string());
            }
            // Check the package ecosystem field
            if let Ok(doc) = content.parse::<toml::Value>() {
                if let Some(eco) = doc
                    .get("package")
                    .and_then(|p| p.get("ecosystem"))
                    .and_then(|e| e.as_str())
                {
                    return Some(eco.to_string());
                }
            }
        }
    }
    if project_dir.join("package.json").exists() {
        return Some("js".to_string());
    }
    if project_dir.join("pyproject.toml").exists()
        || project_dir.join("requirements.txt").exists()
    {
        return Some("python".to_string());
    }
    None
}

/// Resolve the command, arguments, and ecosystem from the user input.
///
/// Handles cases like:
/// - `rusk run node server.js`       -> program="node", args=["server.js"], eco="js"
/// - `rusk run python app.py`        -> program="python", args=["app.py"], eco="python"
/// - `rusk run script.py`            -> program="python", args=["script.py"], eco="python"
/// - `rusk run script.js`            -> program="node", args=["script.js"], eco="js"
/// - `rusk run some-binary --flag`   -> program="some-binary", args=["--flag"], eco from manifest
fn resolve_command(
    first_arg: &str,
    rest_args: &[String],
    manifest_ecosystem: Option<String>,
) -> (String, Vec<String>, String) {
    // If first arg is an explicit runtime, use it directly
    match first_arg {
        "node" | "npx" => {
            return (
                first_arg.to_string(),
                rest_args.to_vec(),
                "js".to_string(),
            );
        }
        "python" | "python3" | "pip" | "pip3" => {
            return (
                first_arg.to_string(),
                rest_args.to_vec(),
                "python".to_string(),
            );
        }
        _ => {}
    }

    // Auto-detect from file extension
    if first_arg.ends_with(".js") || first_arg.ends_with(".mjs") || first_arg.ends_with(".cjs") {
        return (
            "node".to_string(),
            std::iter::once(first_arg.to_string())
                .chain(rest_args.iter().cloned())
                .collect(),
            "js".to_string(),
        );
    }

    if first_arg.ends_with(".py") {
        return (
            "python".to_string(),
            std::iter::once(first_arg.to_string())
                .chain(rest_args.iter().cloned())
                .collect(),
            "python".to_string(),
        );
    }

    if first_arg.ends_with(".ts") || first_arg.ends_with(".tsx") {
        return (
            "npx".to_string(),
            std::iter::once("tsx".to_string())
                .chain(std::iter::once(first_arg.to_string()))
                .chain(rest_args.iter().cloned())
                .collect(),
            "js".to_string(),
        );
    }

    // Fall back to running the command directly with the manifest ecosystem
    let ecosystem = manifest_ecosystem.unwrap_or_else(|| "js".to_string());
    (
        first_arg.to_string(),
        rest_args.to_vec(),
        ecosystem,
    )
}
