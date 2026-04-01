//! `rusk init` command.
//!
//! Initializes a new rusk project by creating a rusk.toml manifest
//! with sensible defaults and optional trust policy configuration.

use clap::Args;
use miette::{IntoDiagnostic, Result};
use std::path::PathBuf;

/// Arguments for the init command.
#[derive(Debug, Args)]
pub struct InitArgs {
    /// Directory to initialize in (default: current directory).
    pub path: Option<PathBuf>,

    /// Ecosystem to initialize for.
    #[arg(long, default_value = "js")]
    pub ecosystem: String,

    /// Include a default trust policy file.
    #[arg(long)]
    pub with_policy: bool,

    /// Project name (default: directory name).
    #[arg(long)]
    pub name: Option<String>,
}

pub async fn run(args: InitArgs) -> Result<()> {
    let path = args.path.unwrap_or_else(|| PathBuf::from("."));
    let path = std::fs::canonicalize(&path).unwrap_or(path);

    tracing::info!(
        path = %path.display(),
        ecosystem = %args.ecosystem,
        "initializing new rusk project"
    );

    // Determine project name from --name flag or directory name
    let project_name = args.name.unwrap_or_else(|| {
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("my-project")
            .to_string()
    });

    // Validate ecosystem
    let ecosystem: rusk_core::Ecosystem = args
        .ecosystem
        .parse()
        .map_err(|e: rusk_core::ecosystem::EcosystemError| {
            miette::miette!("{}", e)
        })?;

    // Check if rusk.toml already exists
    let manifest_path = path.join("rusk.toml");
    if manifest_path.exists() {
        crate::output::print_error("rusk.toml already exists in this directory");
        return Err(miette::miette!(
            "rusk.toml already exists at {}",
            manifest_path.display()
        ));
    }

    // Create the directory if it doesn't exist
    std::fs::create_dir_all(&path).into_diagnostic()?;

    // Generate the rusk.toml content
    let manifest_content = generate_manifest(&project_name, ecosystem);

    // Write rusk.toml
    std::fs::write(&manifest_path, &manifest_content).into_diagnostic()?;
    crate::output::print_info(&format!("  created {}", manifest_path.display()));

    // Create .rusk/ directory
    let rusk_dir = path.join(".rusk");
    std::fs::create_dir_all(&rusk_dir).into_diagnostic()?;
    crate::output::print_info(&format!("  created {}", rusk_dir.display()));

    // Create .rusk/cas directory
    let cas_dir = rusk_dir.join("cas");
    std::fs::create_dir_all(&cas_dir).into_diagnostic()?;

    // Optionally create trust policy file
    if args.with_policy {
        let policy_path = path.join("rusk-policy.toml");
        let policy_content = generate_policy(ecosystem);
        std::fs::write(&policy_path, &policy_content).into_diagnostic()?;
        crate::output::print_info(&format!("  created {}", policy_path.display()));
    }

    crate::output::print_success(&format!(
        "initialized rusk project '{}' for {} ecosystem",
        project_name,
        ecosystem.display_name()
    ));
    Ok(())
}

fn generate_manifest(name: &str, ecosystem: rusk_core::Ecosystem) -> String {
    match ecosystem {
        rusk_core::Ecosystem::Js => {
            format!(
                r#"[package]
name = "{name}"
version = "0.1.0"
ecosystem = "js"
description = ""

[js_dependencies.dependencies]

[js_dependencies.dev_dependencies]

[trust]
require_signatures = false
require_provenance = false
"#
            )
        }
        rusk_core::Ecosystem::Python => {
            format!(
                r#"[package]
name = "{name}"
version = "0.1.0"
ecosystem = "python"
description = ""

[python_dependencies]
requires_python = ">=3.9"

[python_dependencies.dependencies]

[python_dependencies.dev_dependencies]

[trust]
require_signatures = false
require_provenance = false
"#
            )
        }
    }
}

fn generate_policy(ecosystem: rusk_core::Ecosystem) -> String {
    match ecosystem {
        rusk_core::Ecosystem::Js => {
            r#"# rusk trust policy for JavaScript projects
# See https://rusk.dev/docs/trust for documentation

[defaults]
# Default action for packages that don't match any rule
action = "allow"

[rules]
# Block deprecated packages
[[rules.block]]
reason = "deprecated"
deprecated = true

# Warn on packages with install scripts
[[rules.warn]]
reason = "has install scripts"
has_install_scripts = true
"#
            .to_string()
        }
        rusk_core::Ecosystem::Python => {
            r#"# rusk trust policy for Python projects
# See https://rusk.dev/docs/trust for documentation

[defaults]
# Default action for packages that don't match any rule
action = "allow"

[rules]
# Block yanked packages
[[rules.block]]
reason = "yanked"
yanked = true
"#
            .to_string()
        }
    }
}
