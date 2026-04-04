//! `rusk migrate` command.
//!
//! Imports dependencies from foreign lockfiles (package-lock.json,
//! yarn.lock, pnpm-lock.yaml) and generates a rusk.toml manifest
//! so that `rusk install` can create a native rusk.lock.

use clap::Args;
use miette::Result;
use rusk_core::Ecosystem;
use rusk_manifest::schema::{DependencyEntry, JsDependencies, Manifest, PackageMetadata};
use std::collections::HashMap;

/// Arguments for the migrate command.
#[derive(Debug, Args)]
pub struct MigrateArgs {
    /// Source lockfile format to migrate from: "npm", "yarn", or "pnpm".
    /// If omitted, rusk will auto-detect by looking for known lockfiles
    /// in the current directory.
    #[arg(long)]
    pub from: Option<String>,
}

/// Detected lockfile source.
#[derive(Debug, Clone, Copy)]
enum LockSource {
    Npm,
    Yarn,
    Pnpm,
}

impl std::fmt::Display for LockSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockSource::Npm => write!(f, "npm (package-lock.json)"),
            LockSource::Yarn => write!(f, "yarn (yarn.lock)"),
            LockSource::Pnpm => write!(f, "pnpm (pnpm-lock.yaml)"),
        }
    }
}

pub async fn run(args: MigrateArgs, format: crate::output::OutputFormat) -> Result<()> {
    let json_output = format == crate::output::OutputFormat::Json;

    let project_dir = std::env::current_dir()
        .map_err(|e| miette::miette!("failed to get current directory: {}", e))?;

    // Determine the lockfile source and read its content.
    let (source, content) = detect_source(&project_dir, args.from.as_deref())?;

    let spinner = if json_output {
        indicatif::ProgressBar::hidden()
    } else {
        crate::output::create_spinner(&format!("Migrating from {source}..."))
    };

    // Parse the foreign lockfile into (name, version) pairs.
    let packages: Vec<(String, String)> = match source {
        LockSource::Npm => rusk_manifest::parse_package_lock_json(&content)
            .map_err(|e| miette::miette!("failed to parse package-lock.json: {}", e))?,
        LockSource::Yarn => rusk_manifest::parse_yarn_lock(&content)
            .map_err(|e| miette::miette!("failed to parse yarn.lock: {}", e))?,
        LockSource::Pnpm => rusk_manifest::parse_pnpm_lock(&content)
            .map_err(|e| miette::miette!("failed to parse pnpm-lock.yaml: {}", e))?,
    };

    if packages.is_empty() {
        spinner.finish_and_clear();
        if json_output {
            let output = serde_json::json!({
                "status": "error",
                "error": "no packages found in source lockfile",
            });
            println!("{}", serde_json::to_string_pretty(&output).unwrap_or_default());
        } else {
            crate::output::print_warning("No packages found in the source lockfile.");
        }
        return Ok(());
    }

    // Build a rusk.toml manifest with the extracted dependencies.
    // We pin to the exact versions from the lockfile.
    let mut deps: HashMap<String, DependencyEntry> = HashMap::new();
    for (name, version) in &packages {
        deps.insert(name.clone(), DependencyEntry::Simple(version.clone()));
    }

    let manifest = Manifest {
        package: PackageMetadata {
            name: "migrated-project".to_string(),
            version: Some("0.0.0".to_string()),
            ecosystem: Ecosystem::Js,
            description: Some("Migrated from an existing lockfile".to_string()),
            authors: Vec::new(),
            license: None,
            repository: None,
            homepage: None,
            keywords: Vec::new(),
        },
        js_dependencies: Some(JsDependencies {
            dependencies: deps,
            dev_dependencies: HashMap::new(),
            peer_dependencies: HashMap::new(),
            optional_dependencies: HashMap::new(),
            registry_url: None,
            overrides: HashMap::new(),
            patched_dependencies: HashMap::new(),
            node_linker: None,
        }),
        python_dependencies: None,
        trust: None,
        registries: None,
        workspace: None,
        build: None,
    };

    // Write rusk.toml (only if one doesn't already exist).
    let manifest_path = project_dir.join("rusk.toml");
    if manifest_path.exists() {
        spinner.finish_and_clear();
        if json_output {
            let output = serde_json::json!({
                "status": "error",
                "error": "rusk.toml already exists; refusing to overwrite",
            });
            println!("{}", serde_json::to_string_pretty(&output).unwrap_or_default());
        } else {
            crate::output::print_error(
                "rusk.toml already exists. Remove it first or add dependencies manually.",
            );
        }
        return Err(miette::miette!("rusk.toml already exists"));
    }

    let manifest_toml = toml::to_string_pretty(&manifest)
        .map_err(|e| miette::miette!("failed to serialize manifest: {}", e))?;
    std::fs::write(&manifest_path, &manifest_toml)
        .map_err(|e| miette::miette!("failed to write rusk.toml: {}", e))?;

    spinner.finish_and_clear();

    let pkg_count = packages.len();

    // Print summary.
    if json_output {
        let output = serde_json::json!({
            "status": "success",
            "source": format!("{source}"),
            "packages_migrated": pkg_count,
            "manifest_path": manifest_path.display().to_string(),
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap_or_default());
    } else {
        crate::output::print_success(&format!(
            "Migrated {pkg_count} packages from {source}"
        ));
        crate::output::print_info(&format!(
            "Created {}",
            manifest_path.display()
        ));
        crate::output::print_info(
            "Run 'rusk install' to resolve, download, and create rusk.lock.",
        );
    }

    Ok(())
}

/// Detect which foreign lockfile to migrate from.
///
/// If `explicit` is provided ("npm", "yarn", "pnpm"), we look for exactly
/// that file. Otherwise we auto-detect by probing the directory.
fn detect_source(
    project_dir: &std::path::Path,
    explicit: Option<&str>,
) -> Result<(LockSource, String)> {
    if let Some(name) = explicit {
        let (source, path) = match name.to_lowercase().as_str() {
            "npm" => (LockSource::Npm, project_dir.join("package-lock.json")),
            "yarn" => (LockSource::Yarn, project_dir.join("yarn.lock")),
            "pnpm" => (LockSource::Pnpm, project_dir.join("pnpm-lock.yaml")),
            other => return Err(miette::miette!(
                "unknown lockfile source '{}'; expected npm, yarn, or pnpm",
                other
            )),
        };
        let content = std::fs::read_to_string(&path).map_err(|e| {
            miette::miette!("failed to read {}: {}", path.display(), e)
        })?;
        return Ok((source, content));
    }

    // Auto-detect order: package-lock.json > yarn.lock > pnpm-lock.yaml
    let candidates: &[(LockSource, &str)] = &[
        (LockSource::Npm, "package-lock.json"),
        (LockSource::Yarn, "yarn.lock"),
        (LockSource::Pnpm, "pnpm-lock.yaml"),
    ];

    for (source, filename) in candidates {
        let path = project_dir.join(filename);
        if path.exists() {
            let content = std::fs::read_to_string(&path).map_err(|e| {
                miette::miette!("failed to read {}: {}", path.display(), e)
            })?;
            return Ok((*source, content));
        }
    }

    Err(miette::miette!(
        "no foreign lockfile found (looked for package-lock.json, yarn.lock, pnpm-lock.yaml)"
    ))
}
