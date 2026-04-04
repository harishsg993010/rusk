//! `rusk link` — local package symlinks.
//!
//! - `rusk link` (in a package dir): registers the current directory as a
//!   linkable package in the global link registry.
//! - `rusk link <name>` (in a consuming project): creates a symlink from
//!   `node_modules/<name>` to the registered path.

use clap::Args;
use miette::Result;
use std::path::{Path, PathBuf};

/// Link a local package for development.
#[derive(Debug, Args)]
pub struct LinkArgs {
    /// Package name to link into this project. If omitted, registers the
    /// current directory as a linkable package.
    pub package: Option<String>,
}

pub async fn run(args: LinkArgs) -> Result<()> {
    let project_dir = std::env::current_dir()
        .map_err(|e| miette::miette!("failed to get current directory: {e}"))?;
    let links_dir = link_registry_dir();
    std::fs::create_dir_all(&links_dir)
        .map_err(|e| miette::miette!("failed to create link registry dir: {e}"))?;

    match args.package {
        None => {
            // Register the current directory as a linkable package.
            let name = detect_package_name(&project_dir)?;
            let link_file = links_dir.join(&name);
            std::fs::write(&link_file, project_dir.to_string_lossy().as_bytes())
                .map_err(|e| miette::miette!("failed to register link: {e}"))?;
            println!("Registered {} -> {}", name, project_dir.display());
            println!("In another project, run: rusk link {}", name);
        }
        Some(name) => {
            // Create a symlink in node_modules pointing to the registered path.
            let link_file = links_dir.join(&name);
            if !link_file.exists() {
                return Err(miette::miette!(
                    "Package '{}' not registered. Run `rusk link` in the package directory first.",
                    name
                ));
            }
            let target = std::fs::read_to_string(&link_file)
                .map_err(|e| miette::miette!("failed to read link registry: {e}"))?;
            let target = target.trim();

            let node_modules = project_dir.join("node_modules");
            std::fs::create_dir_all(&node_modules)
                .map_err(|e| miette::miette!("failed to create node_modules: {e}"))?;
            let link_path = node_modules.join(&name);

            if link_path.exists() || link_path.symlink_metadata().is_ok() {
                // Remove existing directory or symlink.
                if link_path.is_dir() {
                    std::fs::remove_dir_all(&link_path)
                        .map_err(|e| miette::miette!("failed to remove existing dir: {e}"))?;
                } else {
                    std::fs::remove_file(&link_path)
                        .map_err(|e| miette::miette!("failed to remove existing link: {e}"))?;
                }
            }

            // Create symlink (junction on Windows).
            create_symlink(target, &link_path)?;

            println!("Linked {} -> {}", name, target);
        }
    }

    Ok(())
}

/// Platform-appropriate symlink creation.
fn create_symlink(target: &str, link: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)
            .map_err(|e| miette::miette!("failed to create symlink: {e}"))?;
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_dir(target, link)
            .map_err(|e| miette::miette!("failed to create symlink: {e}"))?;
    }
    Ok(())
}

/// Return the global link registry directory.
fn link_registry_dir() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(
            std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string()),
        )
        .join("rusk")
        .join("links")
    } else {
        PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".to_string()))
            .join(".rusk")
            .join("links")
    }
}

/// Detect the package name from package.json, rusk.toml, or directory name.
fn detect_package_name(dir: &Path) -> Result<String> {
    // Try package.json first.
    let pkg_json = dir.join("package.json");
    if pkg_json.exists() {
        let content = std::fs::read_to_string(&pkg_json)
            .map_err(|e| miette::miette!("failed to read package.json: {e}"))?;
        let doc: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| miette::miette!("failed to parse package.json: {e}"))?;
        if let Some(name) = doc.get("name").and_then(|n| n.as_str()) {
            return Ok(name.to_string());
        }
    }

    // Try rusk.toml.
    let rusk_toml = dir.join("rusk.toml");
    if rusk_toml.exists() {
        let content = std::fs::read_to_string(&rusk_toml)
            .map_err(|e| miette::miette!("failed to read rusk.toml: {e}"))?;
        let doc: toml::Value = toml::from_str(&content)
            .map_err(|e| miette::miette!("failed to parse rusk.toml: {e}"))?;
        if let Some(name) = doc
            .get("package")
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str())
        {
            return Ok(name.to_string());
        }
    }

    // Fallback to directory name.
    Ok(dir
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string())
}
