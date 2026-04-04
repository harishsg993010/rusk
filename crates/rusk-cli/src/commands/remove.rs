//! `rusk remove` command.
//!
//! Removes one or more packages from the manifest, lockfile, and installed
//! directories. Auto-detects the manifest format (rusk.toml, package.json,
//! pyproject.toml, requirements.txt).

use clap::Args;
use miette::Result;
use std::path::{Path, PathBuf};

/// Arguments for the remove command.
#[derive(Debug, Args)]
pub struct RemoveArgs {
    /// Packages to remove (by name).
    #[arg(required = true)]
    pub packages: Vec<String>,
}

pub async fn run(args: RemoveArgs) -> Result<()> {
    let project_dir = std::env::current_dir()
        .map_err(|e| miette::miette!("failed to get current directory: {}", e))?;

    // Detect which manifest file exists
    let rusk_toml = project_dir.join("rusk.toml");
    let package_json = project_dir.join("package.json");
    let pyproject_toml = project_dir.join("pyproject.toml");
    let requirements_txt = project_dir.join("requirements.txt");

    if rusk_toml.exists() {
        remove_from_rusk_toml(&rusk_toml, &args.packages)?;
    } else if package_json.exists() {
        remove_from_package_json(&package_json, &args.packages)?;
    } else if pyproject_toml.exists() {
        remove_from_pyproject_toml(&pyproject_toml, &args.packages)?;
    } else if requirements_txt.exists() {
        remove_from_requirements_txt(&requirements_txt, &args.packages)?;
    } else {
        return Err(miette::miette!(
            "No manifest file found (rusk.toml, package.json, pyproject.toml, or requirements.txt)"
        ));
    }

    // Remove installed package directories
    remove_installed_dirs(&project_dir, &args.packages);

    // Remove entries from rusk.lock if it exists
    remove_from_lockfile(&project_dir, &args.packages)?;

    Ok(())
}

fn remove_from_rusk_toml(path: &Path, packages: &[String]) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| miette::miette!("failed to read rusk.toml: {}", e))?;

    let mut doc: toml::Value = toml::from_str(&content)
        .map_err(|e| miette::miette!("failed to parse rusk.toml: {}", e))?;

    for pkg_name in packages {
        let mut found = false;

        // Try js_dependencies.dependencies and js_dependencies.dev_dependencies
        if let Some(js) = doc.get_mut("js_dependencies").and_then(|v| v.as_table_mut()) {
            for section in &["dependencies", "dev_dependencies"] {
                if let Some(deps) = js.get_mut(*section).and_then(|v| v.as_table_mut()) {
                    if deps.remove(pkg_name).is_some() {
                        found = true;
                    }
                }
            }
        }

        // Try python_dependencies.dependencies and python_dependencies.dev_dependencies
        if let Some(py) = doc.get_mut("python_dependencies").and_then(|v| v.as_table_mut()) {
            for section in &["dependencies", "dev_dependencies"] {
                if let Some(deps) = py.get_mut(*section).and_then(|v| v.as_table_mut()) {
                    if deps.remove(pkg_name).is_some() {
                        found = true;
                    }
                }
            }
        }

        if found {
            crate::output::print_success(&format!("Removed {pkg_name} from rusk.toml"));
        } else {
            crate::output::print_warning(&format!("{pkg_name} not found in rusk.toml"));
        }
    }

    let output = toml::to_string_pretty(&doc)
        .map_err(|e| miette::miette!("failed to serialize rusk.toml: {}", e))?;
    std::fs::write(path, output)
        .map_err(|e| miette::miette!("failed to write rusk.toml: {}", e))?;

    Ok(())
}

fn remove_from_package_json(path: &Path, packages: &[String]) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| miette::miette!("failed to read package.json: {}", e))?;

    let mut doc: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| miette::miette!("failed to parse package.json: {}", e))?;

    for pkg_name in packages {
        let mut found = false;

        for section in &["dependencies", "devDependencies"] {
            if let Some(deps) = doc.get_mut(*section).and_then(|v| v.as_object_mut()) {
                if deps.remove(pkg_name).is_some() {
                    found = true;
                }
            }
        }

        if found {
            crate::output::print_success(&format!("Removed {pkg_name} from package.json"));
        } else {
            crate::output::print_warning(&format!("{pkg_name} not found in package.json"));
        }
    }

    let output = serde_json::to_string_pretty(&doc)
        .map_err(|e| miette::miette!("failed to serialize package.json: {}", e))?;
    std::fs::write(path, output)
        .map_err(|e| miette::miette!("failed to write package.json: {}", e))?;

    Ok(())
}

fn remove_from_pyproject_toml(path: &Path, packages: &[String]) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| miette::miette!("failed to read pyproject.toml: {}", e))?;

    let mut doc: toml::Value = toml::from_str(&content)
        .map_err(|e| miette::miette!("failed to parse pyproject.toml: {}", e))?;

    for pkg_name in packages {
        let mut found = false;
        let pkg_lower = pkg_name.to_lowercase();

        // Remove from [project.dependencies] (array of PEP 508 strings)
        if let Some(deps) = doc
            .get_mut("project")
            .and_then(|v| v.as_table_mut())
            .and_then(|t| t.get_mut("dependencies"))
            .and_then(|v| v.as_array_mut())
        {
            let before_len = deps.len();
            deps.retain(|v| {
                if let Some(s) = v.as_str() {
                    !dep_string_matches(s, &pkg_lower)
                } else {
                    true
                }
            });
            if deps.len() < before_len {
                found = true;
            }
        }

        // Remove from [project.optional-dependencies.*] arrays
        if let Some(opt_deps) = doc
            .get_mut("project")
            .and_then(|v| v.as_table_mut())
            .and_then(|t| t.get_mut("optional-dependencies"))
            .and_then(|v| v.as_table_mut())
        {
            for (_group, group_deps) in opt_deps.iter_mut() {
                if let Some(arr) = group_deps.as_array_mut() {
                    let before_len = arr.len();
                    arr.retain(|v| {
                        if let Some(s) = v.as_str() {
                            !dep_string_matches(s, &pkg_lower)
                        } else {
                            true
                        }
                    });
                    if arr.len() < before_len {
                        found = true;
                    }
                }
            }
        }

        if found {
            crate::output::print_success(&format!("Removed {pkg_name} from pyproject.toml"));
        } else {
            crate::output::print_warning(&format!("{pkg_name} not found in pyproject.toml"));
        }
    }

    let output = toml::to_string_pretty(&doc)
        .map_err(|e| miette::miette!("failed to serialize pyproject.toml: {}", e))?;
    std::fs::write(path, output)
        .map_err(|e| miette::miette!("failed to write pyproject.toml: {}", e))?;

    Ok(())
}

fn remove_from_requirements_txt(path: &Path, packages: &[String]) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| miette::miette!("failed to read requirements.txt: {}", e))?;

    let mut removed: Vec<String> = Vec::new();

    let filtered: Vec<&str> = content
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            // Keep blanks, comments, flags
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('-') {
                return true;
            }
            // Extract package name from the line
            let line_name = extract_req_name(trimmed);
            for pkg in packages {
                if line_name.eq_ignore_ascii_case(pkg) {
                    removed.push(pkg.clone());
                    return false;
                }
            }
            true
        })
        .collect();

    let mut output = filtered.join("\n");
    if !output.ends_with('\n') && !output.is_empty() {
        output.push('\n');
    }

    std::fs::write(path, output)
        .map_err(|e| miette::miette!("failed to write requirements.txt: {}", e))?;

    for pkg in packages {
        if removed.iter().any(|r| r.eq_ignore_ascii_case(pkg)) {
            crate::output::print_success(&format!("Removed {pkg} from requirements.txt"));
        } else {
            crate::output::print_warning(&format!("{pkg} not found in requirements.txt"));
        }
    }

    Ok(())
}

/// Extract the bare package name from a requirements.txt line.
/// e.g. "requests>=2.28.0" -> "requests", "flask[async]>=2.0" -> "flask"
fn extract_req_name(line: &str) -> String {
    // Strip environment markers
    let line = if let Some(idx) = line.find(';') {
        line[..idx].trim()
    } else {
        line.trim()
    };

    // Strip extras
    let line = if let Some(idx) = line.find('[') {
        &line[..idx]
    } else {
        line
    };

    // Strip version operators
    for op in &[">=", "<=", "==", "~=", "!=", ">", "<"] {
        if let Some(idx) = line.find(op) {
            return line[..idx].trim().to_string();
        }
    }

    line.trim().to_string()
}

/// Check if a PEP 508 dependency string starts with the given package name
/// (case-insensitive). E.g., "requests>=2.28" matches "requests".
fn dep_string_matches(dep_str: &str, pkg_lower: &str) -> bool {
    let name = extract_req_name(dep_str).to_lowercase();
    name == *pkg_lower
}

/// Remove installed package directories from node_modules/ or .venv/lib/site-packages/.
fn remove_installed_dirs(project_dir: &Path, packages: &[String]) {
    for pkg_name in packages {
        // JS: node_modules/<package>
        let node_path = project_dir.join("node_modules").join(pkg_name);
        if node_path.exists() {
            if let Err(e) = std::fs::remove_dir_all(&node_path) {
                crate::output::print_warning(&format!(
                    "Failed to remove {}: {e}",
                    node_path.display()
                ));
            } else {
                crate::output::print_info(&format!(
                    "Removed node_modules/{pkg_name}"
                ));
            }
        }

        // Python: .venv/lib/site-packages/<package>
        let venv_site = project_dir.join(".venv").join("lib").join("site-packages");
        if venv_site.exists() {
            let site_path = venv_site.join(pkg_name);
            if site_path.exists() {
                if let Err(e) = std::fs::remove_dir_all(&site_path) {
                    crate::output::print_warning(&format!(
                        "Failed to remove {}: {e}",
                        site_path.display()
                    ));
                } else {
                    crate::output::print_info(&format!(
                        "Removed .venv/lib/site-packages/{pkg_name}"
                    ));
                }
            }
        }
    }
}

/// Remove packages from rusk.lock if the lockfile exists.
fn remove_from_lockfile(project_dir: &Path, packages: &[String]) -> Result<()> {
    let lockfile_path = project_dir.join("rusk.lock");
    if !lockfile_path.exists() {
        return Ok(());
    }

    let lockfile = rusk_lockfile::load_lockfile(&lockfile_path)
        .map_err(|e| miette::miette!("failed to read rusk.lock: {}", e))?;

    let mut updated = lockfile.clone();
    let mut removed_keys: Vec<String> = Vec::new();

    // Find and remove matching packages from the lockfile
    let keys_to_remove: Vec<String> = updated
        .packages
        .keys()
        .filter(|key| {
            let key_lower = key.to_lowercase();
            packages.iter().any(|pkg| {
                let pkg_lower = pkg.to_lowercase();
                // Match on the package name portion of the canonical ID
                // Canonical IDs look like "js:registry.npmjs.org/express" or "python:pypi.org/requests"
                key_lower.ends_with(&format!("/{pkg_lower}"))
                    || key_lower == pkg_lower
            })
        })
        .cloned()
        .collect();

    for key in &keys_to_remove {
        updated.packages.remove(key);
        removed_keys.push(key.clone());
    }

    if !removed_keys.is_empty() {
        rusk_lockfile::save_lockfile(&updated, &lockfile_path)
            .map_err(|e| miette::miette!("failed to write rusk.lock: {}", e))?;

        for key in &removed_keys {
            crate::output::print_info(&format!("Removed {key} from rusk.lock"));
        }
    }

    Ok(())
}
