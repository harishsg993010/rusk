//! `rusk add` command.
//!
//! Adds a package to the manifest and installs it. Auto-detects the
//! ecosystem from the manifest format:
//!   - package.json → JS only
//!   - requirements.txt / pyproject.toml → Python only
//!   - rusk.toml → reads ecosystem from [package] or --ecosystem flag

use clap::Args;
use miette::Result;
use std::path::PathBuf;

/// Arguments for the add command.
#[derive(Debug, Args)]
pub struct AddArgs {
    /// Packages to add (e.g., "express", "requests>=2.28", "lodash@^4.17").
    #[arg(required = true)]
    pub packages: Vec<String>,

    /// Add as dev dependency.
    #[arg(long, short = 'D')]
    pub dev: bool,

    /// Force a specific ecosystem (js or python). Auto-detected if omitted.
    #[arg(long)]
    pub ecosystem: Option<String>,
}

/// Detected project ecosystem based on manifest files.
enum DetectedEcosystem {
    Js,
    Python,
    Mixed(String), // rusk.toml with explicit ecosystem
}

pub async fn run(args: AddArgs) -> Result<()> {
    let project_dir = std::env::current_dir()
        .map_err(|e| miette::miette!("failed to get current directory: {}", e))?;

    let rusk_toml = project_dir.join("rusk.toml");
    let package_json = project_dir.join("package.json");
    let pyproject_toml = project_dir.join("pyproject.toml");
    let requirements_txt = project_dir.join("requirements.txt");

    // Step 1: Detect ecosystem from existing manifest
    let detected = if rusk_toml.exists() {
        // Read ecosystem from rusk.toml
        let content = std::fs::read_to_string(&rusk_toml)
            .map_err(|e| miette::miette!("failed to read rusk.toml: {}", e))?;
        let doc: toml::Value = toml::from_str(&content)
            .map_err(|e| miette::miette!("failed to parse rusk.toml: {}", e))?;
        let eco = doc.get("package")
            .and_then(|p| p.get("ecosystem"))
            .and_then(|e| e.as_str())
            .unwrap_or("js")
            .to_string();
        Some(DetectedEcosystem::Mixed(eco))
    } else if package_json.exists() {
        Some(DetectedEcosystem::Js)
    } else if pyproject_toml.exists() || requirements_txt.exists() {
        Some(DetectedEcosystem::Python)
    } else {
        None // No manifest — need --ecosystem
    };

    // Step 2: Determine target ecosystem
    let target_eco = if let Some(ref eco) = args.ecosystem {
        eco.clone()
    } else {
        match &detected {
            Some(DetectedEcosystem::Js) => "js".to_string(),
            Some(DetectedEcosystem::Python) => "python".to_string(),
            Some(DetectedEcosystem::Mixed(eco)) => eco.clone(),
            None => {
                return Err(miette::miette!(
                    "No manifest found. Use --ecosystem js or --ecosystem python to specify."
                ));
            }
        }
    };

    // Step 3: Validate packages match ecosystem
    for pkg in &args.packages {
        let (name, version) = parse_package_spec(pkg);
        validate_package_for_ecosystem(&name, &version, &target_eco)?;
    }

    // Step 4: Add to the correct manifest
    match target_eco.as_str() {
        "js" => {
            if rusk_toml.exists() {
                add_to_rusk_toml(&rusk_toml, &args, "js")?;
            } else if package_json.exists() {
                add_to_package_json(&package_json, &args)?;
            } else {
                // Create package.json
                let content = r#"{"name":"project","version":"0.1.0","dependencies":{}}"#;
                std::fs::write(&package_json, content)
                    .map_err(|e| miette::miette!("failed to create package.json: {}", e))?;
                crate::output::print_info("Created package.json");
                add_to_package_json(&package_json, &args)?;
            }
        }
        "python" | "py" => {
            if rusk_toml.exists() {
                add_to_rusk_toml(&rusk_toml, &args, "python")?;
            } else if pyproject_toml.exists() {
                add_to_pyproject_toml(&pyproject_toml, &args)?;
            } else if requirements_txt.exists() {
                add_to_requirements_txt(&requirements_txt, &args)?;
            } else {
                // Create requirements.txt
                std::fs::write(&requirements_txt, "")
                    .map_err(|e| miette::miette!("failed to create requirements.txt: {}", e))?;
                crate::output::print_info("Created requirements.txt");
                add_to_requirements_txt(&requirements_txt, &args)?;
            }
        }
        other => {
            return Err(miette::miette!("unknown ecosystem: {other}"));
        }
    }

    // Step 5: Install
    crate::output::print_info("Installing...");
    let install_args = super::install::InstallArgs {
        production: false,
        frozen: false,
        lockfile_only: false,
        packages: vec![],
    };
    super::install::run(install_args, crate::output::OutputFormat::Text).await
}

/// Validate that a package spec makes sense for the target ecosystem.
fn validate_package_for_ecosystem(name: &str, version: &str, ecosystem: &str) -> Result<()> {
    match ecosystem {
        "js" => {
            // Python-style version specs in a JS project = likely mistake
            if version.starts_with(">=") || version.starts_with("==") || version.starts_with("~=") {
                crate::output::print_warning(&format!(
                    "'{name}{version}' looks like a Python package spec. Did you mean --ecosystem python?"
                ));
            }
        }
        "python" | "py" => {
            // npm-style @ version in a Python project = likely mistake
            if version.starts_with('^') || version.starts_with('~') {
                // ^ and ~ are npm semver ranges, not PEP 440
                crate::output::print_warning(&format!(
                    "'{name}@{version}' looks like an npm package spec. Did you mean --ecosystem js?"
                ));
            }
            // Scoped npm packages in Python = definitely wrong
            if name.starts_with('@') {
                return Err(miette::miette!(
                    "'{name}' is a scoped npm package. Use --ecosystem js for JavaScript packages."
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

fn add_to_rusk_toml(path: &PathBuf, args: &AddArgs, eco: &str) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| miette::miette!("failed to read rusk.toml: {}", e))?;

    let mut doc: toml::Value = toml::from_str(&content)
        .map_err(|e| miette::miette!("failed to parse rusk.toml: {}", e))?;

    for pkg_spec in &args.packages {
        let (name, version) = parse_package_spec(pkg_spec);
        crate::output::print_info(&format!("Adding {name} ({eco})"));

        match eco {
            "js" => {
                let section = if args.dev { "dev_dependencies" } else { "dependencies" };
                let deps = doc.as_table_mut().unwrap()
                    .entry("js_dependencies").or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
                    .as_table_mut().ok_or_else(|| miette::miette!("invalid js_dependencies"))?
                    .entry(section).or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
                    .as_table_mut().ok_or_else(|| miette::miette!("invalid {}", section))?;
                deps.insert(name, toml::Value::String(version));
            }
            "python" | "py" => {
                let section = if args.dev { "dev_dependencies" } else { "dependencies" };
                let deps = doc.as_table_mut().unwrap()
                    .entry("python_dependencies").or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
                    .as_table_mut().ok_or_else(|| miette::miette!("invalid python_dependencies"))?
                    .entry(section).or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
                    .as_table_mut().ok_or_else(|| miette::miette!("invalid {}", section))?;
                deps.insert(name, toml::Value::String(version));
            }
            _ => return Err(miette::miette!("unknown ecosystem: {}", eco)),
        }
    }

    let output = toml::to_string_pretty(&doc)
        .map_err(|e| miette::miette!("failed to serialize rusk.toml: {}", e))?;
    std::fs::write(path, output)
        .map_err(|e| miette::miette!("failed to write rusk.toml: {}", e))?;

    Ok(())
}

fn add_to_package_json(path: &PathBuf, args: &AddArgs) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| miette::miette!("failed to read package.json: {}", e))?;

    let mut doc: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| miette::miette!("failed to parse package.json: {}", e))?;

    let section = if args.dev { "devDependencies" } else { "dependencies" };

    if doc.get(section).is_none() {
        doc[section] = serde_json::json!({});
    }

    for pkg_spec in &args.packages {
        let (name, version) = parse_package_spec(pkg_spec);
        let version = if version == "*" { "latest".to_string() } else { version };
        crate::output::print_info(&format!("Adding {name}@{version} to {section}"));
        doc[section][&name] = serde_json::Value::String(version);
    }

    let output = serde_json::to_string_pretty(&doc)
        .map_err(|e| miette::miette!("failed to serialize package.json: {}", e))?;
    std::fs::write(path, output)
        .map_err(|e| miette::miette!("failed to write package.json: {}", e))?;

    Ok(())
}

fn add_to_pyproject_toml(path: &PathBuf, args: &AddArgs) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| miette::miette!("failed to read pyproject.toml: {}", e))?;

    let mut doc: toml::Value = toml::from_str(&content)
        .map_err(|e| miette::miette!("failed to parse pyproject.toml: {}", e))?;

    for pkg_spec in &args.packages {
        let (name, version) = parse_package_spec(pkg_spec);
        let dep_str = if version == "*" {
            name.clone()
        } else {
            format!("{name}{version}")
        };
        crate::output::print_info(&format!("Adding {dep_str}"));

        if args.dev {
            let opt_deps = doc.as_table_mut().unwrap()
                .entry("project").or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
                .as_table_mut().ok_or_else(|| miette::miette!("invalid project table"))?
                .entry("optional-dependencies").or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
                .as_table_mut().ok_or_else(|| miette::miette!("invalid optional-dependencies"))?
                .entry("dev").or_insert_with(|| toml::Value::Array(vec![]))
                .as_array_mut().ok_or_else(|| miette::miette!("invalid dev array"))?;
            opt_deps.push(toml::Value::String(dep_str));
        } else {
            let deps = doc.as_table_mut().unwrap()
                .entry("project").or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
                .as_table_mut().ok_or_else(|| miette::miette!("invalid project table"))?
                .entry("dependencies").or_insert_with(|| toml::Value::Array(vec![]))
                .as_array_mut().ok_or_else(|| miette::miette!("invalid dependencies"))?;
            deps.push(toml::Value::String(dep_str));
        }
    }

    let output = toml::to_string_pretty(&doc)
        .map_err(|e| miette::miette!("failed to serialize pyproject.toml: {}", e))?;
    std::fs::write(path, output)
        .map_err(|e| miette::miette!("failed to write pyproject.toml: {}", e))?;

    Ok(())
}

fn add_to_requirements_txt(path: &PathBuf, args: &AddArgs) -> Result<()> {
    let mut content = std::fs::read_to_string(path)
        .map_err(|e| miette::miette!("failed to read requirements.txt: {}", e))?;

    for pkg_spec in &args.packages {
        let (name, version) = parse_package_spec(pkg_spec);
        let line = if version == "*" {
            name.clone()
        } else {
            format!("{name}{version}")
        };
        crate::output::print_info(&format!("Adding {line}"));

        if !content.ends_with('\n') && !content.is_empty() {
            content.push('\n');
        }
        content.push_str(&line);
        content.push('\n');
    }

    std::fs::write(path, content)
        .map_err(|e| miette::miette!("failed to write requirements.txt: {}", e))?;

    Ok(())
}

/// Parse "package@version" or "package>=version" or "package" into (name, version_req).
fn parse_package_spec(spec: &str) -> (String, String) {
    // Handle npm-style: lodash@^4.17.0
    if let Some((name, version)) = spec.split_once('@') {
        if !name.is_empty() && !name.starts_with('@') {
            return (name.to_string(), version.to_string());
        }
        // Scoped package like @scope/name@version
        if name.starts_with('@') {
            if let Some((_full_name, ver)) = spec[1..].split_once('@') {
                let scope_end = spec[1..].find('@').unwrap() + 1;
                return (spec[..scope_end].to_string(), ver.to_string());
            }
        }
    }

    // Handle pip-style: requests>=2.28.0
    for op in &[">=", "<=", "==", "~=", "!=", ">", "<"] {
        if let Some(idx) = spec.find(op) {
            let name = spec[..idx].trim().to_string();
            let version = spec[idx..].trim().to_string();
            return (name, version);
        }
    }

    // Just a name
    (spec.to_string(), "*".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_npm_style() {
        let (n, v) = parse_package_spec("lodash@^4.17.21");
        assert_eq!(n, "lodash");
        assert_eq!(v, "^4.17.21");
    }

    #[test]
    fn parse_pip_style() {
        let (n, v) = parse_package_spec("requests>=2.28.0");
        assert_eq!(n, "requests");
        assert_eq!(v, ">=2.28.0");
    }

    #[test]
    fn parse_bare_name() {
        let (n, v) = parse_package_spec("flask");
        assert_eq!(n, "flask");
        assert_eq!(v, "*");
    }

    #[test]
    fn parse_exact_version() {
        let (n, v) = parse_package_spec("six==1.16.0");
        assert_eq!(n, "six");
        assert_eq!(v, "==1.16.0");
    }

    #[test]
    fn validate_scoped_npm_in_python_rejected() {
        let result = validate_package_for_ecosystem("@scope/pkg", "^1.0", "python");
        assert!(result.is_err());
    }
}
