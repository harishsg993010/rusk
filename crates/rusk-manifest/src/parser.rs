//! Manifest parsing.
//!
//! Reads and parses rusk.toml files from disk or strings.
//! Also supports importing dependencies from requirements.txt,
//! pyproject.toml, and package.json.

use crate::schema::{
    DependencyEntry, JsDependencies, Manifest, PackageMetadata, PythonDependencies,
};
use rusk_core::Ecosystem;
use std::collections::HashMap;
use std::path::Path;
use tracing::{debug, instrument};

/// Error type for manifest parsing operations.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("manifest file not found: {0}")]
    NotFound(std::path::PathBuf),

    #[error("failed to read manifest: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("invalid format: {0}")]
    InvalidFormat(String),
}

/// Parse a manifest from a TOML string.
///
/// This is the core parsing function. It deserializes the TOML content
/// into a `Manifest` struct.
///
/// # Errors
///
/// Returns `ParseError::Toml` if the string is not valid TOML or does
/// not conform to the manifest schema.
pub fn parse_manifest(content: &str) -> Result<Manifest, ParseError> {
    let manifest: Manifest = toml::from_str(content)?;
    Ok(manifest)
}

/// Load and parse a manifest from a file path.
///
/// Reads the file at `path` and parses it as a rusk.toml manifest.
///
/// # Errors
///
/// - `ParseError::NotFound` if the file doesn't exist
/// - `ParseError::Io` on read failure
/// - `ParseError::Toml` on parse failure
#[instrument(fields(path = %path.display()))]
pub fn load_manifest(path: &Path) -> Result<Manifest, ParseError> {
    if !path.exists() {
        return Err(ParseError::NotFound(path.to_path_buf()));
    }
    debug!("loading manifest from {}", path.display());
    let content = std::fs::read_to_string(path)?;
    parse_manifest(&content)
}

/// Parse a pip `requirements.txt` file into a [`Manifest`].
///
/// Each non-blank, non-comment line is treated as a PEP 508 dependency
/// specifier. Lines starting with flags (`-r`, `-e`, `-f`, `--`) are
/// skipped. Environment markers after `;` are stripped.
///
/// The returned manifest has `ecosystem = "python"` with all entries
/// placed in `python_dependencies.dependencies`.
pub fn parse_requirements_txt(content: &str) -> Result<Manifest, ParseError> {
    let mut deps: HashMap<String, DependencyEntry> = HashMap::new();

    for line in content.lines() {
        let line = line.trim();

        // Skip blanks and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Skip pip flags: -r, -e, -f, --index-url, etc.
        if line.starts_with('-') {
            continue;
        }

        // Strip environment markers (everything after `;`)
        let line = if let Some(idx) = line.find(';') {
            line[..idx].trim()
        } else {
            line
        };

        if line.is_empty() {
            continue;
        }

        // Split on version specifier operators: >=, ==, ~=, !=, <=, <, >
        // Also handle extras like `package[extra]>=1.0`
        let (name, version) = parse_pep508_line(line);

        deps.insert(name, DependencyEntry::Simple(version));
    }

    Ok(Manifest {
        package: PackageMetadata {
            name: "imported-project".to_string(),
            version: None,
            ecosystem: Ecosystem::Python,
            description: None,
            authors: Vec::new(),
            license: None,
            repository: None,
            homepage: None,
            keywords: Vec::new(),
        },
        js_dependencies: None,
        python_dependencies: Some(PythonDependencies {
            dependencies: deps,
            dev_dependencies: HashMap::new(),
            extras: HashMap::new(),
            requires_python: None,
        }),
        trust: None,
        registries: None,
        workspace: None,
        build: None,
    })
}

/// Parse a single PEP 508 dependency line into (name, version_spec).
///
/// Handles forms like:
/// - `requests`
/// - `requests>=2.28`
/// - `requests[security]>=2.28`
/// - `requests==2.28.1`
fn parse_pep508_line(line: &str) -> (String, String) {
    // Strip extras like [security,socks]
    let line_no_extras = if let Some(bracket_start) = line.find('[') {
        if let Some(bracket_end) = line[bracket_start..].find(']') {
            format!(
                "{}{}",
                &line[..bracket_start],
                &line[bracket_start + bracket_end + 1..]
            )
        } else {
            line.to_string()
        }
    } else {
        line.to_string()
    };

    // Find version specifier start
    let version_ops = [">=", "==", "~=", "!=", "<=", "<", ">"];
    for op in &version_ops {
        if let Some(idx) = line_no_extras.find(op) {
            let name = line_no_extras[..idx].trim().to_lowercase();
            let version = line_no_extras[idx..].trim().to_string();
            return (name, version);
        }
    }

    // No version specifier — bare package name
    (line_no_extras.trim().to_lowercase(), "*".to_string())
}

/// Parse a `pyproject.toml` file (PEP 621 / Poetry format) into a [`Manifest`].
///
/// Reads `[project]` for name, version, and dependencies (PEP 621).
/// Reads `[project.optional-dependencies]` for dev/extras.
/// Falls back to `[tool.poetry.dependencies]` for Poetry projects.
pub fn parse_pyproject_toml(content: &str) -> Result<Manifest, ParseError> {
    let doc: toml::Value = toml::from_str(content)?;

    let mut name = "imported-project".to_string();
    let mut version: Option<String> = None;
    let mut deps: HashMap<String, DependencyEntry> = HashMap::new();
    let mut dev_deps: HashMap<String, DependencyEntry> = HashMap::new();
    let mut requires_python: Option<String> = None;

    // PEP 621: [project] table
    if let Some(project) = doc.get("project").and_then(|v| v.as_table()) {
        if let Some(n) = project.get("name").and_then(|v| v.as_str()) {
            name = n.to_string();
        }
        if let Some(v) = project.get("version").and_then(|v| v.as_str()) {
            version = Some(v.to_string());
        }
        if let Some(rp) = project.get("requires-python").and_then(|v| v.as_str()) {
            requires_python = Some(rp.to_string());
        }

        // [project.dependencies] is an array of PEP 508 strings
        if let Some(dep_array) = project.get("dependencies").and_then(|v| v.as_array()) {
            for dep_val in dep_array {
                if let Some(dep_str) = dep_val.as_str() {
                    let (dep_name, dep_version) = parse_pep508_line(dep_str);
                    deps.insert(dep_name, DependencyEntry::Simple(dep_version));
                }
            }
        }

        // [project.optional-dependencies] — treat all groups as dev deps
        if let Some(opt_deps) = project.get("optional-dependencies").and_then(|v| v.as_table()) {
            for (_group, group_deps) in opt_deps {
                if let Some(group_array) = group_deps.as_array() {
                    for dep_val in group_array {
                        if let Some(dep_str) = dep_val.as_str() {
                            let (dep_name, dep_version) = parse_pep508_line(dep_str);
                            dev_deps.insert(dep_name, DependencyEntry::Simple(dep_version));
                        }
                    }
                }
            }
        }
    }

    // Poetry fallback: [tool.poetry.dependencies]
    if deps.is_empty() {
        if let Some(tool) = doc.get("tool").and_then(|v| v.as_table()) {
            if let Some(poetry) = tool.get("poetry").and_then(|v| v.as_table()) {
                if let Some(n) = poetry.get("name").and_then(|v| v.as_str()) {
                    name = n.to_string();
                }
                if let Some(v) = poetry.get("version").and_then(|v| v.as_str()) {
                    version = Some(v.to_string());
                }

                if let Some(poetry_deps) = poetry.get("dependencies").and_then(|v| v.as_table()) {
                    for (dep_name, dep_val) in poetry_deps {
                        // Skip python itself
                        if dep_name == "python" {
                            if let Some(py_ver) = dep_val.as_str() {
                                requires_python = Some(py_ver.to_string());
                            }
                            continue;
                        }
                        let dep_version = if let Some(s) = dep_val.as_str() {
                            s.to_string()
                        } else if let Some(t) = dep_val.as_table() {
                            t.get("version")
                                .and_then(|v| v.as_str())
                                .unwrap_or("*")
                                .to_string()
                        } else {
                            "*".to_string()
                        };
                        deps.insert(dep_name.clone(), DependencyEntry::Simple(dep_version));
                    }
                }

                // Poetry dev-dependencies
                if let Some(poetry_dev) =
                    poetry.get("dev-dependencies").and_then(|v| v.as_table())
                {
                    for (dep_name, dep_val) in poetry_dev {
                        let dep_version = if let Some(s) = dep_val.as_str() {
                            s.to_string()
                        } else if let Some(t) = dep_val.as_table() {
                            t.get("version")
                                .and_then(|v| v.as_str())
                                .unwrap_or("*")
                                .to_string()
                        } else {
                            "*".to_string()
                        };
                        dev_deps.insert(dep_name.clone(), DependencyEntry::Simple(dep_version));
                    }
                }
            }
        }
    }

    Ok(Manifest {
        package: PackageMetadata {
            name,
            version,
            ecosystem: Ecosystem::Python,
            description: None,
            authors: Vec::new(),
            license: None,
            repository: None,
            homepage: None,
            keywords: Vec::new(),
        },
        js_dependencies: None,
        python_dependencies: Some(PythonDependencies {
            dependencies: deps,
            dev_dependencies: dev_deps,
            extras: HashMap::new(),
            requires_python,
        }),
        trust: None,
        registries: None,
        workspace: None,
        build: None,
    })
}

/// Parse a `package.json` file into a [`Manifest`].
///
/// Reads `name`, `version`, `dependencies`, and `devDependencies`.
/// The returned manifest has `ecosystem = "js"`.
pub fn parse_package_json(content: &str) -> Result<Manifest, ParseError> {
    let doc: serde_json::Value = serde_json::from_str(content)?;

    let name = doc
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("imported-project")
        .to_string();

    let version = doc
        .get("version")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let mut deps: HashMap<String, DependencyEntry> = HashMap::new();
    let mut dev_deps: HashMap<String, DependencyEntry> = HashMap::new();

    if let Some(dependencies) = doc.get("dependencies").and_then(|v| v.as_object()) {
        for (dep_name, dep_val) in dependencies {
            if let Some(ver) = dep_val.as_str() {
                deps.insert(dep_name.clone(), DependencyEntry::Simple(ver.to_string()));
            }
        }
    }

    if let Some(dev_dependencies) = doc.get("devDependencies").and_then(|v| v.as_object()) {
        for (dep_name, dep_val) in dev_dependencies {
            if let Some(ver) = dep_val.as_str() {
                dev_deps.insert(dep_name.clone(), DependencyEntry::Simple(ver.to_string()));
            }
        }
    }

    Ok(Manifest {
        package: PackageMetadata {
            name,
            version,
            ecosystem: Ecosystem::Js,
            description: None,
            authors: Vec::new(),
            license: None,
            repository: None,
            homepage: None,
            keywords: Vec::new(),
        },
        js_dependencies: Some(JsDependencies {
            dependencies: deps,
            dev_dependencies: dev_deps,
            peer_dependencies: HashMap::new(),
            optional_dependencies: HashMap::new(),
        }),
        python_dependencies: None,
        trust: None,
        registries: None,
        workspace: None,
        build: None,
    })
}

/// Find and load a manifest by searching upward from a directory.
///
/// Looks for `rusk.toml` starting from `start_dir` and walking up
/// to parent directories until the root is reached.
pub fn find_manifest(start_dir: &Path) -> Result<(std::path::PathBuf, Manifest), ParseError> {
    let mut current = start_dir.to_path_buf();
    loop {
        let candidate = current.join("rusk.toml");
        if candidate.exists() {
            let manifest = load_manifest(&candidate)?;
            return Ok((candidate, manifest));
        }
        if !current.pop() {
            break;
        }
    }
    Err(ParseError::NotFound(start_dir.join("rusk.toml")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusk_core::Ecosystem;

    #[test]
    fn parse_minimal_manifest() {
        let toml_str = r#"
[package]
name = "test-pkg"
ecosystem = "js"
"#;
        let manifest = parse_manifest(toml_str).unwrap();
        assert_eq!(manifest.package.name, "test-pkg");
        assert_eq!(manifest.package.ecosystem, Ecosystem::Js);
        assert!(manifest.js_dependencies.is_none());
    }

    #[test]
    fn parse_full_manifest() {
        let toml_str = r#"
[package]
name = "full-app"
version = "1.0.0"
ecosystem = "js"
description = "A full test app"
authors = ["Test Author <test@example.com>"]
license = "MIT"

[js_dependencies.dependencies]
express = "^4.18.0"

[js_dependencies.dev_dependencies]
jest = "^29.0.0"

[trust]
require_signatures = true
require_provenance = true

[build]
script = "build.sh"
sandbox = true
"#;
        let manifest = parse_manifest(toml_str).unwrap();
        assert_eq!(manifest.package.name, "full-app");
        assert_eq!(manifest.package.version, Some("1.0.0".to_string()));

        let js = manifest.js_dependencies.unwrap();
        assert_eq!(js.dependencies.len(), 1);
        assert_eq!(js.dev_dependencies.len(), 1);

        let trust = manifest.trust.unwrap();
        assert!(trust.require_signatures);
        assert!(trust.require_provenance);

        let build = manifest.build.unwrap();
        assert_eq!(build.script, Some("build.sh".to_string()));
        assert!(build.sandbox);
    }

    #[test]
    fn parse_error_on_invalid_toml() {
        let result = parse_manifest("this is not valid toml {{{}}}");
        assert!(result.is_err());
    }

    #[test]
    fn parse_error_on_missing_required_fields() {
        // Missing ecosystem
        let result = parse_manifest("[package]\nname = \"test\"");
        assert!(result.is_err());
    }

    #[test]
    fn load_nonexistent_file() {
        let result = load_manifest(Path::new("/nonexistent/rusk.toml"));
        assert!(matches!(result, Err(ParseError::NotFound(_))));
    }

    // ---- requirements.txt tests ----

    #[test]
    fn parse_requirements_txt_basic() {
        let content = r#"
# This is a comment
requests>=2.28.0
flask==2.3.2
numpy~=1.24

# Another comment
pandas
"#;
        let manifest = parse_requirements_txt(content).unwrap();
        assert_eq!(manifest.package.ecosystem, Ecosystem::Python);
        let py = manifest.python_dependencies.unwrap();
        assert_eq!(py.dependencies.len(), 4);
        assert_eq!(
            py.dependencies.get("requests").unwrap().version_req(),
            ">=2.28.0"
        );
        assert_eq!(
            py.dependencies.get("flask").unwrap().version_req(),
            "==2.3.2"
        );
        assert_eq!(
            py.dependencies.get("numpy").unwrap().version_req(),
            "~=1.24"
        );
        assert_eq!(py.dependencies.get("pandas").unwrap().version_req(), "*");
    }

    #[test]
    fn parse_requirements_txt_skips_flags_and_markers() {
        let content = r#"
-r base.txt
-e git+https://github.com/foo/bar.git#egg=bar
--index-url https://pypi.org/simple
-f https://download.pytorch.org/whl/torch_stable.html
requests>=2.28 ; python_version >= "3.7"
colorama ; sys_platform == "win32"
"#;
        let manifest = parse_requirements_txt(content).unwrap();
        let py = manifest.python_dependencies.unwrap();
        // Only requests and colorama should be parsed
        assert_eq!(py.dependencies.len(), 2);
        assert!(py.dependencies.contains_key("requests"));
        assert!(py.dependencies.contains_key("colorama"));
        // Markers should be stripped
        assert_eq!(
            py.dependencies.get("requests").unwrap().version_req(),
            ">=2.28"
        );
    }

    #[test]
    fn parse_requirements_txt_with_extras() {
        let content = "requests[security]>=2.28.0\n";
        let manifest = parse_requirements_txt(content).unwrap();
        let py = manifest.python_dependencies.unwrap();
        assert_eq!(py.dependencies.len(), 1);
        assert!(py.dependencies.contains_key("requests"));
        assert_eq!(
            py.dependencies.get("requests").unwrap().version_req(),
            ">=2.28.0"
        );
    }

    #[test]
    fn parse_requirements_txt_empty() {
        let content = "\n# only comments\n\n";
        let manifest = parse_requirements_txt(content).unwrap();
        let py = manifest.python_dependencies.unwrap();
        assert_eq!(py.dependencies.len(), 0);
    }

    // ---- pyproject.toml tests ----

    #[test]
    fn parse_pyproject_toml_pep621() {
        let content = r#"
[project]
name = "my-app"
version = "0.1.0"
requires-python = ">=3.9"
dependencies = [
    "requests>=2.28",
    "flask>=2.3",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0",
    "black",
]
"#;
        let manifest = parse_pyproject_toml(content).unwrap();
        assert_eq!(manifest.package.name, "my-app");
        assert_eq!(manifest.package.version, Some("0.1.0".to_string()));
        assert_eq!(manifest.package.ecosystem, Ecosystem::Python);

        let py = manifest.python_dependencies.unwrap();
        assert_eq!(py.requires_python, Some(">=3.9".to_string()));
        assert_eq!(py.dependencies.len(), 2);
        assert_eq!(
            py.dependencies.get("requests").unwrap().version_req(),
            ">=2.28"
        );
        assert_eq!(py.dev_dependencies.len(), 2);
        assert!(py.dev_dependencies.contains_key("pytest"));
        assert!(py.dev_dependencies.contains_key("black"));
    }

    #[test]
    fn parse_pyproject_toml_poetry() {
        let content = r#"
[tool.poetry]
name = "poetry-app"
version = "1.2.3"

[tool.poetry.dependencies]
python = "^3.9"
requests = "^2.28"
flask = { version = ">=2.3", extras = ["async"] }

[tool.poetry.dev-dependencies]
pytest = "^7.0"
"#;
        let manifest = parse_pyproject_toml(content).unwrap();
        assert_eq!(manifest.package.name, "poetry-app");
        assert_eq!(manifest.package.version, Some("1.2.3".to_string()));

        let py = manifest.python_dependencies.unwrap();
        assert_eq!(py.requires_python, Some("^3.9".to_string()));
        // requests + flask, python is skipped
        assert_eq!(py.dependencies.len(), 2);
        assert!(py.dependencies.contains_key("requests"));
        assert!(py.dependencies.contains_key("flask"));
        assert_eq!(py.dev_dependencies.len(), 1);
        assert!(py.dev_dependencies.contains_key("pytest"));
    }

    // ---- package.json tests ----

    #[test]
    fn parse_package_json_basic() {
        let content = r#"
{
    "name": "my-app",
    "version": "1.0.0",
    "dependencies": {
        "express": "^4.18.0",
        "lodash": "~4.17.21"
    },
    "devDependencies": {
        "jest": "^29.0.0",
        "typescript": "^5.0.0"
    }
}
"#;
        let manifest = parse_package_json(content).unwrap();
        assert_eq!(manifest.package.name, "my-app");
        assert_eq!(manifest.package.version, Some("1.0.0".to_string()));
        assert_eq!(manifest.package.ecosystem, Ecosystem::Js);

        let js = manifest.js_dependencies.unwrap();
        assert_eq!(js.dependencies.len(), 2);
        assert_eq!(
            js.dependencies.get("express").unwrap().version_req(),
            "^4.18.0"
        );
        assert_eq!(
            js.dependencies.get("lodash").unwrap().version_req(),
            "~4.17.21"
        );
        assert_eq!(js.dev_dependencies.len(), 2);
        assert_eq!(
            js.dev_dependencies.get("jest").unwrap().version_req(),
            "^29.0.0"
        );
    }

    #[test]
    fn parse_package_json_no_deps() {
        let content = r#"{ "name": "empty-app", "version": "0.0.1" }"#;
        let manifest = parse_package_json(content).unwrap();
        assert_eq!(manifest.package.name, "empty-app");
        let js = manifest.js_dependencies.unwrap();
        assert_eq!(js.dependencies.len(), 0);
        assert_eq!(js.dev_dependencies.len(), 0);
    }

    #[test]
    fn parse_package_json_invalid() {
        let result = parse_package_json("not json at all {{{");
        assert!(result.is_err());
    }
}
