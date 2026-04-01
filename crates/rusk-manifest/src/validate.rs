//! Manifest validation.
//!
//! Validates a parsed manifest for semantic correctness beyond what
//! TOML deserialization can check.

use crate::schema::{DependencyEntry, Manifest};
use std::collections::HashSet;

/// A single validation issue.
#[derive(Clone, Debug)]
pub struct ValidationIssue {
    /// Path to the problematic field (dotted notation).
    pub path: String,
    /// Human-readable description of the issue.
    pub message: String,
    /// Severity level.
    pub severity: ValidationSeverity,
}

/// Severity of a validation issue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationSeverity {
    Error,
    Warning,
}

/// Error type for validation failures.
#[derive(Debug, thiserror::Error)]
#[error("manifest validation failed with {error_count} error(s)")]
pub struct ValidationError {
    /// All issues found during validation.
    pub issues: Vec<ValidationIssue>,
    /// Number of error-severity issues.
    pub error_count: usize,
}

/// Validate a manifest and return any issues found.
///
/// Returns `Ok(warnings)` if no errors are found (warnings are informational),
/// or `Err(ValidationError)` if there are errors.
pub fn validate_manifest(manifest: &Manifest) -> Result<Vec<ValidationIssue>, ValidationError> {
    let mut issues = Vec::new();

    validate_package_metadata(manifest, &mut issues);
    validate_dependencies(manifest, &mut issues);
    validate_trust_config(manifest, &mut issues);
    validate_registries(manifest, &mut issues);
    validate_workspace(manifest, &mut issues);

    let error_count = issues
        .iter()
        .filter(|i| i.severity == ValidationSeverity::Error)
        .count();

    if error_count > 0 {
        Err(ValidationError {
            issues,
            error_count,
        })
    } else {
        Ok(issues)
    }
}

fn validate_package_metadata(manifest: &Manifest, issues: &mut Vec<ValidationIssue>) {
    // Package name must not be empty.
    if manifest.package.name.is_empty() {
        issues.push(ValidationIssue {
            path: "package.name".to_string(),
            message: "package name must not be empty".to_string(),
            severity: ValidationSeverity::Error,
        });
    }

    // Package name should follow naming conventions.
    if manifest.package.name.contains(char::is_uppercase) {
        issues.push(ValidationIssue {
            path: "package.name".to_string(),
            message: "package name should be lowercase".to_string(),
            severity: ValidationSeverity::Warning,
        });
    }

    // Version should be parseable if present.
    if let Some(ref version) = manifest.package.version {
        let valid = match manifest.package.ecosystem {
            rusk_core::Ecosystem::Js => semver::Version::parse(version).is_ok(),
            rusk_core::Ecosystem::Python => version.parse::<pep440_rs::Version>().is_ok(),
        };
        if !valid {
            issues.push(ValidationIssue {
                path: "package.version".to_string(),
                message: format!(
                    "version '{}' is not valid for {} ecosystem",
                    version,
                    manifest.package.ecosystem.display_name()
                ),
                severity: ValidationSeverity::Error,
            });
        }
    }
}

fn validate_dependencies(manifest: &Manifest, issues: &mut Vec<ValidationIssue>) {
    // Check for duplicate dependencies across groups.
    let mut seen_names = HashSet::new();

    if let Some(ref js) = manifest.js_dependencies {
        for (name, entry) in &js.dependencies {
            validate_dependency_entry("js_dependencies.dependencies", name, entry, issues);
            seen_names.insert(name.clone());
        }
        for (name, entry) in &js.dev_dependencies {
            validate_dependency_entry("js_dependencies.dev_dependencies", name, entry, issues);
            if seen_names.contains(name) {
                issues.push(ValidationIssue {
                    path: format!("js_dependencies.dev_dependencies.{}", name),
                    message: format!(
                        "'{}' appears in both dependencies and dev_dependencies",
                        name
                    ),
                    severity: ValidationSeverity::Warning,
                });
            }
        }
    }

    if let Some(ref py) = manifest.python_dependencies {
        seen_names.clear();
        for (name, entry) in &py.dependencies {
            validate_dependency_entry("python_dependencies.dependencies", name, entry, issues);
            seen_names.insert(name.clone());
        }
        for (name, entry) in &py.dev_dependencies {
            validate_dependency_entry("python_dependencies.dev_dependencies", name, entry, issues);
        }
    }
}

fn validate_dependency_entry(
    group: &str,
    name: &str,
    entry: &DependencyEntry,
    issues: &mut Vec<ValidationIssue>,
) {
    let version_str = entry.version_req();
    if version_str.is_empty() && !entry.is_git() {
        issues.push(ValidationIssue {
            path: format!("{}.{}", group, name),
            message: format!("dependency '{}' has empty version requirement", name),
            severity: ValidationSeverity::Error,
        });
    }
}

fn validate_trust_config(manifest: &Manifest, issues: &mut Vec<ValidationIssue>) {
    if let Some(ref trust) = manifest.trust {
        if trust.require_provenance && !trust.require_signatures {
            issues.push(ValidationIssue {
                path: "trust".to_string(),
                message: "require_provenance is set but require_signatures is not; provenance verification typically requires signature verification".to_string(),
                severity: ValidationSeverity::Warning,
            });
        }
    }
}

fn validate_registries(manifest: &Manifest, issues: &mut Vec<ValidationIssue>) {
    if let Some(ref registries) = manifest.registries {
        for (name, config) in registries {
            if url::Url::parse(&config.url).is_err() {
                issues.push(ValidationIssue {
                    path: format!("registries.{}.url", name),
                    message: format!("invalid registry URL: '{}'", config.url),
                    severity: ValidationSeverity::Error,
                });
            }
        }
    }
}

fn validate_workspace(manifest: &Manifest, issues: &mut Vec<ValidationIssue>) {
    if let Some(ref workspace) = manifest.workspace {
        if workspace.members.is_empty() {
            issues.push(ValidationIssue {
                path: "workspace.members".to_string(),
                message: "workspace.members is empty".to_string(),
                severity: ValidationSeverity::Warning,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_manifest;

    #[test]
    fn valid_minimal_manifest() {
        let toml_str = r#"
[package]
name = "test-pkg"
ecosystem = "js"
"#;
        let manifest = parse_manifest(toml_str).unwrap();
        let warnings = validate_manifest(&manifest).unwrap();
        assert!(warnings.is_empty());
    }

    #[test]
    fn empty_name_is_error() {
        let toml_str = r#"
[package]
name = ""
ecosystem = "js"
"#;
        let manifest = parse_manifest(toml_str).unwrap();
        let err = validate_manifest(&manifest).unwrap_err();
        assert!(err.error_count > 0);
        assert!(err.issues.iter().any(|i| i.path == "package.name"));
    }

    #[test]
    fn invalid_version_is_error() {
        let toml_str = r#"
[package]
name = "test"
version = "not-a-version"
ecosystem = "js"
"#;
        let manifest = parse_manifest(toml_str).unwrap();
        let err = validate_manifest(&manifest).unwrap_err();
        assert!(err.issues.iter().any(|i| i.path == "package.version"));
    }

    #[test]
    fn uppercase_name_is_warning() {
        let toml_str = r#"
[package]
name = "MyPackage"
ecosystem = "js"
"#;
        let manifest = parse_manifest(toml_str).unwrap();
        let warnings = validate_manifest(&manifest).unwrap();
        assert!(warnings.iter().any(|w| w.path == "package.name"));
    }

    #[test]
    fn invalid_registry_url_is_error() {
        let toml_str = r#"
[package]
name = "test"
ecosystem = "js"

[registries.my-registry]
url = "not a url"
"#;
        let manifest = parse_manifest(toml_str).unwrap();
        let err = validate_manifest(&manifest).unwrap_err();
        assert!(err
            .issues
            .iter()
            .any(|i| i.path.contains("registries")));
    }
}
