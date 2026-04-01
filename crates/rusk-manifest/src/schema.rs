//! Manifest schema types.
//!
//! Defines all the types that make up a rusk.toml manifest file.

use rusk_core::Ecosystem;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A complete rusk.toml manifest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Manifest {
    /// Package metadata.
    pub package: PackageMetadata,
    /// JavaScript dependencies (if applicable).
    #[serde(default)]
    pub js_dependencies: Option<JsDependencies>,
    /// Python dependencies (if applicable).
    #[serde(default)]
    pub python_dependencies: Option<PythonDependencies>,
    /// Trust/security configuration.
    #[serde(default)]
    pub trust: Option<TrustConfig>,
    /// Registry configuration.
    #[serde(default)]
    pub registries: Option<HashMap<String, RegistryConfig>>,
    /// Workspace configuration (for monorepos).
    #[serde(default)]
    pub workspace: Option<WorkspaceConfig>,
    /// Build configuration.
    #[serde(default)]
    pub build: Option<BuildConfig>,
}

/// Package-level metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PackageMetadata {
    /// Package name.
    pub name: String,
    /// Package version.
    #[serde(default)]
    pub version: Option<String>,
    /// Primary ecosystem.
    pub ecosystem: Ecosystem,
    /// Human-readable description.
    #[serde(default)]
    pub description: Option<String>,
    /// Authors.
    #[serde(default)]
    pub authors: Vec<String>,
    /// License identifier (SPDX).
    #[serde(default)]
    pub license: Option<String>,
    /// Repository URL.
    #[serde(default)]
    pub repository: Option<String>,
    /// Homepage URL.
    #[serde(default)]
    pub homepage: Option<String>,
    /// Keywords for discovery.
    #[serde(default)]
    pub keywords: Vec<String>,
}

/// JavaScript dependency declarations.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct JsDependencies {
    /// Production dependencies: name => semver range.
    #[serde(default)]
    pub dependencies: HashMap<String, DependencyEntry>,
    /// Development dependencies.
    #[serde(default)]
    pub dev_dependencies: HashMap<String, DependencyEntry>,
    /// Peer dependencies.
    #[serde(default)]
    pub peer_dependencies: HashMap<String, DependencyEntry>,
    /// Optional dependencies.
    #[serde(default)]
    pub optional_dependencies: HashMap<String, DependencyEntry>,
}

/// Python dependency declarations.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PythonDependencies {
    /// Production dependencies: name => PEP 440 specifier.
    #[serde(default)]
    pub dependencies: HashMap<String, DependencyEntry>,
    /// Development dependencies.
    #[serde(default)]
    pub dev_dependencies: HashMap<String, DependencyEntry>,
    /// Optional dependency groups (extras).
    #[serde(default)]
    pub extras: HashMap<String, Vec<String>>,
    /// Required Python version.
    #[serde(default)]
    pub requires_python: Option<String>,
}

/// A single dependency declaration.
///
/// Can be a simple version string or a detailed entry with registry/features.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DependencyEntry {
    /// Simple version string: `"^1.0.0"`.
    Simple(String),
    /// Detailed dependency with extra options.
    Detailed(DetailedDependency),
}

/// Detailed dependency with additional configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DetailedDependency {
    /// Version requirement string.
    pub version: String,
    /// Override registry name for this dependency.
    #[serde(default)]
    pub registry: Option<String>,
    /// Whether this dependency is optional.
    #[serde(default)]
    pub optional: bool,
    /// Features/extras to enable.
    #[serde(default)]
    pub features: Vec<String>,
    /// Git repository URL (alternative to registry).
    #[serde(default)]
    pub git: Option<String>,
    /// Git branch.
    #[serde(default)]
    pub branch: Option<String>,
    /// Git tag.
    #[serde(default)]
    pub tag: Option<String>,
}

/// Trust and security policy configuration.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TrustConfig {
    /// Path to the policy file.
    #[serde(default)]
    pub policy: Option<String>,
    /// Whether signatures are required.
    #[serde(default)]
    pub require_signatures: bool,
    /// Whether provenance is required.
    #[serde(default)]
    pub require_provenance: bool,
    /// Whether transparency log inclusion is required.
    #[serde(default)]
    pub require_transparency: bool,
    /// Trusted signer identities.
    #[serde(default)]
    pub trusted_signers: Vec<String>,
    /// Trusted builder identities for provenance.
    #[serde(default)]
    pub trusted_builders: Vec<String>,
    /// Quarantine duration for new packages (in hours).
    #[serde(default)]
    pub quarantine_hours: Option<u64>,
}

/// Registry configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistryConfig {
    /// Registry URL.
    pub url: String,
    /// Registry type.
    #[serde(default = "default_registry_type")]
    pub registry_type: String,
    /// Authentication token environment variable name.
    #[serde(default)]
    pub auth_token_env: Option<String>,
    /// Whether to use TUF for this registry.
    #[serde(default)]
    pub tuf: bool,
}

fn default_registry_type() -> String {
    "public".to_string()
}

/// Workspace configuration for monorepo setups.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WorkspaceConfig {
    /// Glob patterns for workspace member directories.
    #[serde(default)]
    pub members: Vec<String>,
    /// Glob patterns for excluded directories.
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Shared dependency versions across workspace members.
    #[serde(default)]
    pub shared_dependencies: HashMap<String, String>,
}

/// Build configuration.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BuildConfig {
    /// Build script path.
    #[serde(default)]
    pub script: Option<String>,
    /// Whether to run builds in a sandbox.
    #[serde(default)]
    pub sandbox: bool,
    /// Environment variables to pass to the build.
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// Pre-build hooks.
    #[serde(default)]
    pub pre_build: Vec<String>,
    /// Post-build hooks.
    #[serde(default)]
    pub post_build: Vec<String>,
}

impl DependencyEntry {
    /// Get the version requirement string regardless of variant.
    pub fn version_req(&self) -> &str {
        match self {
            DependencyEntry::Simple(v) => v,
            DependencyEntry::Detailed(d) => &d.version,
        }
    }

    /// Whether this is a git dependency.
    pub fn is_git(&self) -> bool {
        match self {
            DependencyEntry::Simple(_) => false,
            DependencyEntry::Detailed(d) => d.git.is_some(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_manifest_toml() {
        let toml_str = r#"
[package]
name = "my-app"
ecosystem = "js"
description = "A test app"

[js_dependencies.dependencies]
express = "^4.18.0"
lodash = { version = "^4.17.0", optional = true }

[trust]
require_signatures = true
trusted_signers = ["user@example.com"]
"#;
        let manifest: Manifest = toml::from_str(toml_str).unwrap();
        assert_eq!(manifest.package.name, "my-app");
        assert_eq!(manifest.package.ecosystem, Ecosystem::Js);

        let js_deps = manifest.js_dependencies.unwrap();
        assert_eq!(js_deps.dependencies.len(), 2);

        let trust = manifest.trust.unwrap();
        assert!(trust.require_signatures);
        assert_eq!(trust.trusted_signers, vec!["user@example.com"]);
    }

    #[test]
    fn dependency_entry_version_req() {
        let simple = DependencyEntry::Simple("^1.0.0".to_string());
        assert_eq!(simple.version_req(), "^1.0.0");
        assert!(!simple.is_git());

        let detailed = DependencyEntry::Detailed(DetailedDependency {
            version: ">=2.0".to_string(),
            registry: None,
            optional: false,
            features: vec![],
            git: Some("https://github.com/foo/bar".to_string()),
            branch: Some("main".to_string()),
            tag: None,
        });
        assert_eq!(detailed.version_req(), ">=2.0");
        assert!(detailed.is_git());
    }

    #[test]
    fn python_manifest() {
        let toml_str = r#"
[package]
name = "my-py-app"
ecosystem = "python"

[python_dependencies]
requires_python = ">=3.9"

[python_dependencies.dependencies]
requests = ">=2.28"
flask = { version = ">=2.3", features = ["async"] }

[python_dependencies.extras]
dev = ["pytest>=7.0", "black"]
"#;
        let manifest: Manifest = toml::from_str(toml_str).unwrap();
        assert_eq!(manifest.package.ecosystem, Ecosystem::Python);
        let py_deps = manifest.python_dependencies.unwrap();
        assert_eq!(py_deps.requires_python, Some(">=3.9".to_string()));
        assert_eq!(py_deps.dependencies.len(), 2);
        assert!(py_deps.extras.contains_key("dev"));
    }
}
