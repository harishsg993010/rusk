//! Enterprise configuration types.
//!
//! Defines the configuration schema for enterprise deployments, including
//! internal registries, package controls, and organizational policies.

use rusk_core::{Ecosystem, RegistryUrl};
use serde::{Deserialize, Serialize};
use url::Url;

/// Top-level enterprise configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnterpriseConfig {
    /// Organization identifier.
    pub org_id: String,
    /// Internal registry configurations.
    #[serde(default)]
    pub registries: Vec<InternalRegistryConfig>,
    /// Package-level controls.
    #[serde(default)]
    pub package_controls: PackageControls,
    /// Path to the enterprise policy file.
    pub policy_file: Option<String>,
    /// Whether air-gap mode is enabled.
    #[serde(default)]
    pub airgap_mode: bool,
    /// URL for the enterprise audit log endpoint.
    pub audit_endpoint: Option<Url>,
}

impl EnterpriseConfig {
    /// Create a minimal configuration for the given organization.
    pub fn new(org_id: &str) -> Self {
        Self {
            org_id: org_id.to_string(),
            registries: Vec::new(),
            package_controls: PackageControls::default(),
            policy_file: None,
            airgap_mode: false,
            audit_endpoint: None,
        }
    }

    /// Find the internal registry for a given ecosystem.
    pub fn registry_for_ecosystem(&self, ecosystem: Ecosystem) -> Option<&InternalRegistryConfig> {
        self.registries.iter().find(|r| r.ecosystem == ecosystem)
    }

    /// Whether this configuration has any internal registries.
    pub fn has_internal_registries(&self) -> bool {
        !self.registries.is_empty()
    }
}

/// Configuration for an internal (enterprise) package registry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InternalRegistryConfig {
    /// Human-readable name for this registry.
    pub name: String,
    /// Registry URL.
    pub url: RegistryUrl,
    /// Which ecosystem this registry serves.
    pub ecosystem: Ecosystem,
    /// Whether this registry requires authentication.
    #[serde(default)]
    pub auth_required: bool,
    /// Token environment variable name for authentication.
    pub auth_token_env: Option<String>,
    /// Whether packages from this registry are considered internal.
    #[serde(default = "default_true")]
    pub is_internal: bool,
    /// Namespaces/scopes that belong to this registry.
    #[serde(default)]
    pub namespaces: Vec<String>,
}

fn default_true() -> bool {
    true
}

/// Package-level controls for enterprise environments.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PackageControls {
    /// Packages that are explicitly allowed.
    #[serde(default)]
    pub allowlist: Vec<String>,
    /// Packages that are explicitly blocked.
    #[serde(default)]
    pub blocklist: Vec<String>,
    /// Maximum number of transitive dependencies allowed.
    pub max_transitive_deps: Option<u32>,
    /// Maximum allowed depth of the dependency tree.
    pub max_depth: Option<u32>,
    /// Whether to require signatures on all packages.
    #[serde(default)]
    pub require_signatures: bool,
    /// Whether to require provenance on all packages.
    #[serde(default)]
    pub require_provenance: bool,
    /// Minimum age (in hours) before a new version can be installed.
    pub quarantine_hours: Option<u64>,
}

impl PackageControls {
    /// Check if a package name is explicitly allowed.
    pub fn is_allowed(&self, name: &str) -> bool {
        if self.allowlist.is_empty() {
            // No allowlist means everything is allowed (unless blocked)
            !self.is_blocked(name)
        } else {
            self.allowlist.iter().any(|a| pattern_matches(a, name))
        }
    }

    /// Check if a package name is explicitly blocked.
    pub fn is_blocked(&self, name: &str) -> bool {
        self.blocklist.iter().any(|b| pattern_matches(b, name))
    }
}

/// Simple glob-like pattern matching for package names.
fn pattern_matches(pattern: &str, name: &str) -> bool {
    if pattern.ends_with('*') {
        let prefix = &pattern[..pattern.len() - 1];
        name.starts_with(prefix)
    } else {
        pattern == name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_controls_allowlist() {
        let controls = PackageControls {
            allowlist: vec!["@myorg/*".to_string(), "lodash".to_string()],
            ..Default::default()
        };
        assert!(controls.is_allowed("@myorg/utils"));
        assert!(controls.is_allowed("lodash"));
        assert!(!controls.is_allowed("express"));
    }

    #[test]
    fn package_controls_blocklist() {
        let controls = PackageControls {
            blocklist: vec!["evil-*".to_string()],
            ..Default::default()
        };
        assert!(controls.is_blocked("evil-package"));
        assert!(!controls.is_blocked("good-package"));
    }

    #[test]
    fn empty_allowlist_means_all_allowed() {
        let controls = PackageControls::default();
        assert!(controls.is_allowed("anything"));
    }
}
