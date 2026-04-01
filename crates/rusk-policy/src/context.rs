//! Policy evaluation context.
//!
//! Provides the variable bindings that policy expressions can reference.

use rusk_core::{Ecosystem, PackageId, Sha256Digest, TrustClass, Version};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The full context available to policy evaluation.
#[derive(Clone, Debug)]
pub struct PolicyContext {
    /// Information about the artifact being evaluated.
    pub artifact: ArtifactInfo,
    /// Dependency graph context.
    pub graph: GraphContext,
    /// Installation mode.
    pub install_mode: InstallMode,
    /// Additional user-defined variables.
    pub extra: HashMap<String, String>,
}

/// Information about a single artifact under evaluation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArtifactInfo {
    /// Package identity.
    pub package_id: PackageId,
    /// Package version.
    pub version: Version,
    /// Package ecosystem.
    pub ecosystem: Ecosystem,
    /// Content digest.
    pub digest: Sha256Digest,
    /// Whether the artifact has a verified signature.
    pub signature_verified: bool,
    /// Signer identity, if signed.
    pub signer: Option<String>,
    /// Whether provenance was verified.
    pub provenance_verified: bool,
    /// Source repository URL from provenance, if available.
    pub source_repo: Option<String>,
    /// Trust classification.
    pub trust_class: TrustClass,
    /// Whether the artifact appeared in a transparency log.
    pub in_transparency_log: bool,
    /// Whether the artifact has been yanked.
    pub yanked: bool,
    /// Age of the version in hours since publication.
    pub age_hours: u64,
}

/// Dependency graph context for the artifact under evaluation.
#[derive(Clone, Debug, Default)]
pub struct GraphContext {
    /// Depth in the dependency tree (0 = direct dependency).
    pub depth: u32,
    /// Number of dependents (reverse dependencies) in the graph.
    pub dependent_count: u32,
    /// Total number of transitive dependencies this package introduces.
    pub transitive_dep_count: u32,
    /// Whether this is a new addition to the lockfile.
    pub is_new_addition: bool,
    /// Whether this is a version change from what's in the lockfile.
    pub is_version_change: bool,
    /// The previous version, if this is an update.
    pub previous_version: Option<String>,
    /// Whether this is a dev dependency.
    pub is_dev_dependency: bool,
    /// Whether the package has install scripts.
    pub has_install_scripts: bool,
}

/// How the install was initiated.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallMode {
    /// Interactive install (user at terminal).
    Interactive,
    /// CI/CD pipeline (non-interactive).
    Ci,
    /// Lockfile-only mode (no resolution, just verify).
    Frozen,
    /// Development/local mode.
    Dev,
}

impl PolicyContext {
    /// Look up a variable by dotted path name.
    ///
    /// Supported paths:
    /// - `package.name` - package display name
    /// - `package.ecosystem` - "js" or "python"
    /// - `package.namespace` - scope/namespace or ""
    /// - `version` - version string
    /// - `signature.verified` - "true"/"false"
    /// - `signature.signer` - signer identity or ""
    /// - `provenance.verified` - "true"/"false"
    /// - `provenance.source_repo` - source repo URL or ""
    /// - `trust_class` - trust classification string
    /// - `transparency.logged` - "true"/"false"
    /// - `graph.depth` - depth as string
    /// - `graph.is_new` - "true"/"false"
    /// - `graph.is_update` - "true"/"false"
    /// - `install_mode` - install mode string
    /// - `yanked` - "true"/"false"
    /// - `age_hours` - age in hours as string
    pub fn lookup(&self, path: &str) -> Option<String> {
        match path {
            "package.name" => Some(self.artifact.package_id.display_name()),
            "package.ecosystem" => Some(self.artifact.ecosystem.to_string()),
            "package.namespace" => Some(
                self.artifact
                    .package_id
                    .namespace
                    .clone()
                    .unwrap_or_default(),
            ),
            "version" => Some(self.artifact.version.to_string()),
            "signature.verified" => Some(self.artifact.signature_verified.to_string()),
            "signature.signer" => Some(
                self.artifact
                    .signer
                    .clone()
                    .unwrap_or_default(),
            ),
            "provenance.verified" => Some(self.artifact.provenance_verified.to_string()),
            "provenance.source_repo" => Some(
                self.artifact
                    .source_repo
                    .clone()
                    .unwrap_or_default(),
            ),
            "trust_class" => {
                let s = match self.artifact.trust_class {
                    TrustClass::TrustedRelease => "trusted_release",
                    TrustClass::LocalDev => "local_dev",
                    TrustClass::Quarantined => "quarantined",
                    TrustClass::Unverified => "unverified",
                };
                Some(s.to_string())
            }
            "transparency.logged" => Some(self.artifact.in_transparency_log.to_string()),
            "graph.depth" => Some(self.graph.depth.to_string()),
            "graph.dependent_count" => Some(self.graph.dependent_count.to_string()),
            "graph.transitive_dep_count" => Some(self.graph.transitive_dep_count.to_string()),
            "graph.is_new" => Some(self.graph.is_new_addition.to_string()),
            "graph.is_update" => Some(self.graph.is_version_change.to_string()),
            "graph.previous_version" => Some(
                self.graph
                    .previous_version
                    .clone()
                    .unwrap_or_default(),
            ),
            "install_mode" => {
                let s = match self.install_mode {
                    InstallMode::Interactive => "interactive",
                    InstallMode::Ci => "ci",
                    InstallMode::Frozen => "frozen",
                    InstallMode::Dev => "dev",
                };
                Some(s.to_string())
            }
            "yanked" => Some(self.artifact.yanked.to_string()),
            "age_hours" => Some(self.artifact.age_hours.to_string()),
            other => self.extra.get(other).cloned(),
        }
    }

    /// Convert the entire context to a flat key-value map (for debugging/explain).
    pub fn to_flat_map(&self) -> HashMap<String, String> {
        let keys = [
            "package.name",
            "package.ecosystem",
            "package.namespace",
            "version",
            "signature.verified",
            "signature.signer",
            "provenance.verified",
            "provenance.source_repo",
            "trust_class",
            "transparency.logged",
            "graph.depth",
            "graph.dependent_count",
            "graph.transitive_dep_count",
            "graph.is_new",
            "graph.is_update",
            "graph.previous_version",
            "install_mode",
            "yanked",
            "age_hours",
        ];
        let mut map = HashMap::new();
        for key in &keys {
            if let Some(val) = self.lookup(key) {
                map.insert(key.to_string(), val);
            }
        }
        for (k, v) in &self.extra {
            map.insert(k.clone(), v.clone());
        }
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_context() -> PolicyContext {
        PolicyContext {
            artifact: ArtifactInfo {
                package_id: PackageId::js("@scope/foo"),
                version: Version::Semver(semver::Version::new(1, 2, 3)),
                ecosystem: Ecosystem::Js,
                digest: Sha256Digest::zero(),
                signature_verified: true,
                signer: Some("user@example.com".to_string()),
                provenance_verified: false,
                source_repo: None,
                trust_class: TrustClass::TrustedRelease,
                in_transparency_log: true,
                yanked: false,
                age_hours: 72,
            },
            graph: GraphContext {
                depth: 1,
                dependent_count: 5,
                transitive_dep_count: 10,
                is_new_addition: true,
                is_version_change: false,
                previous_version: None,
                is_dev_dependency: false,
                has_install_scripts: false,
            },
            install_mode: InstallMode::Ci,
            extra: HashMap::new(),
        }
    }

    #[test]
    fn lookup_basic_vars() {
        let ctx = test_context();
        assert_eq!(ctx.lookup("package.ecosystem"), Some("js".to_string()));
        assert_eq!(ctx.lookup("signature.verified"), Some("true".to_string()));
        assert_eq!(
            ctx.lookup("signature.signer"),
            Some("user@example.com".to_string())
        );
        assert_eq!(ctx.lookup("graph.depth"), Some("1".to_string()));
        assert_eq!(ctx.lookup("install_mode"), Some("ci".to_string()));
    }

    #[test]
    fn lookup_missing_returns_none() {
        let ctx = test_context();
        assert_eq!(ctx.lookup("nonexistent.var"), None);
    }

    #[test]
    fn flat_map_has_all_keys() {
        let ctx = test_context();
        let map = ctx.to_flat_map();
        assert!(map.contains_key("package.name"));
        assert!(map.contains_key("version"));
        assert!(map.contains_key("install_mode"));
    }
}
