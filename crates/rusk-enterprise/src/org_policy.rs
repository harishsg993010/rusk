//! Organization-level policy overrides.
//!
//! Allows organizations to enforce policies (e.g., minimum signing requirements,
//! approved registries, blocked packages) across all projects.

use serde::{Deserialize, Serialize};

/// Organization-level policy configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrgPolicyConfig {
    /// Minimum required trust class for all packages.
    pub minimum_trust_class: Option<String>,
    /// List of approved registry URLs.
    pub approved_registries: Vec<String>,
    /// List of blocked package patterns.
    pub blocked_packages: Vec<String>,
    /// Whether to require provenance for all packages.
    pub require_provenance: bool,
    /// Whether to require signatures for all packages.
    pub require_signatures: bool,
    /// Maximum allowed age for transparency log inclusion (hours).
    pub max_transparency_staleness_hours: Option<u64>,
}

/// An organization-wide policy document.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrgPolicy {
    /// Policy version for change tracking.
    pub version: u64,
    /// Human-readable policy name.
    pub name: String,
    /// Policy configuration.
    pub config: OrgPolicyConfig,
}

/// Evaluates packages against organization policies.
pub struct OrgPolicyEvaluator {
    policy: OrgPolicy,
}

impl OrgPolicyEvaluator {
    /// Create a new evaluator with the given organization policy.
    pub fn new(policy: OrgPolicy) -> Self {
        Self { policy }
    }

    /// Check if a registry URL is approved.
    pub fn is_registry_approved(&self, registry_url: &str) -> bool {
        if self.policy.config.approved_registries.is_empty() {
            return true; // No restrictions
        }
        self.policy
            .config
            .approved_registries
            .iter()
            .any(|r| registry_url.starts_with(r))
    }

    /// Check if a package name is blocked.
    pub fn is_package_blocked(&self, package_name: &str) -> bool {
        self.policy.config.blocked_packages.iter().any(|pattern| {
            if pattern.ends_with('*') {
                package_name.starts_with(pattern.trim_end_matches('*'))
            } else {
                package_name == pattern
            }
        })
    }

    /// Get a reference to the policy.
    pub fn policy(&self) -> &OrgPolicy {
        &self.policy
    }
}
