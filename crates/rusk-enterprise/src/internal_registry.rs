//! Internal/enterprise registry support.
//!
//! Manages connections to internal package registries (Artifactory, Nexus,
//! GitHub Packages, etc.) with authentication and TUF integration.

use serde::{Deserialize, Serialize};
use url::Url;

/// Configuration for an internal registry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InternalRegistryConfig {
    /// Registry URL.
    pub url: Url,
    /// Human-readable name for this registry.
    pub name: String,
    /// Authentication method.
    pub auth: RegistryAuth,
    /// Whether to use TUF for this registry.
    pub tuf_enabled: bool,
    /// Package scopes that should be fetched from this registry.
    pub scopes: Vec<String>,
    /// Priority relative to other registries (lower = preferred).
    pub priority: u32,
}

/// Authentication methods for internal registries.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RegistryAuth {
    /// No authentication required.
    None,
    /// Bearer token authentication.
    Token { token: String },
    /// Basic authentication.
    Basic { username: String, password: String },
    /// Certificate-based mutual TLS.
    MutualTls {
        cert_path: String,
        key_path: String,
    },
}

/// A configured internal registry client.
pub struct InternalRegistry {
    config: InternalRegistryConfig,
}

impl InternalRegistry {
    /// Create a new internal registry client.
    pub fn new(config: InternalRegistryConfig) -> Self {
        Self { config }
    }

    /// Check if a package scope belongs to this registry.
    pub fn handles_scope(&self, scope: &str) -> bool {
        self.config.scopes.iter().any(|s| {
            if s.ends_with('*') {
                scope.starts_with(s.trim_end_matches('*'))
            } else {
                s == scope
            }
        })
    }

    /// Get the registry URL.
    pub fn url(&self) -> &Url {
        &self.config.url
    }

    /// Get the registry name.
    pub fn name(&self) -> &str {
        &self.config.name
    }
}
