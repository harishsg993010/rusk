use crate::{Ecosystem, RegistryUrl, Sha256Digest, Version};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Fully-qualified package identity, unique across ecosystems and registries.
#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct PackageId {
    pub ecosystem: Ecosystem,
    pub registry: RegistryUrl,
    pub namespace: Option<String>,
    pub name: String,
}

impl PackageId {
    /// Create a JS package ID with default npm registry.
    pub fn js(name: &str) -> Self {
        let (namespace, bare_name) = if let Some(stripped) = name.strip_prefix('@') {
            if let Some((scope, pkg)) = stripped.split_once('/') {
                (Some(format!("@{}", scope)), pkg.to_string())
            } else {
                (None, name.to_string())
            }
        } else {
            (None, name.to_string())
        };

        Self {
            ecosystem: Ecosystem::Js,
            registry: RegistryUrl::npm_default(),
            namespace,
            name: bare_name,
        }
    }

    /// Create a Python package ID with default PyPI registry.
    pub fn python(name: &str) -> Self {
        Self {
            ecosystem: Ecosystem::Python,
            registry: RegistryUrl::pypi_default(),
            namespace: None,
            name: normalize_python_name(name),
        }
    }

    /// Canonical string form: "js:npmjs.org/@scope/name" or "py:pypi.org/requests"
    pub fn canonical(&self) -> String {
        let registry_host = self.registry.host();
        match &self.namespace {
            Some(ns) => format!("{}:{}/{}/{}", self.ecosystem, registry_host, ns, self.name),
            None => format!("{}:{}/{}", self.ecosystem, registry_host, self.name),
        }
    }

    /// Sentinel root package for the resolver.
    pub fn root() -> Self {
        Self {
            ecosystem: Ecosystem::Js,
            registry: RegistryUrl::npm_default(),
            namespace: None,
            name: "__root__".to_string(),
        }
    }

    /// Full display name including scope/namespace.
    pub fn display_name(&self) -> String {
        match &self.namespace {
            Some(ns) => format!("{}/{}", ns, self.name),
            None => self.name.clone(),
        }
    }
}

impl fmt::Debug for PackageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.canonical())
    }
}

impl fmt::Display for PackageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// A specific artifact (file) identity.
#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct ArtifactId {
    pub package: PackageId,
    pub version: Version,
    pub digest: Sha256Digest,
}

impl fmt::Debug for ArtifactId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}#{:?}", self.package, self.version, self.digest)
    }
}

/// Signer identity (OIDC subject or key fingerprint).
#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct SignerIdentity {
    /// OIDC issuer URL (e.g., "https://accounts.google.com").
    pub issuer: String,
    /// OIDC subject (e.g., "user@example.com").
    pub subject: String,
    /// Optional key fingerprint.
    pub fingerprint: Option<String>,
}

impl fmt::Debug for SignerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.subject, self.issuer)
    }
}

impl fmt::Display for SignerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.subject)
    }
}

/// Builder identity for provenance verification.
#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct BuilderIdentity {
    /// Builder type (e.g., "github-actions", "gitlab-ci").
    pub builder_type: String,
    /// Builder ID URL (e.g., "https://github.com/actions/runner").
    pub builder_id: String,
}

impl fmt::Debug for BuilderIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.builder_type, self.builder_id)
    }
}

impl fmt::Display for BuilderIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.builder_type)
    }
}

/// Normalize Python package name per PEP 503.
fn normalize_python_name(name: &str) -> String {
    name.to_lowercase()
        .replace(['-', '.', ' '], "_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn js_scoped_package() {
        let id = PackageId::js("@scope/react");
        assert_eq!(id.namespace, Some("@scope".to_string()));
        assert_eq!(id.name, "react");
        assert_eq!(id.ecosystem, Ecosystem::Js);
    }

    #[test]
    fn js_unscoped_package() {
        let id = PackageId::js("express");
        assert_eq!(id.namespace, None);
        assert_eq!(id.name, "express");
    }

    #[test]
    fn python_package_normalization() {
        let id = PackageId::python("My-Package.Name");
        assert_eq!(id.name, "my_package_name");
    }

    #[test]
    fn canonical_format() {
        let id = PackageId::js("@scope/react");
        assert!(id.canonical().contains("js:"));
        assert!(id.canonical().contains("@scope"));
        assert!(id.canonical().contains("react"));
    }
}
