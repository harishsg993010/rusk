//! Lockfile schema types.
//!
//! Defines the types that make up a rusk.lock file.

use chrono::{DateTime, Utc};
use rusk_core::{Ecosystem, PackageId, Sha256Digest, Version};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A complete lockfile representing a resolved dependency graph.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Lockfile {
    /// Lockfile format version.
    pub version: u32,
    /// When this lockfile was last updated.
    pub updated_at: DateTime<Utc>,
    /// Integrity root hash covering all locked packages.
    #[serde(default)]
    pub integrity: Option<String>,
    /// Locked packages keyed by canonical ID, sorted for determinism.
    pub packages: BTreeMap<String, LockedPackage>,
}

/// A single locked package entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LockedPackage {
    /// Package identity.
    pub package: PackageId,
    /// Resolved version.
    pub version: Version,
    /// Ecosystem this package belongs to.
    pub ecosystem: Ecosystem,
    /// SHA-256 digest of the artifact.
    pub digest: Sha256Digest,
    /// Download URL where the artifact was obtained.
    #[serde(default)]
    pub source_url: Option<String>,
    /// Direct dependencies (canonical IDs of other locked packages).
    #[serde(default)]
    pub dependencies: Vec<LockedDependency>,
    /// Whether this is a development-only dependency.
    #[serde(default)]
    pub dev: bool,
    /// Signer reference, if the artifact was signed.
    #[serde(default)]
    pub signer: Option<LockedSignerRef>,
    /// Resolution metadata (e.g., which rule resolved it).
    #[serde(default)]
    pub resolved_by: Option<String>,
}

/// A reference to a dependency within the lockfile.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LockedDependency {
    /// Canonical ID of the dependency in the lockfile.
    pub canonical_id: String,
    /// Kind of dependency relationship.
    pub kind: LockedDepKind,
}

/// Kind of locked dependency.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockedDepKind {
    Normal,
    Dev,
    Peer,
    Optional,
    Build,
}

/// Reference to the signer of a locked package.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LockedSignerRef {
    /// Signer identity (e.g., OIDC subject).
    pub identity: String,
    /// Issuer (e.g., OIDC issuer URL).
    pub issuer: String,
    /// When the signature was verified.
    #[serde(default)]
    pub verified_at: Option<DateTime<Utc>>,
}

impl Lockfile {
    /// Create a new empty lockfile.
    pub fn new() -> Self {
        Self {
            version: 1,
            updated_at: Utc::now(),
            integrity: None,
            packages: BTreeMap::new(),
        }
    }

    /// Add a locked package to the lockfile.
    pub fn add_package(&mut self, pkg: LockedPackage) {
        let key = pkg.package.canonical();
        self.packages.insert(key, pkg);
    }

    /// Look up a locked package by its canonical ID.
    pub fn get_package(&self, canonical_id: &str) -> Option<&LockedPackage> {
        self.packages.get(canonical_id)
    }

    /// Check if a package is locked at the expected version and digest.
    pub fn is_locked(
        &self,
        package: &PackageId,
        version: &Version,
        digest: &Sha256Digest,
    ) -> bool {
        let key = package.canonical();
        self.packages
            .get(&key)
            .map(|p| p.version == *version && p.digest == *digest)
            .unwrap_or(false)
    }

    /// Check if a package exists in the lockfile (any version).
    pub fn contains(&self, package: &PackageId) -> bool {
        let key = package.canonical();
        self.packages.contains_key(&key)
    }

    /// Number of locked packages.
    pub fn package_count(&self) -> usize {
        self.packages.len()
    }

    /// Get all package canonical IDs.
    pub fn package_ids(&self) -> Vec<&str> {
        self.packages.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for Lockfile {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_lockfile() {
        let lf = Lockfile::new();
        assert_eq!(lf.version, 1);
        assert_eq!(lf.package_count(), 0);
        assert!(lf.packages.is_empty());
    }

    #[test]
    fn add_and_retrieve_package() {
        let mut lf = Lockfile::new();
        let pkg_id = PackageId::js("express");
        let locked = LockedPackage {
            package: pkg_id.clone(),
            version: Version::Semver(semver::Version::new(4, 18, 2)),
            ecosystem: Ecosystem::Js,
            digest: Sha256Digest::compute(b"test"),
            source_url: Some("https://registry.npmjs.org/express/-/express-4.18.2.tgz".to_string()),
            dependencies: vec![],
            dev: false,
            signer: None,
            resolved_by: None,
        };
        lf.add_package(locked);
        assert_eq!(lf.package_count(), 1);
        assert!(lf.contains(&pkg_id));
    }

    #[test]
    fn is_locked_checks_version_and_digest() {
        let mut lf = Lockfile::new();
        let pkg_id = PackageId::js("lodash");
        let digest = Sha256Digest::compute(b"lodash content");
        let version = Version::Semver(semver::Version::new(4, 17, 21));
        lf.add_package(LockedPackage {
            package: pkg_id.clone(),
            version: version.clone(),
            ecosystem: Ecosystem::Js,
            digest,
            source_url: None,
            dependencies: vec![],
            dev: false,
            signer: None,
            resolved_by: None,
        });

        assert!(lf.is_locked(&pkg_id, &version, &digest));
        // Wrong digest should not match.
        assert!(!lf.is_locked(&pkg_id, &version, &Sha256Digest::zero()));
    }

    #[test]
    fn btree_provides_sorted_keys() {
        let mut lf = Lockfile::new();
        // Add in non-alphabetical order.
        for name in ["zebra", "alpha", "middle"] {
            lf.add_package(LockedPackage {
                package: PackageId::js(name),
                version: Version::Semver(semver::Version::new(1, 0, 0)),
                ecosystem: Ecosystem::Js,
                digest: Sha256Digest::zero(),
                source_url: None,
                dependencies: vec![],
                dev: false,
                signer: None,
                resolved_by: None,
            });
        }
        let ids = lf.package_ids();
        // BTreeMap keys should be sorted.
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
    }
}
