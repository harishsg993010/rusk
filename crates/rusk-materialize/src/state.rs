//! Installation state tracking.
//!
//! Maintains a record of what is currently installed, enabling incremental
//! updates and garbage collection of orphaned packages.

use chrono::{DateTime, Utc};
use rusk_core::{PackageId, Sha256Digest, Version};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

/// Persistent state of the current installation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstallState {
    /// Schema version of the state file.
    pub version: u32,
    /// When this state was last updated.
    pub updated_at: DateTime<Utc>,
    /// Currently installed packages keyed by canonical ID.
    pub packages: HashMap<String, InstalledPackage>,
}

/// Record of a single installed package.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstalledPackage {
    /// Package identity.
    pub package: PackageId,
    /// Installed version.
    pub version: Version,
    /// Content digest.
    pub digest: Sha256Digest,
    /// Path on disk where the package was materialized.
    pub install_path: PathBuf,
    /// When this package was installed.
    pub installed_at: DateTime<Utc>,
}

impl InstallState {
    /// Create a new empty state.
    pub fn new() -> Self {
        Self {
            version: 1,
            updated_at: Utc::now(),
            packages: HashMap::new(),
        }
    }

    /// Load state from a JSON file on disk.
    pub fn load(path: &Path) -> Result<Self, InstallStateError> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let content = std::fs::read_to_string(path)?;
        let state: Self =
            serde_json::from_str(&content).map_err(|e| InstallStateError::Parse(e.to_string()))?;
        Ok(state)
    }

    /// Save state to a JSON file on disk.
    pub fn save(&self, path: &Path) -> Result<(), InstallStateError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| InstallStateError::Parse(e.to_string()))?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Record a package as installed.
    pub fn record_install(
        &mut self,
        package: PackageId,
        version: Version,
        digest: Sha256Digest,
        install_path: PathBuf,
    ) {
        let key = package.canonical();
        self.packages.insert(
            key,
            InstalledPackage {
                package,
                version,
                digest,
                install_path,
                installed_at: Utc::now(),
            },
        );
        self.updated_at = Utc::now();
    }

    /// Remove a package from the installed state.
    pub fn remove(&mut self, package: &PackageId) -> Option<InstalledPackage> {
        let key = package.canonical();
        let result = self.packages.remove(&key);
        if result.is_some() {
            self.updated_at = Utc::now();
        }
        result
    }

    /// Check if a package is installed at the expected version and digest.
    pub fn is_up_to_date(&self, package: &PackageId, version: &Version, digest: &Sha256Digest) -> bool {
        let key = package.canonical();
        self.packages
            .get(&key)
            .map(|p| p.version == *version && p.digest == *digest)
            .unwrap_or(false)
    }

    /// Find packages in the current state that are not in the desired set.
    pub fn orphaned_packages(&self, desired: &[PackageId]) -> Vec<&InstalledPackage> {
        let desired_keys: std::collections::HashSet<String> =
            desired.iter().map(|p| p.canonical()).collect();
        self.packages
            .iter()
            .filter(|(key, _)| !desired_keys.contains(key.as_str()))
            .map(|(_, pkg)| pkg)
            .collect()
    }
}

impl Default for InstallState {
    fn default() -> Self {
        Self::new()
    }
}

/// Error type for install state operations.
#[derive(Debug, thiserror::Error)]
pub enum InstallStateError {
    #[error("state file parse error: {0}")]
    Parse(String),
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusk_core::Sha256Digest;

    #[test]
    fn record_and_check() {
        let mut state = InstallState::new();
        let pkg = PackageId::js("express");
        let version = Version::Semver(semver::Version::new(4, 18, 2));
        let digest = Sha256Digest::compute(b"express-4.18.2");

        state.record_install(
            pkg.clone(),
            version.clone(),
            digest,
            PathBuf::from("/tmp/node_modules/express"),
        );

        assert!(state.is_up_to_date(&pkg, &version, &digest));
    }

    #[test]
    fn not_up_to_date_with_different_digest() {
        let mut state = InstallState::new();
        let pkg = PackageId::js("express");
        let version = Version::Semver(semver::Version::new(4, 18, 2));
        let digest = Sha256Digest::compute(b"express-4.18.2");

        state.record_install(
            pkg.clone(),
            version.clone(),
            digest,
            PathBuf::from("/tmp/node_modules/express"),
        );

        let other_digest = Sha256Digest::compute(b"different");
        assert!(!state.is_up_to_date(&pkg, &version, &other_digest));
    }

    #[test]
    fn orphaned_packages() {
        let mut state = InstallState::new();
        let express = PackageId::js("express");
        let lodash = PackageId::js("lodash");

        state.record_install(
            express.clone(),
            Version::Semver(semver::Version::new(4, 0, 0)),
            Sha256Digest::zero(),
            PathBuf::from("/tmp/express"),
        );
        state.record_install(
            lodash.clone(),
            Version::Semver(semver::Version::new(4, 0, 0)),
            Sha256Digest::zero(),
            PathBuf::from("/tmp/lodash"),
        );

        let orphans = state.orphaned_packages(&[express]);
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].package, lodash);
    }
}
