//! Air-gapped bundle support.
//!
//! Produces and consumes self-contained bundles that include all package
//! artifacts, metadata, and verification material needed to install in
//! an environment without network access.

use rusk_cas::CasStore;
use rusk_core::{PackageId, Sha256Digest, Version};
use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};
use tracing::{info, instrument};

/// Error type for airgap bundle operations.
#[derive(Debug, thiserror::Error)]
pub enum AirGapError {
    #[error("bundle creation failed: {0}")]
    CreationFailed(String),
    #[error("bundle extraction failed: {0}")]
    ExtractionFailed(String),
    #[error("artifact missing from CAS: {0}")]
    MissingArtifact(Sha256Digest),
    #[error("bundle integrity check failed: expected {expected}, got {actual}")]
    IntegrityFailed { expected: String, actual: String },
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
}

/// Manifest for an air-gapped bundle.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BundleManifest {
    /// Bundle format version.
    pub version: u32,
    /// When the bundle was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Packages included in the bundle.
    pub packages: Vec<BundlePackage>,
    /// Overall bundle digest for integrity verification.
    pub bundle_digest: Option<Sha256Digest>,
}

/// A package entry in the bundle manifest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BundlePackage {
    /// Package identity.
    pub package: PackageId,
    /// Exact version.
    pub version: Version,
    /// Content digest.
    pub digest: Sha256Digest,
    /// Size in bytes.
    pub size: u64,
    /// Relative path within the bundle.
    pub path: String,
}

/// An air-gapped bundle that can be transported to offline environments.
pub struct AirGapBundle {
    /// Bundle manifest.
    pub manifest: BundleManifest,
    /// Root directory of the bundle on disk.
    pub root: PathBuf,
}

impl AirGapBundle {
    /// Create a new bundle from a set of packages in the CAS.
    #[instrument(skip(cas, packages))]
    pub fn create(
        cas: &CasStore,
        packages: &[(PackageId, Version, Sha256Digest)],
        output_dir: &Path,
    ) -> Result<Self, AirGapError> {
        std::fs::create_dir_all(output_dir)?;

        let blobs_dir = output_dir.join("blobs");
        std::fs::create_dir_all(&blobs_dir)?;

        let mut bundle_packages = Vec::new();

        for (package, version, digest) in packages {
            let data = cas
                .read(digest)
                .map_err(AirGapError::Io)?
                .ok_or_else(|| AirGapError::MissingArtifact(*digest))?;

            let blob_path = format!("blobs/{}", digest.to_hex());
            let full_path = output_dir.join(&blob_path);
            std::fs::write(&full_path, &data)?;

            bundle_packages.push(BundlePackage {
                package: package.clone(),
                version: version.clone(),
                digest: *digest,
                size: data.len() as u64,
                path: blob_path,
            });
        }

        let manifest = BundleManifest {
            version: 1,
            created_at: chrono::Utc::now(),
            packages: bundle_packages,
            bundle_digest: None,
        };

        // Write manifest
        let manifest_json = serde_json::to_string_pretty(&manifest)
            .map_err(|e| AirGapError::CreationFailed(e.to_string()))?;
        std::fs::write(output_dir.join("manifest.json"), &manifest_json)?;

        info!(
            packages = manifest.packages.len(),
            output = %output_dir.display(),
            "air-gap bundle created"
        );

        Ok(Self {
            manifest,
            root: output_dir.to_path_buf(),
        })
    }

    /// Load an existing bundle from disk.
    pub fn open(bundle_dir: &Path) -> Result<Self, AirGapError> {
        let manifest_path = bundle_dir.join("manifest.json");
        let manifest_json = std::fs::read_to_string(&manifest_path)?;
        let manifest: BundleManifest = serde_json::from_str(&manifest_json)
            .map_err(|e| AirGapError::ExtractionFailed(e.to_string()))?;

        Ok(Self {
            manifest,
            root: bundle_dir.to_path_buf(),
        })
    }

    /// Import the bundle contents into a CAS store.
    #[instrument(skip(self, cas))]
    pub fn import_into_cas(&self, cas: &CasStore) -> Result<usize, AirGapError> {
        let mut imported = 0;

        for pkg in &self.manifest.packages {
            let blob_path = self.root.join(&pkg.path);
            let data = std::fs::read(&blob_path)?;

            // Verify integrity
            let computed = Sha256Digest::compute(&data);
            if computed != pkg.digest {
                return Err(AirGapError::IntegrityFailed {
                    expected: pkg.digest.to_hex(),
                    actual: computed.to_hex(),
                });
            }

            // Write to CAS (deduplicates automatically)
            cas.write(&data).map_err(AirGapError::Io)?;
            imported += 1;
        }

        info!(imported, "imported bundle artifacts into CAS");
        Ok(imported)
    }

    /// Total size of the bundle in bytes.
    pub fn total_size(&self) -> u64 {
        self.manifest.packages.iter().map(|p| p.size).sum()
    }

    /// Number of packages in the bundle.
    pub fn package_count(&self) -> usize {
        self.manifest.packages.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_manifest_roundtrip() {
        let manifest = BundleManifest {
            version: 1,
            created_at: chrono::Utc::now(),
            packages: vec![BundlePackage {
                package: PackageId::js("express"),
                version: Version::Semver(semver::Version::new(4, 18, 2)),
                digest: Sha256Digest::compute(b"express"),
                size: 1024,
                path: "blobs/abc123".to_string(),
            }],
            bundle_digest: None,
        };

        let json = serde_json::to_string(&manifest).unwrap();
        let parsed: BundleManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.packages.len(), 1);
        assert_eq!(parsed.version, 1);
    }
}
