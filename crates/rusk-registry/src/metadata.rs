//! Unified metadata types returned by registry clients.
//!
//! These types abstract over the differences between npm and PyPI metadata
//! formats, providing a single set of types the resolver can work with.

use rusk_core::{Ecosystem, PackageId, Sha256Digest, Version};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Top-level package metadata containing all known versions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PackageMetadata {
    /// The package identity.
    pub package: PackageId,
    /// Human-readable description.
    pub description: Option<String>,
    /// All known versions, sorted ascending.
    pub versions: Vec<Version>,
    /// Per-version metadata that was available in the index response.
    /// Not all registries provide full metadata here (PyPI Simple API doesn't).
    pub version_metadata: HashMap<String, VersionMetadata>,
    /// Tags/labels from the registry (e.g., "latest", "next" for npm dist-tags).
    pub dist_tags: HashMap<String, String>,
}

/// Metadata for a specific version of a package.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VersionMetadata {
    /// The package this version belongs to.
    pub package: PackageId,
    /// The resolved version.
    pub version: Version,
    /// Available artifacts for this version (tarballs, wheels, etc.).
    pub artifacts: Vec<ArtifactInfo>,
    /// Dependencies declared by this version.
    pub dependencies: Vec<DependencySpec>,
    /// Whether this version has been yanked/deprecated.
    pub yanked: bool,
    /// Yank reason, if available.
    pub yank_reason: Option<String>,
    /// Publication timestamp, if available.
    pub published_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Information about a downloadable artifact (tarball, wheel, etc.).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArtifactInfo {
    /// Filename of the artifact.
    pub filename: String,
    /// Download URL.
    pub url: url::Url,
    /// SHA-256 digest of the artifact, if known.
    pub sha256: Option<Sha256Digest>,
    /// Artifact type.
    pub artifact_type: ArtifactType,
    /// Size in bytes, if known.
    pub size: Option<u64>,
    /// Python-specific: requires-python constraint.
    pub requires_python: Option<String>,
}

/// Type of downloadable artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactType {
    /// npm tarball (.tgz).
    NpmTarball,
    /// Python wheel (.whl).
    PythonWheel,
    /// Python source distribution (.tar.gz).
    PythonSdist,
    /// Other/unknown format.
    Other,
}

/// A dependency specification from registry metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DependencySpec {
    /// Name of the dependency.
    pub name: String,
    /// Version requirement string (semver range or PEP 440 specifier).
    pub requirement: String,
    /// Kind of dependency relationship.
    pub kind: DependencyKind,
    /// Ecosystem of the dependency.
    pub ecosystem: Ecosystem,
}

/// Kind of dependency relationship.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    Normal,
    Dev,
    Optional,
    Peer,
    Build,
}

impl PackageMetadata {
    /// Get the latest non-prerelease version, if any.
    pub fn latest_stable(&self) -> Option<&Version> {
        self.versions.iter().rev().find(|v| !v.is_prerelease())
    }

    /// Get the version tagged as "latest" (npm) or the highest stable version.
    pub fn latest(&self) -> Option<&Version> {
        if let Some(tag) = self.dist_tags.get("latest") {
            self.versions.iter().find(|v| v.to_string() == *tag)
        } else {
            self.latest_stable()
        }
    }
}

impl VersionMetadata {
    /// Get the preferred artifact for download (wheel > sdist > tarball).
    pub fn preferred_artifact(&self) -> Option<&ArtifactInfo> {
        // Prefer wheel, then sdist, then tarball, then anything.
        self.artifacts
            .iter()
            .find(|a| a.artifact_type == ArtifactType::PythonWheel)
            .or_else(|| {
                self.artifacts
                    .iter()
                    .find(|a| a.artifact_type == ArtifactType::PythonSdist)
            })
            .or_else(|| {
                self.artifacts
                    .iter()
                    .find(|a| a.artifact_type == ArtifactType::NpmTarball)
            })
            .or_else(|| self.artifacts.first())
    }
}
