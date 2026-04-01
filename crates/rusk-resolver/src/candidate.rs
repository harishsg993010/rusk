//! Candidate provider trait for ecosystem-specific resolution.
//!
//! Each ecosystem (JS, Python) implements `CandidateProvider` to supply
//! version candidates from its registry. The resolver calls these to
//! explore the version space during resolution.

use async_trait::async_trait;
use rusk_core::{Ecosystem, PackageId, Sha256Digest, Version, VersionReq};
use rusk_registry::DependencySpec;
use serde::{Deserialize, Serialize};

/// Error type for candidate provider operations.
#[derive(Debug, thiserror::Error)]
pub enum CandidateError {
    #[error("package not found: {0}")]
    PackageNotFound(String),
    #[error("no matching version for {package}: {requirement}")]
    NoMatchingVersion { package: String, requirement: String },
    #[error("registry error: {0}")]
    Registry(String),
    #[error("candidate rejected by policy: {0}")]
    PolicyRejected(String),
}

/// A version candidate during resolution.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VersionCandidate {
    /// The package this candidate belongs to.
    pub package: PackageId,
    /// The candidate version.
    pub version: Version,
    /// Expected content digest, if known from registry metadata.
    pub digest: Option<Sha256Digest>,
    /// Dependencies declared by this candidate.
    pub dependencies: Vec<DependencySpec>,
    /// Ecosystem-specific metadata.
    pub metadata: CandidateMetadata,
    /// Whether this version has been yanked.
    pub yanked: bool,
    /// Whether this version is a prerelease.
    pub prerelease: bool,
}

/// Ecosystem-specific metadata attached to a candidate.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CandidateMetadata {
    /// npm-specific metadata.
    Npm {
        /// Download URL for the tarball.
        tarball_url: String,
        /// npm dist-tag, if this candidate is tagged (e.g., "latest").
        dist_tag: Option<String>,
        /// Whether this package has an install script.
        has_install_scripts: bool,
    },
    /// PyPI-specific metadata.
    PyPi {
        /// Download URL for the preferred artifact (wheel or sdist).
        artifact_url: String,
        /// Whether a wheel is available.
        has_wheel: bool,
        /// Python version requirement (requires-python).
        requires_python: Option<String>,
    },
    /// No ecosystem-specific metadata.
    None,
}

/// Trait for providing version candidates to the resolver.
///
/// Each ecosystem implements this to translate registry metadata into
/// the resolver's candidate format.
#[async_trait]
pub trait CandidateProvider: Send + Sync {
    /// Fetch all available candidates for a package matching a version requirement.
    ///
    /// Candidates should be returned in preference order (best match first).
    async fn fetch_candidates(
        &self,
        package: &PackageId,
        requirement: &VersionReq,
    ) -> Result<Vec<VersionCandidate>, CandidateError>;

    /// Fetch the dependencies for a specific candidate.
    ///
    /// This may be called after `fetch_candidates` when the resolver needs
    /// full dependency information for a candidate.
    async fn fetch_dependencies(
        &self,
        candidate: &VersionCandidate,
    ) -> Result<Vec<DependencySpec>, CandidateError>;

    /// The ecosystem this provider serves.
    fn ecosystem(&self) -> Ecosystem;

    /// Get the preferred candidate from a list (e.g., latest stable).
    fn preferred_candidate<'a>(
        &self,
        candidates: &'a [VersionCandidate],
    ) -> Option<&'a VersionCandidate> {
        // Default: prefer the first non-yanked, non-prerelease candidate
        candidates
            .iter()
            .find(|c| !c.yanked && !c.prerelease)
            .or_else(|| candidates.first())
    }
}
