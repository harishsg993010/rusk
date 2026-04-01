//! Python candidate provider implementing the resolver's CandidateProvider trait.
//!
//! Translates PyPI registry metadata into `VersionCandidate` objects. Handles
//! Python-specific concerns like wheel compatibility, requires-python, and
//! PEP 508 dependency markers.

use async_trait::async_trait;
use rusk_core::{Ecosystem, PackageId, Version, VersionReq};
use rusk_registry::{ArtifactType, DependencySpec, RegistryClient, VersionMetadata};
use rusk_registry_pypi::PypiRegistryClient;
use rusk_resolver::candidate::{
    CandidateError, CandidateMetadata, CandidateProvider, VersionCandidate,
};
use std::sync::Arc;
use tracing::{debug, instrument};

/// Candidate provider for the Python ecosystem.
///
/// Wraps a `PypiRegistryClient` and converts PyPI metadata into the
/// resolver's `VersionCandidate` format.
pub struct PythonCandidateProvider {
    client: Arc<PypiRegistryClient>,
    /// Target Python version for compatibility filtering.
    python_version: Option<String>,
}

impl PythonCandidateProvider {
    /// Create a new Python candidate provider.
    pub fn new(client: Arc<PypiRegistryClient>) -> Self {
        Self {
            client,
            python_version: None,
        }
    }

    /// Create a provider using the default PyPI registry.
    pub fn default_registry() -> Self {
        Self::new(Arc::new(PypiRegistryClient::default_registry()))
    }

    /// Set the target Python version for requires-python filtering.
    pub fn with_python_version(mut self, version: String) -> Self {
        self.python_version = Some(version);
        self
    }

    /// Convert `VersionMetadata` into a `VersionCandidate`.
    fn convert_to_candidate(meta: &VersionMetadata) -> VersionCandidate {
        let has_wheel = meta
            .artifacts
            .iter()
            .any(|a| a.artifact_type == ArtifactType::PythonWheel);

        let preferred = meta.preferred_artifact();
        let artifact_url = preferred.map(|a| a.url.to_string()).unwrap_or_default();
        let digest = preferred.and_then(|a| a.sha256);
        let requires_python = preferred.and_then(|a| a.requires_python.clone());

        VersionCandidate {
            package: meta.package.clone(),
            version: meta.version.clone(),
            digest,
            dependencies: meta.dependencies.clone(),
            metadata: CandidateMetadata::PyPi {
                artifact_url,
                has_wheel,
                requires_python,
            },
            yanked: meta.yanked,
            prerelease: meta.version.is_prerelease(),
        }
    }

    /// Check if a candidate is compatible with the target Python version.
    fn is_python_compatible(&self, candidate: &VersionCandidate) -> bool {
        let target = match &self.python_version {
            Some(v) => v,
            None => return true, // No target specified, accept all
        };

        match &candidate.metadata {
            CandidateMetadata::PyPi {
                requires_python: Some(req),
                ..
            } => {
                // Parse the requires-python specifier and check compatibility
                let target_ver = match target.parse::<pep440_rs::Version>() {
                    Ok(v) => v,
                    Err(_) => return true, // Can't parse target, accept
                };
                match req.parse::<pep440_rs::VersionSpecifiers>() {
                    Ok(specifiers) => specifiers.contains(&target_ver),
                    Err(_) => true, // Can't parse specifier, accept
                }
            }
            _ => true,
        }
    }
}

#[async_trait]
impl CandidateProvider for PythonCandidateProvider {
    #[instrument(skip(self), fields(package = %package, requirement = %requirement))]
    async fn fetch_candidates(
        &self,
        package: &PackageId,
        requirement: &VersionReq,
    ) -> Result<Vec<VersionCandidate>, CandidateError> {
        let matching = self
            .client
            .fetch_matching_versions(package, requirement)
            .await
            .map_err(|e| CandidateError::Registry(e.to_string()))?;

        if matching.is_empty() {
            return Err(CandidateError::NoMatchingVersion {
                package: package.display_name(),
                requirement: requirement.to_string(),
            });
        }

        let mut candidates: Vec<VersionCandidate> = matching
            .iter()
            .map(Self::convert_to_candidate)
            .filter(|c| self.is_python_compatible(c))
            .collect();

        // Sort by version descending (newest first), prefer wheels
        candidates.sort_by(|a, b| {
            let a_wheel = matches!(&a.metadata, CandidateMetadata::PyPi { has_wheel: true, .. });
            let b_wheel = matches!(&b.metadata, CandidateMetadata::PyPi { has_wheel: true, .. });
            b_wheel.cmp(&a_wheel).then_with(|| b.version.cmp(&a.version))
        });

        debug!(
            package = %package,
            count = candidates.len(),
            "fetched Python candidates"
        );

        Ok(candidates)
    }

    #[instrument(skip(self), fields(package = %candidate.package, version = %candidate.version))]
    async fn fetch_dependencies(
        &self,
        candidate: &VersionCandidate,
    ) -> Result<Vec<DependencySpec>, CandidateError> {
        if !candidate.dependencies.is_empty() {
            return Ok(candidate.dependencies.clone());
        }

        let meta = self
            .client
            .fetch_version_metadata(&candidate.package, &candidate.version)
            .await
            .map_err(|e| CandidateError::Registry(e.to_string()))?;

        Ok(meta.dependencies)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Python
    }

    fn preferred_candidate<'a>(
        &self,
        candidates: &'a [VersionCandidate],
    ) -> Option<&'a VersionCandidate> {
        // Prefer latest stable with a wheel
        candidates
            .iter()
            .find(|c| {
                !c.yanked
                    && !c.prerelease
                    && matches!(
                        &c.metadata,
                        CandidateMetadata::PyPi { has_wheel: true, .. }
                    )
            })
            .or_else(|| candidates.iter().find(|c| !c.yanked && !c.prerelease))
            .or_else(|| candidates.first())
    }
}
