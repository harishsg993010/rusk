//! JS candidate provider implementing the resolver's CandidateProvider trait.
//!
//! Translates npm registry metadata into `VersionCandidate` objects that the
//! resolver can work with. Handles npm-specific concerns like dist-tags,
//! peer dependencies, and install scripts.

use async_trait::async_trait;
use rusk_core::{Ecosystem, PackageId, Version, VersionReq};
use rusk_registry::{DependencySpec, RegistryClient, VersionMetadata};
use rusk_registry_npm::NpmRegistryClient;
use rusk_resolver::candidate::{
    CandidateError, CandidateMetadata, CandidateProvider, VersionCandidate,
};
use std::sync::Arc;
use tracing::{debug, instrument};

/// Candidate provider for the JavaScript/TypeScript ecosystem.
///
/// Wraps an `NpmRegistryClient` and converts npm metadata into the
/// resolver's `VersionCandidate` format.
pub struct JsCandidateProvider {
    client: Arc<NpmRegistryClient>,
}

impl JsCandidateProvider {
    /// Create a new JS candidate provider wrapping the given npm client.
    pub fn new(client: Arc<NpmRegistryClient>) -> Self {
        Self { client }
    }

    /// Create a provider using the default npm registry.
    pub fn default_registry() -> Self {
        Self::new(Arc::new(NpmRegistryClient::default_registry()))
    }

    /// Convert a `VersionMetadata` into a `VersionCandidate`.
    fn convert_to_candidate(meta: &VersionMetadata) -> VersionCandidate {
        let tarball_url = meta
            .preferred_artifact()
            .map(|a| a.url.to_string())
            .unwrap_or_default();

        let digest = meta
            .preferred_artifact()
            .and_then(|a| a.sha256);

        VersionCandidate {
            package: meta.package.clone(),
            version: meta.version.clone(),
            digest,
            dependencies: meta.dependencies.clone(),
            metadata: CandidateMetadata::Npm {
                tarball_url,
                dist_tag: None,
                has_install_scripts: false,
            },
            yanked: meta.yanked,
            prerelease: meta.version.is_prerelease(),
        }
    }
}

#[async_trait]
impl CandidateProvider for JsCandidateProvider {
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
            .collect();

        // Sort by version descending (newest first)
        candidates.sort_by(|a, b| b.version.cmp(&a.version));

        debug!(
            package = %package,
            count = candidates.len(),
            "fetched JS candidates"
        );

        Ok(candidates)
    }

    #[instrument(skip(self), fields(package = %candidate.package, version = %candidate.version))]
    async fn fetch_dependencies(
        &self,
        candidate: &VersionCandidate,
    ) -> Result<Vec<DependencySpec>, CandidateError> {
        // If we already have dependencies from the initial fetch, use those.
        if !candidate.dependencies.is_empty() {
            return Ok(candidate.dependencies.clone());
        }

        // Otherwise fetch full metadata for this version.
        let meta = self
            .client
            .fetch_version_metadata(&candidate.package, &candidate.version)
            .await
            .map_err(|e| CandidateError::Registry(e.to_string()))?;

        Ok(meta.dependencies)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Js
    }

    fn preferred_candidate<'a>(
        &self,
        candidates: &'a [VersionCandidate],
    ) -> Option<&'a VersionCandidate> {
        // Prefer the latest stable version (non-yanked, non-prerelease)
        candidates
            .iter()
            .find(|c| !c.yanked && !c.prerelease)
            .or_else(|| candidates.first())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusk_resolver::candidate::CandidateMetadata;

    #[test]
    fn preferred_skips_yanked_and_prerelease() {
        let provider = JsCandidateProvider::default_registry();

        let candidates = vec![
            VersionCandidate {
                package: PackageId::js("foo"),
                version: Version::Semver(semver::Version::new(3, 0, 0)),
                digest: None,
                dependencies: vec![],
                metadata: CandidateMetadata::None,
                yanked: true,
                prerelease: false,
            },
            VersionCandidate {
                package: PackageId::js("foo"),
                version: Version::Semver(semver::Version::parse("2.0.0-beta.1").unwrap()),
                digest: None,
                dependencies: vec![],
                metadata: CandidateMetadata::None,
                yanked: false,
                prerelease: true,
            },
            VersionCandidate {
                package: PackageId::js("foo"),
                version: Version::Semver(semver::Version::new(1, 0, 0)),
                digest: None,
                dependencies: vec![],
                metadata: CandidateMetadata::None,
                yanked: false,
                prerelease: false,
            },
        ];

        let preferred = provider.preferred_candidate(&candidates).unwrap();
        assert_eq!(preferred.version.to_string(), "1.0.0");
    }
}
