//! Registry client trait definition.
//!
//! Defines the core abstraction that all registry implementations must satisfy.

use crate::metadata::{PackageMetadata, VersionMetadata};
use async_trait::async_trait;
use rusk_core::{Ecosystem, PackageId, RegistryUrl, Version, VersionReq};
use rusk_tuf::SignedMetadata;
use serde_json::Value as JsonValue;

/// Error type for registry operations.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("package not found: {0}")]
    PackageNotFound(String),

    #[error("version not found: {package}@{version}")]
    VersionNotFound { package: String, version: String },

    #[error("network error: {0}")]
    Network(String),

    #[error("registry returned invalid response: {0}")]
    InvalidResponse(String),

    #[error("authentication required for registry: {0}")]
    AuthRequired(String),

    #[error("TUF metadata error: {0}")]
    TufError(String),

    #[error("rate limited by registry, retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },
}

/// Trait for registry clients that can fetch package metadata.
///
/// Implementations exist for npm (`rusk-registry-npm`) and PyPI (`rusk-registry-pypi`).
/// Each implementation handles the registry-specific wire protocol and translates
/// responses into the unified metadata types.
#[async_trait]
pub trait RegistryClient: Send + Sync {
    /// Fetch top-level package metadata including all known versions.
    async fn fetch_package_metadata(
        &self,
        package: &PackageId,
    ) -> Result<PackageMetadata, RegistryError>;

    /// Fetch metadata for a specific version of a package.
    async fn fetch_version_metadata(
        &self,
        package: &PackageId,
        version: &Version,
    ) -> Result<VersionMetadata, RegistryError>;

    /// Construct the download URL for a specific artifact.
    ///
    /// This does not perform any network requests; it computes the URL
    /// from the registry base and the package/version coordinates.
    fn artifact_url(
        &self,
        package: &PackageId,
        version: &Version,
    ) -> Result<url::Url, RegistryError>;

    /// Fetch TUF metadata for this registry, if the registry supports TUF.
    ///
    /// Returns `Ok(None)` if TUF is not supported by this registry.
    async fn fetch_tuf_metadata(
        &self,
        role: &str,
    ) -> Result<Option<SignedMetadata<JsonValue>>, RegistryError>;

    /// Fetch all versions matching a version requirement.
    ///
    /// Default implementation fetches all versions and filters locally.
    async fn fetch_matching_versions(
        &self,
        package: &PackageId,
        requirement: &VersionReq,
    ) -> Result<Vec<VersionMetadata>, RegistryError> {
        let pkg_meta = self.fetch_package_metadata(package).await?;
        let matching: Vec<Version> = pkg_meta
            .versions
            .iter()
            .filter(|v| requirement.matches(v))
            .cloned()
            .collect();

        let mut results = Vec::new();
        for version in matching {
            let meta = self.fetch_version_metadata(package, &version).await?;
            results.push(meta);
        }
        Ok(results)
    }

    /// The ecosystem this client serves.
    fn ecosystem(&self) -> Ecosystem;

    /// The registry URL this client is configured for.
    fn registry_url(&self) -> &RegistryUrl;
}
