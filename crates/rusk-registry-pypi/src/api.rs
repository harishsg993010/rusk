//! PyPI registry API client implementation.
//!
//! Implements the `RegistryClient` trait for the PyPI JSON API.

use crate::metadata::{PypiFile, PypiPackageIndex};
use async_trait::async_trait;
use rusk_core::{Ecosystem, PackageId, RegistryUrl, Sha256Digest, Version};
use rusk_registry::{
    ArtifactInfo, ArtifactType, DependencyKind, DependencySpec, PackageMetadata, RegistryClient,
    RegistryError, VersionMetadata,
};
use rusk_tuf::SignedMetadata;
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use tracing::{debug, instrument, warn};

/// PyPI registry client implementing the `RegistryClient` trait.
pub struct PypiRegistryClient {
    registry_url: RegistryUrl,
    http: reqwest::Client,
}

impl PypiRegistryClient {
    /// Create a new client for the given registry URL.
    pub fn new(registry_url: RegistryUrl) -> Self {
        Self {
            registry_url,
            http: reqwest::Client::builder()
                .user_agent("rusk/0.1.0")
                .build()
                .expect("failed to build HTTP client"),
        }
    }

    /// Create a new client with a custom reqwest client.
    pub fn with_http_client(registry_url: RegistryUrl, http: reqwest::Client) -> Self {
        Self { registry_url, http }
    }

    /// Create a client for the default PyPI registry.
    pub fn default_registry() -> Self {
        Self::new(RegistryUrl::pypi_default())
    }

    /// Fetch the raw PyPI package index JSON.
    #[instrument(skip(self), fields(registry = %self.registry_url))]
    pub async fn fetch_package_json(
        &self,
        package: &PackageId,
    ) -> Result<PypiPackageIndex, RegistryError> {
        let url = format!(
            "{}/pypi/{}/json",
            self.registry_url.as_url(),
            package.name
        );
        debug!(url = %url, "fetching PyPI package JSON");

        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| RegistryError::Network(e.to_string()))?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(RegistryError::PackageNotFound(package.name.clone()));
        }
        if !status.is_success() {
            return Err(RegistryError::InvalidResponse(format!(
                "HTTP {} from {}",
                status, url
            )));
        }

        response
            .json::<PypiPackageIndex>()
            .await
            .map_err(|e| RegistryError::InvalidResponse(e.to_string()))
    }

    /// Convert a list of PyPI files into unified ArtifactInfo entries.
    fn convert_artifacts(files: &[PypiFile]) -> Vec<ArtifactInfo> {
        let mut artifacts = Vec::new();
        for file in files {
            let url = match url::Url::parse(&file.url) {
                Ok(u) => u,
                Err(e) => {
                    warn!(filename = %file.filename, error = %e, "skipping file with invalid URL");
                    continue;
                }
            };

            let sha256 = file
                .digests
                .sha256
                .as_ref()
                .and_then(|hex| Sha256Digest::from_hex(hex).ok());

            let artifact_type = if file.is_wheel() {
                ArtifactType::PythonWheel
            } else if file.is_sdist() {
                ArtifactType::PythonSdist
            } else {
                ArtifactType::Other
            };

            artifacts.push(ArtifactInfo {
                filename: file.filename.clone(),
                url,
                sha256,
                artifact_type,
                size: file.size,
                requires_python: file.requires_python.clone(),
            });
        }
        artifacts
    }

    /// Parse PEP 508 requires_dist lines into DependencySpec entries.
    fn parse_requires_dist(requires_dist: &[String]) -> Vec<DependencySpec> {
        let mut deps = Vec::new();
        for spec in requires_dist {
            // PEP 508 format: "name (>=1.0) ; extra == 'dev'"
            // Simple parsing: split on ';' for marker, then parse name and version.
            let (spec_part, marker) = match spec.split_once(';') {
                Some((s, m)) => (s.trim(), Some(m.trim())),
                None => (spec.as_str(), None),
            };

            // Determine dependency kind from marker.
            let kind = match marker {
                Some(m) if m.contains("extra") && m.contains("dev") => DependencyKind::Dev,
                Some(m) if m.contains("extra") && m.contains("test") => DependencyKind::Dev,
                Some(m) if m.contains("extra") => DependencyKind::Optional,
                _ => DependencyKind::Normal,
            };

            // Parse name and requirement from spec_part.
            let (name, requirement) = if let Some(paren_start) = spec_part.find('(') {
                let name = spec_part[..paren_start].trim();
                let req = spec_part[paren_start..]
                    .trim_start_matches('(')
                    .trim_end_matches(')')
                    .trim();
                (name.to_string(), req.to_string())
            } else if let Some(space_pos) = spec_part.find(|c: char| c == '>' || c == '<' || c == '=' || c == '!' || c == '~') {
                let name = spec_part[..space_pos].trim();
                let req = spec_part[space_pos..].trim();
                (name.to_string(), req.to_string())
            } else {
                (spec_part.trim().to_string(), String::new())
            };

            if !name.is_empty() {
                deps.push(DependencySpec {
                    name,
                    requirement,
                    kind,
                    ecosystem: Ecosystem::Python,
                });
            }
        }
        deps
    }
}

#[async_trait]
impl RegistryClient for PypiRegistryClient {
    #[instrument(skip(self), fields(package = %package.name))]
    async fn fetch_package_metadata(
        &self,
        package: &PackageId,
    ) -> Result<PackageMetadata, RegistryError> {
        let index = self.fetch_package_json(package).await?;

        let mut versions = Vec::new();
        let mut version_metadata = HashMap::new();

        for (ver_str, files) in &index.releases {
            let pep_version = match ver_str.parse::<pep440_rs::Version>() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let version = Version::Pep440(pep_version);
            let artifacts = Self::convert_artifacts(files);

            let yanked = files.iter().any(|f| f.yanked);
            let yank_reason = files
                .iter()
                .find(|f| f.yanked)
                .and_then(|f| f.yanked_reason.clone());

            let dependencies = index
                .info
                .requires_dist
                .as_deref()
                .map(Self::parse_requires_dist)
                .unwrap_or_default();

            let published_at = files
                .first()
                .and_then(|f| f.upload_time_iso_8601.as_ref())
                .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
                .map(|dt| dt.with_timezone(&chrono::Utc));

            let meta = VersionMetadata {
                package: package.clone(),
                version: version.clone(),
                artifacts,
                dependencies,
                yanked,
                yank_reason,
                published_at,
            };

            versions.push(version);
            version_metadata.insert(ver_str.clone(), meta);
        }
        versions.sort();

        Ok(PackageMetadata {
            package: package.clone(),
            description: index.info.summary.clone(),
            versions,
            version_metadata,
            dist_tags: HashMap::new(),
        })
    }

    #[instrument(skip(self), fields(package = %package.name, version = %version))]
    async fn fetch_version_metadata(
        &self,
        package: &PackageId,
        version: &Version,
    ) -> Result<VersionMetadata, RegistryError> {
        let url = format!(
            "{}/pypi/{}/{}/json",
            self.registry_url.as_url(),
            package.name,
            version
        );
        debug!(url = %url, "fetching PyPI version metadata");

        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| RegistryError::Network(e.to_string()))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(RegistryError::VersionNotFound {
                package: package.name.clone(),
                version: version.to_string(),
            });
        }

        let index: PypiPackageIndex = response
            .json()
            .await
            .map_err(|e| RegistryError::InvalidResponse(e.to_string()))?;

        let files = index
            .releases
            .get(&version.to_string())
            .cloned()
            .unwrap_or_default();

        let artifacts = Self::convert_artifacts(&files);
        let dependencies = index
            .info
            .requires_dist
            .as_deref()
            .map(Self::parse_requires_dist)
            .unwrap_or_default();

        let yanked = files.iter().any(|f| f.yanked);
        let yank_reason = files
            .iter()
            .find(|f| f.yanked)
            .and_then(|f| f.yanked_reason.clone());

        Ok(VersionMetadata {
            package: package.clone(),
            version: version.clone(),
            artifacts,
            dependencies,
            yanked,
            yank_reason,
            published_at: None,
        })
    }

    fn artifact_url(
        &self,
        package: &PackageId,
        version: &Version,
    ) -> Result<url::Url, RegistryError> {
        // PyPI doesn't have a predictable URL scheme; return the JSON API URL instead.
        let url_str = format!(
            "{}/pypi/{}/{}/json",
            self.registry_url.as_url(),
            package.name,
            version
        );
        url::Url::parse(&url_str)
            .map_err(|e| RegistryError::InvalidResponse(e.to_string()))
    }

    async fn fetch_tuf_metadata(
        &self,
        _role: &str,
    ) -> Result<Option<SignedMetadata<JsonValue>>, RegistryError> {
        // PyPI does not currently support TUF.
        Ok(None)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Python
    }

    fn registry_url(&self) -> &RegistryUrl {
        &self.registry_url
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_requires_dist_basic() {
        let specs = vec![
            "charset-normalizer (<4,>=2)".to_string(),
            "idna (<4,>=2.5)".to_string(),
        ];
        let deps = PypiRegistryClient::parse_requires_dist(&specs);
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "charset-normalizer");
        assert_eq!(deps[0].requirement, "<4,>=2");
        assert_eq!(deps[0].kind, DependencyKind::Normal);
    }

    #[test]
    fn parse_requires_dist_with_extras() {
        let specs = vec![
            "PySocks (!=1.5.7,>=1.5.6) ; extra == 'socks'".to_string(),
            "pytest ; extra == 'dev'".to_string(),
        ];
        let deps = PypiRegistryClient::parse_requires_dist(&specs);
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].kind, DependencyKind::Optional);
        assert_eq!(deps[1].kind, DependencyKind::Dev);
    }

    #[test]
    fn parse_requires_dist_no_version() {
        let specs = vec!["simple-package".to_string()];
        let deps = PypiRegistryClient::parse_requires_dist(&specs);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "simple-package");
        assert!(deps[0].requirement.is_empty());
    }
}
